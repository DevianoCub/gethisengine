package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"gethisengine/internal/crypt"
	"gethisengine/internal/crypt/nss"
	"gethisengine/internal/export"
	"gethisengine/internal/model"
)

const (
	tuiViewProfiles = iota
	tuiViewPasswords
	tuiViewHistory
	tuiViewCookies
	tuiViewBookmarks
	tuiViewAutofill
	tuiViewCount
)

var tuiViewTitles = []string{
	"Profiles", "Passwords", "History", "Cookies", "Bookmarks", "Autofill",
}

type tuiState struct {
	opts      Options
	profiles  []model.Profile
	dataset   model.Dataset
	warnings  []string
	reveal    bool
	view      int
	offset    int
	maxOffset int
}

func newTUICommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Aliases: []string{"ui"},
		Short:   "Open the interactive terminal browser",
		Long: `Open a full-screen terminal browser for the discovered profiles and data.

The TUI uses the same read-only extractors as the other commands. Passwords and
cookie values stay masked until you press "r" to enable reveal mode.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
				return fmt.Errorf("tui requires an interactive terminal (use the regular commands for scripts)")
			}
			return runTUI(a.opts)
		},
	}
}

func runTUI(opts Options) error {
	state := &tuiState{opts: opts, reveal: opts.Reveal}
	if err := state.reload(); err != nil {
		return err
	}

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("enable raw terminal mode: %w", err)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
		fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[0m\r\n")
	}()
	fmt.Fprint(os.Stdout, "\x1b[?25l")

	reader := bufio.NewReader(os.Stdin)
	for {
		width, height := tuiSize()
		renderTUI(state, width, height)
		key, err := readTUIKey(reader)
		if err != nil {
			return nil
		}
		switch key {
		case "q", "ctrl-c":
			return nil
		case "up", "k":
			state.scroll(-1)
		case "down", "j":
			state.scroll(1)
		case "pgup":
			state.scroll(-10)
		case "pgdown":
			state.scroll(10)
		case "home", "g":
			state.offset = 0
		case "end", "G":
			state.offset = state.maxOffset
		case "1":
			state.setView(tuiViewProfiles)
		case "2":
			state.setView(tuiViewPasswords)
		case "3":
			state.setView(tuiViewHistory)
		case "4":
			state.setView(tuiViewCookies)
		case "5":
			state.setView(tuiViewBookmarks)
		case "6":
			state.setView(tuiViewAutofill)
		case "r":
			state.reveal = !state.reveal
			if err := state.reload(); err != nil {
				state.warnings = append(state.warnings, err.Error())
			}
		case "R":
			if err := state.reload(); err != nil {
				state.warnings = append(state.warnings, err.Error())
			}
		}
	}
}

func (s *tuiState) reload() error {
	opts := s.opts
	opts.Reveal = s.reveal
	opts.Format = "table"
	opts.Out = ""
	opts.Quiet = true

	sub := &app{
		opts:      opts,
		stdout:    io.Discard,
		stderr:    io.Discard,
		seenWarn:  make(map[string]bool),
		decryptor: make(map[string]*crypt.ChromiumDecryptor),
		decErr:    make(map[string]error),
		keys:      make(map[string]*nss.Key4),
		keyErr:    make(map[string]error),
	}
	profiles, err := sub.loadProfiles()
	if err != nil {
		return err
	}
	since, err := parseSince(opts.Since)
	if err != nil {
		return err
	}
	s.profiles = profiles
	s.dataset = sub.collect(profiles, since)
	s.warnings = append([]string(nil), sub.warnings...)
	s.offset = 0
	s.maxOffset = 0
	return nil
}

func (s *tuiState) setView(view int) {
	if view < 0 || view >= tuiViewCount {
		return
	}
	s.view = view
	s.offset = 0
}

func (s *tuiState) scroll(delta int) {
	s.offset += delta
	if s.offset < 0 {
		s.offset = 0
	}
	if s.offset > s.maxOffset {
		s.offset = s.maxOffset
	}
}

func (s *tuiState) table() export.Table {
	switch s.view {
	case tuiViewPasswords:
		return passwordsTable(s.dataset.Passwords, s.reveal)
	case tuiViewHistory:
		return historyTable(s.dataset.History)
	case tuiViewCookies:
		return cookiesTable(s.dataset.Cookies, s.reveal)
	case tuiViewBookmarks:
		return bookmarksTable(s.dataset.Bookmarks)
	case tuiViewAutofill:
		return autofillTable(s.dataset.Autofill)
	default:
		return profilesTable(s.profiles)
	}
}

func renderTUI(state *tuiState, width, height int) {
	if width < 40 {
		width = 40
	}
	if height < 10 {
		height = 10
	}

	reveal := "off"
	if state.reveal {
		reveal = "ON"
	}

	lines := make([]string, 0, height)
	lines = append(lines,
		truncateANSI("gethisengine  |  profiles: "+fmt.Sprint(len(state.profiles))+
			"  history: "+fmt.Sprint(len(state.dataset.History))+
			"  cookies: "+fmt.Sprint(len(state.dataset.Cookies))+
			"  bookmarks: "+fmt.Sprint(len(state.dataset.Bookmarks))+
			"  autofill: "+fmt.Sprint(len(state.dataset.Autofill))+
			"  reveal: "+reveal+"  warnings: "+fmt.Sprint(len(state.warnings)), width),
	)

	tabs := make([]string, 0, tuiViewCount)
	for i, title := range tuiViewTitles {
		label := fmt.Sprintf(" %d %s ", i+1, title)
		if i == state.view {
			label = "\x1b[7m" + label + "\x1b[0m"
		}
		tabs = append(tabs, label)
	}
	lines = append(lines, truncateANSI(strings.Join(tabs, " "), width))
	lines = append(lines,
		truncateANSI("↑/↓ or j/k scroll   PgUp/PgDn page   g/G top/bottom   r reveal   R reload   q quit", width),
		"",
	)

	var buf bytes.Buffer
	table := state.table()
	if len(table.Rows) == 0 {
		state.maxOffset = 0
		state.offset = 0
		lines = append(lines, "(no entries)")
	} else {
		_ = export.WriteTable(&buf, table)
		content := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		available := height - len(lines)
		if available < 1 {
			available = 1
		}
		maxOffset := len(content) - available
		if maxOffset < 0 {
			maxOffset = 0
		}
		state.maxOffset = maxOffset
		if state.offset > maxOffset {
			state.offset = maxOffset
		}
		end := state.offset + available
		if end > len(content) {
			end = len(content)
		}
		for _, line := range content[state.offset:end] {
			lines = append(lines, truncateANSI(line, width))
		}
	}

	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}

	var out strings.Builder
	out.WriteString("\x1b[H\x1b[2J")
	for i, line := range lines {
		if i > 0 {
			out.WriteString("\r\n")
		}
		out.WriteString(line)
	}
	fmt.Fprint(os.Stdout, out.String())
}

func truncateANSI(value string, width int) string {
	// The TUI only inserts SGR sequences around tab labels. Preserve them
	// while counting visible runes so the screen does not wrap.
	var out strings.Builder
	visible := 0
	for i := 0; i < len(value) && visible < width; {
		if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '[' {
			j := i + 2
			for j < len(value) {
				c := value[j]
				j++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			out.WriteString(value[i:j])
			i = j
			continue
		}
		if value[i] < 0x80 {
			out.WriteByte(value[i])
			visible++
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			out.WriteByte(value[i])
			visible++
			i++
			continue
		}
		out.WriteString(value[i : i+size])
		visible++
		i += size
	}
	return out.String()
}

func tuiSize() (int, int) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return 100, 30
	}
	return width, height
}

func readTUIKey(reader *bufio.Reader) (string, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	switch b {
	case 3:
		return "ctrl-c", nil
	case 13, 10:
		return "enter", nil
	case 27:
		next, err := reader.ReadByte()
		if err != nil {
			return "esc", nil
		}
		if next != '[' && next != 'O' {
			return "esc", nil
		}
		code, err := reader.ReadByte()
		if err != nil {
			return "esc", nil
		}
		switch code {
		case 'A':
			return "up", nil
		case 'B':
			return "down", nil
		case 'H':
			return "home", nil
		case 'F':
			return "end", nil
		case '5':
			if _, err := reader.ReadByte(); err == nil {
				return "pgup", nil
			}
		case '6':
			if _, err := reader.ReadByte(); err == nil {
				return "pgdown", nil
			}
		}
		return "", nil
	default:
		return string(b), nil
	}
}
