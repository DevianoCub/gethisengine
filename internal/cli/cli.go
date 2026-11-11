// Package cli wires profile discovery, extractors and exporters into the
// gethisengine command line interface.
package cli

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"gethisengine/internal/chromium"
	"gethisengine/internal/crypt"
	"gethisengine/internal/crypt/nss"
	"gethisengine/internal/discover"
	"gethisengine/internal/export"
	"gethisengine/internal/model"
)

// Version is overridden at build time with -ldflags.
var Version = "0.1.0-dev"

// Options collects the flags shared by every command.
type Options struct {
	Browsers        []string
	Profiles        []string
	Roots           []string
	Reveal          bool
	KeyringPassword string
	Peanuts         bool
	MasterPassword  string
	ChromiumKeyHex  string
	Format          string
	Out             string
	Quiet           bool
	Since           string
	Limit           int
}

type app struct {
	opts Options

	stdout io.Writer
	stderr io.Writer

	warnings  []string
	seenWarn  map[string]bool
	decryptor map[string]*crypt.ChromiumDecryptor
	decErr    map[string]error
	keys      map[string]*nss.Key4
	keyErr    map[string]error
}

// NewRootCommand builds the cobra command tree.
func NewRootCommand() *cobra.Command {
	return newRootCommand(os.Stdout, os.Stderr)
}

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	a := &app{
		stdout:    stdout,
		stderr:    stderr,
		seenWarn:  make(map[string]bool),
		decryptor: make(map[string]*crypt.ChromiumDecryptor),
		decErr:    make(map[string]error),
		keys:      make(map[string]*nss.Key4),
		keyErr:    make(map[string]error),
	}

	root := &cobra.Command{
		Use:           "gethisengine",
		Short:         "Find browser profiles, saved passwords and history on this device",
		Long:          rootLong,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetOut(stdout)
	root.SetErr(stderr)

	flags := root.PersistentFlags()
	flags.StringArrayVar(&a.opts.Browsers, "browser", nil, "only this browser key/family/alias; repeat or separate with commas")
	flags.StringArrayVar(&a.opts.Profiles, "profile", nil, "only profiles whose name matches this substring; repeat or separate with commas")
	flags.StringArrayVar(&a.opts.Roots, "root", nil, "extra directory to scan (Chromium User Data, Firefox profile or base directory); repeatable")
	flags.BoolVar(&a.opts.Reveal, "reveal", false, "decrypt and print saved passwords and cookie values")
	flags.StringVar(&a.opts.KeyringPassword, "keyring-password", "", "use this Linux keyring password instead of querying Secret Service")
	flags.BoolVar(&a.opts.Peanuts, "peanuts", false, "force the legacy Linux fallback password \"peanuts\"")
	flags.StringVar(&a.opts.MasterPassword, "master-password", "", "Firefox primary (master) password")
	flags.StringVar(&a.opts.ChromiumKeyHex, "chromium-key-hex", "", "advanced: use this Chromium master key (hex) instead of the OS key store")
	flags.StringVarP(&a.opts.Format, "format", "f", "table", "output format: table, json or csv")
	flags.StringVarP(&a.opts.Out, "out", "o", "", "write output to this file (or directory for dump) instead of stdout")
	flags.BoolVar(&a.opts.Quiet, "quiet", false, "suppress warnings")

	root.AddCommand(
		newScanCommand(a),
		newPasswordsCommand(a),
		newHistoryCommand(a),
		newCookiesCommand(a),
		newBookmarksCommand(a),
		newAutofillCommand(a),
		newDumpCommand(a),
		newTUICommand(a),
	)
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute() int {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

const rootLong = `gethisengine discovers browser profiles and extracts saved logins, history,
cookies, bookmarks and autofill data from Chromium-based and Firefox-based
browsers on Linux, macOS and Windows.

The tool is strictly read-only: browser databases are copied to a temporary
directory and opened in immutable mode. Nothing is written back to a profile
and no network connections are made.

Saved secrets are hidden by default. Pass --reveal to decrypt them. Use this
tool only on devices you own or are explicitly authorised to examine.`

// ------------------------------------------------------------------ helpers

func (a *app) warnf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if a.seenWarn[message] {
		return
	}
	a.seenWarn[message] = true
	a.warnings = append(a.warnings, message)
}

func (a *app) flushWarnings() {
	if a.opts.Quiet {
		return
	}
	for _, warning := range a.warnings {
		fmt.Fprintln(a.stderr, "warning:", warning)
	}
}

func (a *app) warnAll(warnings []string) {
	for _, warning := range warnings {
		a.warnf("%s", warning)
	}
}

func (a *app) loadProfiles() ([]model.Profile, error) {
	profiles, warnings := discover.Find(a.opts.Roots)
	for _, warning := range warnings {
		a.warnf("%s", warning)
	}

	filtered := make([]model.Profile, 0, len(profiles))
	for _, profile := range profiles {
		if a.matchesProfile(profile) {
			filtered = append(filtered, profile)
		}
	}
	if len(a.opts.Browsers) > 0 && len(filtered) == 0 {
		a.warnf("no profiles matched --browser %s", strings.Join(a.opts.Browsers, ","))
	}
	if len(a.opts.Profiles) > 0 && len(filtered) == 0 {
		a.warnf("no profiles matched --profile %s", strings.Join(a.opts.Profiles, ","))
	}
	return filtered, nil
}

func (a *app) matchesProfile(profile model.Profile) bool {
	if len(a.opts.Browsers) > 0 {
		matched := false
		for _, want := range splitList(a.opts.Browsers) {
			want = strings.ToLower(strings.TrimSpace(want))
			if want == "" {
				continue
			}
			if want == strings.ToLower(profile.BrowserKey) ||
				want == strings.ToLower(profile.Family) ||
				strings.Contains(strings.ToLower(profile.Browser), want) {
				matched = true
				break
			}
			for _, alias := range profile.Aliases {
				if want == strings.ToLower(alias) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(a.opts.Profiles) > 0 {
		matched := false
		for _, want := range splitList(a.opts.Profiles) {
			want = strings.ToLower(strings.TrimSpace(want))
			if want == "" {
				continue
			}
			if strings.Contains(strings.ToLower(profile.Name), want) ||
				strings.Contains(strings.ToLower(filepath.Base(profile.Path)), want) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func splitList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// chromiumDecryptor returns a cached decryptor for a Chromium profile. A nil
// decryptor with a nil error means "not requested" (--reveal was not given).
func (a *app) chromiumDecryptor(profile model.Profile) (chromium.Decryptor, error) {
	if !a.opts.Reveal {
		return nil, nil
	}
	cacheKey := profile.BrowserKey + "\x00" + profile.Browser
	if dec, ok := a.decryptor[cacheKey]; ok {
		if a.decErr[cacheKey] != nil {
			return nil, a.decErr[cacheKey]
		}
		if dec == nil {
			return nil, nil
		}
		return dec, nil
	}

	if a.opts.ChromiumKeyHex != "" {
		key, err := hex.DecodeString(strings.TrimSpace(a.opts.ChromiumKeyHex))
		if err != nil {
			a.warnf("invalid --chromium-key-hex: %v", err)
			return nil, err
		}
		mode := crypt.ModeCBC
		if runtime.GOOS == "windows" {
			mode = crypt.ModeGCM
		}
		dec := crypt.NewChromiumDecryptorWithKey(key, mode)
		a.decryptor[cacheKey] = dec
		return dec, nil
	}

	spec, _ := discover.Lookup(profile.BrowserKey)
	linuxApps := spec.LinuxKeyringCandidates()
	darwinApps := spec.DarwinKeychainCandidates()
	if len(linuxApps) == 0 {
		linuxApps = []string{profile.BrowserKey, "chrome", "chromium"}
	}
	if len(darwinApps) == 0 {
		darwinApps = []string{profile.BrowserKey, "Chrome", "Chromium"}
	}
	appName := linuxApps[0]
	if runtime.GOOS == "darwin" {
		appName = darwinApps[0]
	}
	if appName == "" {
		appName = profile.BrowserKey
	}

	localState := filepath.Join(profile.Path, "Local State")
	if _, err := os.Stat(localState); err != nil {
		localState = filepath.Join(filepath.Dir(profile.Path), "Local State")
	}

	dec, err := crypt.NewChromiumDecryptor(crypt.ChromiumOptions{
		App:             appName,
		Apps:            linuxApps,
		KeychainApps:    darwinApps,
		LocalStatePath:  localState,
		KeyringPassword: a.opts.KeyringPassword,
		ForcePeanuts:    a.opts.Peanuts,
	})
	a.decryptor[cacheKey] = dec
	a.decErr[cacheKey] = err
	if err != nil {
		a.warnf("%s: cannot obtain encryption key: %v", profile.Browser, err)
		return nil, err
	}
	if warning := dec.Warning(); warning != "" {
		a.warnf("%s: %s", profile.Browser, warning)
	}
	return dec, nil
}

// firefoxKey returns a cached key4.db decryptor.
func (a *app) firefoxKey(profile model.Profile) (*nss.Key4, error) {
	if !a.opts.Reveal {
		return nil, nil
	}
	if key, ok := a.keys[profile.Path]; ok {
		return key, a.keyErr[profile.Path]
	}
	path := profile.Artifacts["key4"]
	if path == "" {
		path = filepath.Join(profile.Path, "key4.db")
	}
	key, err := nss.NewKey4(path, a.opts.MasterPassword)
	a.keys[profile.Path] = key
	a.keyErr[profile.Path] = err
	if err != nil {
		if err == nss.ErrWrongMasterPassword {
			a.warnf("%s/%s: wrong Firefox primary password; use --master-password", profile.Browser, profile.Name)
		} else {
			a.warnf("%s/%s: cannot unlock key4.db: %v", profile.Browser, profile.Name, err)
		}
		return nil, err
	}
	return key, nil
}

func (a *app) output(table export.Table, jsonValue any, defaultName string) error {
	format := strings.ToLower(strings.TrimSpace(a.opts.Format))
	if format == "" {
		format = "table"
	}

	var buf bytes.Buffer
	switch format {
	case "table":
		if err := export.WriteTable(&buf, table); err != nil {
			return err
		}
	case "json":
		if err := export.WriteJSON(&buf, jsonValue); err != nil {
			return err
		}
	case "csv":
		if err := export.WriteCSV(&buf, table); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (want table, json or csv)", a.opts.Format)
	}

	if a.opts.Out == "" {
		_, err := a.stdout.Write(buf.Bytes())
		return err
	}

	path := a.opts.Out
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, defaultName)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(a.stderr, "wrote", path)
	return nil
}

func outputName(base, format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return base + ".json"
	case "csv":
		return base + ".csv"
	default:
		return base + ".txt"
	}
}

func mask(secret string, reveal bool) string {
	if reveal || secret == "" {
		return secret
	}
	return export.Mask(secret)
}

func parseSince(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	layouts := []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if layout == "2006-01-02" {
			if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
				return t, nil
			}
			continue
		}
		if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse date %q (try 2006-01-02)", value)
}

func redactCookies(cookies []model.Cookie, reveal bool) {
	if reveal {
		return
	}
	for i := range cookies {
		cookies[i].Value = mask(cookies[i].Value, false)
	}
}

func sortCredentials(creds []model.Credential) {
	sort.SliceStable(creds, func(i, j int) bool {
		if creds[i].Browser != creds[j].Browser {
			return creds[i].Browser < creds[j].Browser
		}
		if creds[i].Profile != creds[j].Profile {
			return creds[i].Profile < creds[j].Profile
		}
		if creds[i].URL != creds[j].URL {
			return creds[i].URL < creds[j].URL
		}
		return creds[i].Username < creds[j].Username
	})
}
