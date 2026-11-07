package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"gethisengine/internal/chromium"
	"gethisengine/internal/export"
	"gethisengine/internal/firefox"
	"gethisengine/internal/model"
)

func newDumpCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Extract everything into a report directory",
		Long: `Extract profiles, logins, history, cookies, bookmarks and autofill data
into a directory as a single JSON report (--format json), a set of CSV files
(--format csv) or both (--format both).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			since, err := parseSince(a.opts.Since)
			if err != nil {
				return err
			}

			dataset := a.collect(profiles, since)
			defer a.flushWarnings()

			dataset.Warnings = append([]string(nil), a.warnings...)
			return a.writeDump(dataset)
		},
	}
	cmd.Flags().StringVar(&a.opts.Since, "since", "", "only history entries newer than this date (2006-01-02 or RFC3339)")
	cmd.Flags().IntVarP(&a.opts.Limit, "limit", "n", 0, "maximum number of history entries (0 = unlimited)")
	return cmd
}

func (a *app) collect(profiles []model.Profile, since time.Time) model.Dataset {
	dataset := model.Dataset{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Profiles:      make([]model.Profile, 0),
		Passwords:     make([]model.Credential, 0),
		History:       make([]model.HistoryEntry, 0),
		Cookies:       make([]model.Cookie, 0),
		Bookmarks:     make([]model.Bookmark, 0),
		Autofill:      make([]model.AutofillEntry, 0),
	}
	dataset.Hostname, _ = os.Hostname()

	for _, profile := range profiles {
		dataset.Profiles = append(dataset.Profiles, profile)

		switch profile.Family {
		case model.FamilyChromium:
			dec, _ := a.chromiumDecryptor(profile)

			creds, warnings := chromium.Passwords(profile, dec)
			dataset.Passwords = append(dataset.Passwords, creds...)
			a.warnAll(warnings)

			history, warnings := chromium.History(profile, since, a.opts.Limit)
			dataset.History = append(dataset.History, history...)
			a.warnAll(warnings)

			cookies, warnings := chromium.Cookies(profile, dec)
			dataset.Cookies = append(dataset.Cookies, cookies...)
			a.warnAll(warnings)

			bookmarks, warnings := chromium.Bookmarks(profile)
			dataset.Bookmarks = append(dataset.Bookmarks, bookmarks...)
			a.warnAll(warnings)

			autofill, warnings := chromium.Autofill(profile)
			dataset.Autofill = append(dataset.Autofill, autofill...)
			a.warnAll(warnings)

		case model.FamilyFirefox:
			key, _ := a.firefoxKey(profile)

			creds, warnings := firefox.Passwords(profile, key)
			dataset.Passwords = append(dataset.Passwords, creds...)
			a.warnAll(warnings)

			history, warnings := firefox.History(profile, since, a.opts.Limit)
			dataset.History = append(dataset.History, history...)
			a.warnAll(warnings)

			cookies, warnings := firefox.Cookies(profile)
			dataset.Cookies = append(dataset.Cookies, cookies...)
			a.warnAll(warnings)

			bookmarks, warnings := firefox.Bookmarks(profile)
			dataset.Bookmarks = append(dataset.Bookmarks, bookmarks...)
			a.warnAll(warnings)

			formHistory, warnings := firefox.FormHistory(profile)
			dataset.Autofill = append(dataset.Autofill, formHistory...)
			a.warnAll(warnings)
		}
	}

	sortCredentials(dataset.Passwords)
	sortHistory(dataset.History)
	sortCookies(dataset.Cookies)
	sortBookmarks(dataset.Bookmarks)
	sortAutofill(dataset.Autofill)
	if a.opts.Limit > 0 && len(dataset.History) > a.opts.Limit {
		dataset.History = dataset.History[:a.opts.Limit]
	}

	redactCookies(dataset.Cookies, a.opts.Reveal)
	dataset.Passwords = prepareCredentials(dataset.Passwords, a.opts.Reveal)
	if !a.opts.Reveal && (len(dataset.Passwords) > 0 || len(dataset.Cookies) > 0) {
		a.warnf("saved passwords and cookie values are hidden; pass --reveal to include them")
	}
	return dataset
}

func (a *app) writeDump(dataset model.Dataset) error {
	format := strings.ToLower(strings.TrimSpace(a.opts.Format))
	if format == "" || format == "table" {
		format = "json"
	}
	switch format {
	case "json", "csv", "both":
	default:
		return fmt.Errorf("dump format must be json, csv or both")
	}

	outDir := a.opts.Out
	if outDir == "" {
		outDir = "."
	}
	if info, err := os.Stat(outDir); err == nil && !info.IsDir() {
		return fmt.Errorf("--out must be a directory for dump")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}

	if format == "json" || format == "both" {
		path := filepath.Join(outDir, "report.json")
		if err := writeFile(path, func(w io.Writer) error { return export.WriteJSON(w, dataset) }); err != nil {
			return err
		}
		fmt.Fprintln(a.stderr, "wrote", path)
	}

	if format == "csv" || format == "both" {
		tables := []struct {
			name  string
			table export.Table
		}{
			{"profiles", profilesTable(dataset.Profiles)},
			{"passwords", passwordsTable(dataset.Passwords, a.opts.Reveal)},
			{"history", historyTable(dataset.History)},
			{"cookies", cookiesTable(dataset.Cookies, a.opts.Reveal)},
			{"bookmarks", bookmarksTable(dataset.Bookmarks)},
			{"autofill", autofillTable(dataset.Autofill)},
		}
		for _, item := range tables {
			path := filepath.Join(outDir, item.name+".csv")
			table := item.table
			if err := writeFile(path, func(w io.Writer) error { return export.WriteCSV(w, table) }); err != nil {
				return err
			}
			fmt.Fprintln(a.stderr, "wrote", path)
		}
	}
	return nil
}

func writeFile(path string, render func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := render(file); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
