package cli

import (
	"sort"

	"github.com/spf13/cobra"

	"gethisengine/internal/chromium"
	"gethisengine/internal/firefox"
	"gethisengine/internal/model"
)

func newCookiesCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "cookies",
		Short: "Extract cookies (values hidden unless --reveal)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			cookies := make([]model.Cookie, 0)
			for _, profile := range profiles {
				var (
					got      []model.Cookie
					warnings []string
				)
				switch profile.Family {
				case model.FamilyChromium:
					dec, _ := a.chromiumDecryptor(profile)
					got, warnings = chromium.Cookies(profile, dec)
				case model.FamilyFirefox:
					got, warnings = firefox.Cookies(profile)
				}
				cookies = append(cookies, got...)
				a.warnAll(warnings)
			}
			sortCookies(cookies)
			redactCookies(cookies, a.opts.Reveal)

			if !a.opts.Reveal && len(cookies) > 0 {
				a.warnf("cookie values are hidden; pass --reveal to decrypt them")
			}
			if len(cookies) == 0 {
				a.warnf("no cookies found")
			}
			return a.output(cookiesTable(cookies, a.opts.Reveal), cookies, outputName("cookies", a.opts.Format))
		},
	}
}

func newBookmarksCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "bookmarks",
		Short: "Extract bookmarks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			bookmarks := make([]model.Bookmark, 0)
			for _, profile := range profiles {
				var (
					got      []model.Bookmark
					warnings []string
				)
				switch profile.Family {
				case model.FamilyChromium:
					got, warnings = chromium.Bookmarks(profile)
				case model.FamilyFirefox:
					got, warnings = firefox.Bookmarks(profile)
				}
				bookmarks = append(bookmarks, got...)
				a.warnAll(warnings)
			}
			sortBookmarks(bookmarks)

			if len(bookmarks) == 0 {
				a.warnf("no bookmarks found")
			}
			return a.output(bookmarksTable(bookmarks), bookmarks, outputName("bookmarks", a.opts.Format))
		},
	}
}

func newAutofillCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "autofill",
		Short: "Extract saved form values and autofill entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			entries := make([]model.AutofillEntry, 0)
			for _, profile := range profiles {
				var (
					got      []model.AutofillEntry
					warnings []string
				)
				switch profile.Family {
				case model.FamilyChromium:
					got, warnings = chromium.Autofill(profile)
				case model.FamilyFirefox:
					got, warnings = firefox.FormHistory(profile)
				}
				entries = append(entries, got...)
				a.warnAll(warnings)
			}
			sortAutofill(entries)

			if len(entries) == 0 {
				a.warnf("no autofill entries found")
			}
			return a.output(autofillTable(entries), entries, outputName("autofill", a.opts.Format))
		},
	}
}

func sortHistory(entries []model.HistoryEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].LastVisit.After(entries[j].LastVisit)
	})
}

func sortCookies(cookies []model.Cookie) {
	sort.SliceStable(cookies, func(i, j int) bool {
		a, b := cookies[i], cookies[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Name < b.Name
	})
}

func sortBookmarks(bookmarks []model.Bookmark) {
	sort.SliceStable(bookmarks, func(i, j int) bool {
		a, b := bookmarks[i], bookmarks[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Folder != b.Folder {
			return a.Folder < b.Folder
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.URL < b.URL
	})
}

func sortAutofill(entries []model.AutofillEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Value < b.Value
	})
}
