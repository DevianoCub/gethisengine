package cli

import (
	"sort"
	"strconv"
	"strings"

	"gethisengine/internal/export"
	"gethisengine/internal/model"
)

func profilesTable(profiles []model.Profile) export.Table {
	table := export.Table{
		Headers: []string{"FAMILY", "BROWSER", "PROFILE", "DEFAULT", "FILES", "PATH"},
	}
	for _, profile := range profiles {
		isDefault := ""
		if profile.IsDefault {
			isDefault = "yes"
		}
		files := make([]string, 0, len(profile.Artifacts))
		for key := range profile.Artifacts {
			files = append(files, key)
		}
		sort.Strings(files)
		table.Rows = append(table.Rows, []string{
			profile.Family,
			profile.Browser,
			profile.Name,
			isDefault,
			strings.Join(files, ","),
			profile.Path,
		})
	}
	return table
}

func passwordsTable(creds []model.Credential, reveal bool) export.Table {
	table := export.Table{
		Headers: []string{"BROWSER", "PROFILE", "URL", "USERNAME", "PASSWORD", "CREATED", "LAST USED", "TIMES", "NOTE"},
	}
	for _, cred := range creds {
		password := ""
		switch {
		case !cred.HasPassword:
			password = ""
		case !reveal:
			password = "********"
		case cred.Password == "":
			password = "(decryption failed)"
		default:
			password = cred.Password
		}
		created, lastUsed := "", ""
		if cred.Created != nil {
			created = export.Time(*cred.Created)
		}
		if cred.LastUsed != nil {
			lastUsed = export.Time(*cred.LastUsed)
		}
		table.Rows = append(table.Rows, []string{
			cred.Browser,
			cred.Profile,
			cred.URL,
			cred.Username,
			password,
			created,
			lastUsed,
			strconv.FormatInt(cred.TimesUsed, 10),
			cred.Note,
		})
	}
	return table
}

func historyTable(entries []model.HistoryEntry) export.Table {
	table := export.Table{
		Headers: []string{"BROWSER", "PROFILE", "LAST VISIT", "VISITS", "URL", "TITLE"},
	}
	for _, entry := range entries {
		table.Rows = append(table.Rows, []string{
			entry.Browser,
			entry.Profile,
			export.Time(entry.LastVisit),
			strconv.FormatInt(entry.VisitCount, 10),
			entry.URL,
			entry.Title,
		})
	}
	return table
}

func cookiesTable(cookies []model.Cookie, reveal bool) export.Table {
	table := export.Table{
		Headers: []string{"BROWSER", "PROFILE", "HOST", "NAME", "VALUE", "EXPIRES", "SECURE", "HTTPONLY"},
	}
	for _, cookie := range cookies {
		value := cookie.Value
		if !reveal && value != "" {
			value = "********"
		}
		table.Rows = append(table.Rows, []string{
			cookie.Browser,
			cookie.Profile,
			cookie.Host,
			cookie.Name,
			value,
			export.Time(cookie.Expires),
			strconv.FormatBool(cookie.Secure),
			strconv.FormatBool(cookie.HTTPOnly),
		})
	}
	return table
}

func bookmarksTable(bookmarks []model.Bookmark) export.Table {
	table := export.Table{
		Headers: []string{"BROWSER", "PROFILE", "FOLDER", "TITLE", "URL", "ADDED"},
	}
	for _, bookmark := range bookmarks {
		table.Rows = append(table.Rows, []string{
			bookmark.Browser,
			bookmark.Profile,
			bookmark.Folder,
			bookmark.Title,
			bookmark.URL,
			export.Time(bookmark.Added),
		})
	}
	return table
}

func autofillTable(entries []model.AutofillEntry) export.Table {
	table := export.Table{
		Headers: []string{"BROWSER", "PROFILE", "FIELD", "VALUE", "COUNT"},
	}
	for _, entry := range entries {
		table.Rows = append(table.Rows, []string{
			entry.Browser,
			entry.Profile,
			entry.Field,
			entry.Value,
			strconv.FormatInt(entry.Count, 10),
		})
	}
	return table
}

func prepareCredentials(creds []model.Credential, reveal bool) []model.Credential {
	if reveal {
		return creds
	}
	out := make([]model.Credential, len(creds))
	copy(out, creds)
	for i := range out {
		out[i].Password = ""
	}
	return out
}
