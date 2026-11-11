// Package firefox reads data from Firefox-based profiles: saved logins,
// history, cookies and form history.
package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gethisengine/internal/crypt/nss"
	"gethisengine/internal/model"
	dbsqlite "gethisengine/internal/sqlite"
)

func artifact(profile model.Profile, key, fallback string) string {
	if path := profile.Artifacts[key]; path != "" {
		return path
	}
	return filepath.Join(profile.Path, fallback)
}

type loginEntry struct {
	Hostname          string `json:"hostname"`
	FormSubmitURL     string `json:"formSubmitURL"`
	HTTPRealm         string `json:"httpRealm"`
	UsernameField     string `json:"usernameField"`
	PasswordField     string `json:"passwordField"`
	EncryptedUsername string `json:"encryptedUsername"`
	EncryptedPassword string `json:"encryptedPassword"`
	GUID              string `json:"guid"`
	TimeCreated       int64  `json:"timeCreated"`
	TimeLastUsed      int64  `json:"timeLastUsed"`
	TimesUsed         int64  `json:"timesUsed"`
}

type loginsFile struct {
	Logins []loginEntry `json:"logins"`
}

// Passwords returns saved logins. Recent Firefox builds use logins.db; older
// builds use logins.json. When both exist the SQLite store is authoritative.
// key may be nil, in which case only site metadata is returned.
func Passwords(profile model.Profile, key *nss.Key4) ([]model.Credential, []string) {
	if dbPath := artifact(profile, "logins_db", "logins.db"); fileExists(dbPath) {
		creds, warnings, ok := passwordsFromDB(profile, key, dbPath)
		if ok {
			return creds, warnings
		}
		// A malformed/old logins.db must not hide a usable logins.json.
		if jsonPath := artifact(profile, "logins", "logins.json"); !fileExists(jsonPath) {
			return creds, warnings
		}
	}

	path := artifact(profile, "logins", "logins.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("%s: read logins.json: %v", profile.Browser, err)}
	}

	var file loginsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: parse logins.json: %v", profile.Browser, profile.Name, err)}
	}

	var out []model.Credential
	var warnings []string
	for _, login := range file.Logins {
		if login.Hostname == "" {
			continue
		}
		cred := model.Credential{
			Browser:     profile.Browser,
			Profile:     profile.Name,
			URL:         login.Hostname,
			Realm:       login.HTTPRealm,
			HasPassword: login.EncryptedPassword != "",
			TimesUsed:   login.TimesUsed,
		}
		if login.FormSubmitURL != "" && login.FormSubmitURL != login.Hostname {
			cred.Note = "form action: " + login.FormSubmitURL
		}
		if login.TimeCreated > 0 {
			t := time.UnixMilli(login.TimeCreated).UTC()
			cred.Created = &t
		}
		if login.TimeLastUsed > 0 {
			t := time.UnixMilli(login.TimeLastUsed).UTC()
			cred.LastUsed = &t
		}

		if key != nil {
			if login.EncryptedUsername != "" {
				if user, err := key.Decrypt(login.EncryptedUsername); err != nil {
					warnings = append(warnings, fmt.Sprintf("%s/%s: decrypt username for %s: %v",
						profile.Browser, profile.Name, login.Hostname, err))
				} else {
					cred.Username = user
				}
			}
			if login.EncryptedPassword != "" {
				if pass, err := key.Decrypt(login.EncryptedPassword); err != nil {
					warnings = append(warnings, fmt.Sprintf("%s/%s: decrypt password for %s: %v",
						profile.Browser, profile.Name, login.Hostname, err))
					cred.Note = "decryption failed: " + err.Error()
				} else {
					cred.Password = pass
				}
			}
		}
		out = append(out, cred)
	}
	return out, warnings
}

type loginRow struct {
	origin           string
	httpRealm        string
	formActionOrigin string
	timesUsed        int64
	timeCreated      int64
	timeLastUsed     int64
	secFields        string
	guid             string
}

func passwordsFromDB(profile model.Profile, key *nss.Key4, path string) ([]model.Credential, []string, bool) {
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open logins.db: %v", profile.Browser, err)}, false
	}
	defer cleanup()

	var warnings []string
	rows := make([]loginRow, 0)
	seen := make(map[string]bool)

	for _, table := range []string{"loginsL", "loginsM"} {
		if !dbsqlite.HasTable(db, table) {
			continue
		}
		query := fmt.Sprintf(`SELECT origin, httpRealm, formActionOrigin, timesUsed,
			timeCreated, timeLastUsed, secFields, guid FROM %s`, table)
		switch table {
		case "loginsL":
			if dbsqlite.HasColumn(db, table, "is_deleted") {
				query += " WHERE is_deleted = 0"
			}
		case "loginsM":
			if dbsqlite.HasColumn(db, table, "is_overridden") {
				query += " WHERE is_overridden = 0"
			}
		}
		rs, err := db.Query(query)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s/%s: query %s: %v", profile.Browser, profile.Name, table, err))
			continue
		}
		for rs.Next() {
			var (
				origin, realm, action, secFields, guid sql.NullString
				timesUsed, created, lastUsed           sql.NullInt64
			)
			if err := rs.Scan(&origin, &realm, &action, &timesUsed, &created, &lastUsed, &secFields, &guid); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: scan %s: %v", profile.Browser, profile.Name, table, err))
				continue
			}
			key := guid.String
			if key == "" {
				key = origin.String + "\x00" + realm.String + "\x00" + action.String + "\x00" + fmt.Sprint(created.Int64)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, loginRow{
				origin:           origin.String,
				httpRealm:        realm.String,
				formActionOrigin: action.String,
				timesUsed:        timesUsed.Int64,
				timeCreated:      created.Int64,
				timeLastUsed:     lastUsed.Int64,
				secFields:        secFields.String,
				guid:             guid.String,
			})
		}
		if err := rs.Err(); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s/%s: read %s: %v", profile.Browser, profile.Name, table, err))
		}
		rs.Close()
	}

	out := make([]model.Credential, 0, len(rows))
	for _, row := range rows {
		if row.origin == "" {
			continue
		}
		cred := model.Credential{
			Browser:     profile.Browser,
			Profile:     profile.Name,
			URL:         row.origin,
			Realm:       row.httpRealm,
			HasPassword: row.secFields != "",
			TimesUsed:   row.timesUsed,
		}
		if row.formActionOrigin != "" && row.formActionOrigin != row.origin {
			cred.Note = "form action: " + row.formActionOrigin
		}
		if strings.HasPrefix(row.origin, "chrome://FirefoxAccounts") {
			cred.Note = "Mozilla Account credentials"
			if row.httpRealm != "" {
				cred.Note += " (" + row.httpRealm + ")"
			}
		}
		if row.timeCreated > 0 {
			t := time.UnixMilli(row.timeCreated).UTC()
			cred.Created = &t
		}
		if row.timeLastUsed > 0 {
			t := time.UnixMilli(row.timeLastUsed).UTC()
			cred.LastUsed = &t
		}

		if key != nil && row.secFields != "" {
			plain, err := key.DecryptSecFields(row.secFields)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: decrypt logins.db entry for %s: %v",
					profile.Browser, profile.Name, row.origin, err))
				cred.Note = "decryption failed: " + err.Error()
			} else {
				user, pass, note, err := parseSecFields(plain)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s/%s: parse logins.db entry for %s: %v",
						profile.Browser, profile.Name, row.origin, err))
					cred.Note = "unsupported secFields payload"
				} else {
					cred.Username = user
					cred.Password = pass
					if strings.HasPrefix(row.origin, "chrome://FirefoxAccounts") {
						// This row contains Mozilla Account sync tokens, not a
						// site password. Keep the username but never expose
						// the structured payload as a password.
						cred.Password = ""
						note = "Mozilla Account credentials (account data is not a site password)"
					}
					if note != "" {
						cred.Note = note
					}
				}
			}
		}
		out = append(out, cred)
	}
	return out, warnings, true
}

func parseSecFields(plain []byte) (username, password, note string, err error) {
	// Firefox's logins.db stores the short keys u/p. Older or future builds
	// may use descriptive names, so handle both.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(plain, &obj); err == nil {
		readString := func(key string) string {
			raw, ok := obj[key]
			if !ok {
				return ""
			}
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return ""
			}
			return value
		}
		username = readString("u")
		if username == "" {
			username = readString("username")
		}
		if username == "" {
			username = readString("user")
		}
		rawPassword, hasPassword := obj["p"]
		if !hasPassword {
			rawPassword, hasPassword = obj["password"]
		}
		if hasPassword {
			var value string
			if err := json.Unmarshal(rawPassword, &value); err == nil {
				password = value
			} else {
				// Firefox Accounts rows keep a structured account-data object
				// in p. It is not a site password and must not be printed.
				var structured any
				if json.Unmarshal(rawPassword, &structured) == nil {
					note = "structured account data (no site password)"
				}
			}
		}
		if action := readString("formActionOrigin"); action != "" {
			note = "form action: " + action
		}
		if username != "" || password != "" || note != "" {
			return username, password, note, nil
		}
	}

	var value any
	if err := json.Unmarshal(plain, &value); err != nil {
		return "", "", "", err
	}
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for k, child := range typed {
				switch strings.ToLower(k) {
				case "username", "user", "usernamevalue":
					if s, ok := child.(string); ok && username == "" {
						username = s
					}
				case "password", "pass", "passwordvalue":
					if s, ok := child.(string); ok && password == "" {
						password = s
					}
				case "formactionorigin", "formaction":
					if s, ok := child.(string); ok && note == "" {
						note = "form action: " + s
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return username, password, note, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// History returns visited URLs from places.sqlite.
func History(profile model.Profile, since time.Time, limit int) ([]model.HistoryEntry, []string) {
	path := artifact(profile, "places", "places.sqlite")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open places.sqlite: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "moz_places") {
		return nil, nil
	}

	query := "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC"
	args := []any{}
	if !since.IsZero() {
		query = "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL AND last_visit_date >= ? ORDER BY last_visit_date DESC"
		args = append(args, since.UnixMicro())
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query places: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.HistoryEntry
	for rows.Next() {
		var (
			url    sql.NullString
			title  sql.NullString
			visits sql.NullInt64
			last   sql.NullInt64
		)
		if err := rows.Scan(&url, &title, &visits, &last); err != nil {
			continue
		}
		if url.String == "" {
			continue
		}
		entry := model.HistoryEntry{
			Browser:    profile.Browser,
			Profile:    profile.Name,
			URL:        url.String,
			Title:      title.String,
			VisitCount: visits.Int64,
		}
		if last.Int64 > 0 {
			entry.LastVisit = time.UnixMicro(last.Int64).UTC()
		}
		out = append(out, entry)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Cookies returns cookies from cookies.sqlite. Firefox stores them in
// plaintext.
func Cookies(profile model.Profile) ([]model.Cookie, []string) {
	path := artifact(profile, "cookies", "cookies.sqlite")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open cookies.sqlite: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "moz_cookies") {
		return nil, nil
	}
	rows, err := db.Query("SELECT host, name, path, expiry, isSecure, isHttpOnly, value FROM moz_cookies")
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query cookies: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.Cookie
	for rows.Next() {
		var (
			host, name, path, value sql.NullString
			expiry                  sql.NullInt64
			secure, httpOnly        sql.NullInt64
		)
		if err := rows.Scan(&host, &name, &path, &expiry, &secure, &httpOnly, &value); err != nil {
			continue
		}
		cookie := model.Cookie{
			Browser:  profile.Browser,
			Profile:  profile.Name,
			Host:     host.String,
			Name:     name.String,
			Path:     path.String,
			Value:    value.String,
			Secure:   secure.Int64 != 0,
			HTTPOnly: httpOnly.Int64 != 0,
		}
		if expiry.Int64 > 0 {
			cookie.Expires = time.Unix(expiry.Int64, 0).UTC()
		}
		out = append(out, cookie)
	}
	return out, nil
}

// Bookmarks returns bookmarks from places.sqlite.
func Bookmarks(profile model.Profile) ([]model.Bookmark, []string) {
	path := artifact(profile, "places", "places.sqlite")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open places.sqlite: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "moz_bookmarks") || !dbsqlite.HasTable(db, "moz_places") {
		return nil, nil
	}

	rows, err := db.Query(`SELECT b.id, b.type, b.title, b.parent, p.url, b.dateAdded
		FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id`)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query bookmarks: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	type row struct {
		id        int64
		nodeType  int64
		title     string
		parent    int64
		url       string
		dateAdded int64
	}
	var all []row
	folders := make(map[int64]row)
	for rows.Next() {
		var (
			r       row
			title   sql.NullString
			url     sql.NullString
			parent  sql.NullInt64
			added   sql.NullInt64
			nodeTyp sql.NullInt64
		)
		if err := rows.Scan(&r.id, &nodeTyp, &title, &parent, &url, &added); err != nil {
			continue
		}
		r.title = title.String
		r.parent = parent.Int64
		r.url = url.String
		r.dateAdded = added.Int64
		r.nodeType = nodeTyp.Int64
		all = append(all, r)
		if r.nodeType == 2 {
			folders[r.id] = r
		}
	}

	folderPath := func(id int64) string {
		var parts []string
		for depth := 0; depth < 32; depth++ {
			folder, ok := folders[id]
			if !ok || id <= 0 {
				break
			}
			if folder.title != "" {
				parts = append([]string{folder.title}, parts...)
			}
			id = folder.parent
			if id <= 0 {
				break
			}
		}
		return strings.Join(parts, "/")
	}

	var out []model.Bookmark
	for _, r := range all {
		if r.nodeType != 1 || r.url == "" {
			continue
		}
		bookmark := model.Bookmark{
			Browser: profile.Browser,
			Profile: profile.Name,
			Folder:  folderPath(r.parent),
			Title:   r.title,
			URL:     r.url,
		}
		if r.dateAdded > 0 {
			bookmark.Added = time.UnixMicro(r.dateAdded).UTC()
		}
		out = append(out, bookmark)
	}
	return out, nil
}

// FormHistory returns saved form field values.
func FormHistory(profile model.Profile) ([]model.AutofillEntry, []string) {
	path := artifact(profile, "formhistory", "formhistory.sqlite")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open formhistory.sqlite: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "moz_formhistory") {
		return nil, nil
	}
	rows, err := db.Query("SELECT fieldname, value, timesUsed FROM moz_formhistory")
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query form history: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.AutofillEntry
	for rows.Next() {
		var (
			field, value sql.NullString
			times        sql.NullInt64
		)
		if err := rows.Scan(&field, &value, &times); err != nil {
			continue
		}
		if value.String == "" {
			continue
		}
		out = append(out, model.AutofillEntry{
			Browser: profile.Browser,
			Profile: profile.Name,
			Field:   field.String,
			Value:   value.String,
			Count:   times.Int64,
		})
	}
	return out, nil
}
