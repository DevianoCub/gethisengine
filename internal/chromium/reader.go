// Package chromium reads data from Chromium-based browser profiles: saved
// logins, history, cookies, bookmarks and autofill entries.
package chromium

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gethisengine/internal/model"
	dbsqlite "gethisengine/internal/sqlite"
)

// Decryptor matches crypt.ChromiumDecryptor and keeps this package testable.
type Decryptor interface {
	Decrypt(blob []byte) ([]byte, error)
}

// chromeEpochOffsetMicros is the number of microseconds between
// 1601-01-01 (Chromium's epoch) and 1970-01-01 (Unix epoch).
const chromeEpochOffsetMicros = int64(11644473600000000)

func chromeTime(micros int64) time.Time {
	if micros <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (micros-chromeEpochOffsetMicros)*1000).UTC()
}

func artifact(profile model.Profile, key, fallback string) string {
	if path := profile.Artifacts[key]; path != "" {
		return path
	}
	return filepath.Join(profile.Path, fallback)
}

// Passwords returns saved logins. When dec is nil the password values are
// left empty and HasPassword reports whether an encrypted value is present.
func Passwords(profile model.Profile, dec Decryptor) ([]model.Credential, []string) {
	path := artifact(profile, "logins", "Login Data")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open Login Data: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "logins") {
		return nil, nil
	}

	col := func(name, fallback string) string {
		if dbsqlite.HasColumn(db, "logins", name) {
			return name
		}
		return fallback
	}
	query := fmt.Sprintf(`SELECT origin_url, action_url, username_value, password_value, signon_realm,
		%s AS date_created, %s AS date_last_used, %s AS times_used, %s AS blacklisted
		FROM logins`,
		col("date_created", "0"), col("date_last_used", "0"),
		col("times_used", "0"), col("blacklisted_by_user", "0"))

	rows, err := db.Query(query)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query logins: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.Credential
	var warnings []string
	for rows.Next() {
		var (
			origin, action, username, realm sql.NullString
			password                        []byte
			created, lastUsed, timesUsed    sql.NullInt64
			blacklisted                     sql.NullInt64
		)
		if err := rows.Scan(&origin, &action, &username, &password, &realm, &created, &lastUsed, &timesUsed, &blacklisted); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s/%s: scan login row: %v", profile.Browser, profile.Name, err))
			continue
		}

		cred := model.Credential{
			Browser:     profile.Browser,
			Profile:     profile.Name,
			URL:         origin.String,
			Realm:       realm.String,
			Username:    username.String,
			HasPassword: len(password) > 0 && blacklisted.Int64 == 0,
			TimesUsed:   timesUsed.Int64,
		}
		if action.Valid && action.String != "" && action.String != origin.String {
			cred.Note = "form action: " + action.String
		}
		if created.Int64 > 0 {
			t := chromeTime(created.Int64)
			cred.Created = &t
		}
		if lastUsed.Int64 > 0 {
			t := chromeTime(lastUsed.Int64)
			cred.LastUsed = &t
		}
		if blacklisted.Int64 != 0 {
			cred.Note = "login disabled by user"
		}

		if cred.HasPassword && dec != nil {
			plain, err := dec.Decrypt(password)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: decrypt password for %s: %v",
					profile.Browser, profile.Name, cred.URL, err))
				cred.Note = "decryption failed: " + err.Error()
			} else {
				cred.Password = string(plain)
			}
		}
		out = append(out, cred)
	}
	return out, warnings
}

// History returns visited URLs ordered newest first.
func History(profile model.Profile, since time.Time, limit int) ([]model.HistoryEntry, []string) {
	path := artifact(profile, "history", "History")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open History: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "urls") {
		return nil, nil
	}

	query := "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
	args := []any{}
	if !since.IsZero() {
		query = "SELECT url, title, visit_count, last_visit_time FROM urls WHERE last_visit_time >= ? ORDER BY last_visit_time DESC"
		args = append(args, since.UnixMicro()+chromeEpochOffsetMicros)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query history: %v", profile.Browser, profile.Name, err)}
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
		out = append(out, model.HistoryEntry{
			Browser:    profile.Browser,
			Profile:    profile.Name,
			URL:        url.String,
			Title:      title.String,
			VisitCount: visits.Int64,
			LastVisit:  chromeTime(last.Int64),
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Cookies returns stored cookies. When dec is nil, encrypted values are left
// empty.
func Cookies(profile model.Profile, dec Decryptor) ([]model.Cookie, []string) {
	path := artifact(profile, "cookies", "Cookies")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open Cookies: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "cookies") {
		return nil, nil
	}
	valueCol := "''"
	if dbsqlite.HasColumn(db, "cookies", "value") {
		valueCol = "value"
	}
	query := fmt.Sprintf(`SELECT host_key, name, path, expires_utc, is_secure, is_httponly, %s, encrypted_value FROM cookies`, valueCol)

	rows, err := db.Query(query)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query cookies: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.Cookie
	var warnings []string
	for rows.Next() {
		var (
			host, name, path, value sql.NullString
			expires                 sql.NullInt64
			secure, httpOnly        sql.NullInt64
			encrypted               []byte
		)
		if err := rows.Scan(&host, &name, &path, &expires, &secure, &httpOnly, &value, &encrypted); err != nil {
			continue
		}
		cookie := model.Cookie{
			Browser:  profile.Browser,
			Profile:  profile.Name,
			Host:     host.String,
			Name:     name.String,
			Path:     path.String,
			Value:    value.String,
			Expires:  chromeTime(expires.Int64),
			Secure:   secure.Int64 != 0,
			HTTPOnly: httpOnly.Int64 != 0,
		}
		if cookie.Value == "" && len(encrypted) > 0 && dec != nil {
			if plain, err := dec.Decrypt(encrypted); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: decrypt cookie %s: %v",
					profile.Browser, profile.Name, cookie.Name, err))
			} else {
				cookie.Value = string(stripCookieDomainHash(cookie.Host, plain))
			}
		}
		out = append(out, cookie)
	}
	return out, warnings
}

// stripCookieDomainHash removes the SHA-256(host) prefix that newer Chromium
// versions prepend to encrypted cookie values (domain-bound cookies).
func stripCookieDomainHash(host string, plain []byte) []byte {
	if len(plain) <= sha256.Size {
		return plain
	}
	candidates := []string{
		host,
		strings.TrimPrefix(host, "."),
		"http://" + host,
		"https://" + host,
		"http://" + strings.TrimPrefix(host, "."),
		"https://" + strings.TrimPrefix(host, "."),
	}
	for _, candidate := range candidates {
		sum := sha256.Sum256([]byte(candidate))
		if bytes.Equal(plain[:sha256.Size], sum[:]) {
			return plain[sha256.Size:]
		}
	}
	return plain
}

// ------------------------------------------------------------------ bookmarks
type bookmarkNode struct {
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	URL       string          `json:"url"`
	DateAdded json.RawMessage `json:"date_added"`
	Children  []bookmarkNode  `json:"children"`
}

func bookmarkTime(raw json.RawMessage) time.Time {
	value := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if value == "" {
		return time.Time{}
	}
	micros, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return chromeTime(micros)
}

type bookmarksFile struct {
	Roots map[string]bookmarkNode `json:"roots"`
}

// Bookmarks returns bookmarks from the profile's Bookmarks JSON file.
func Bookmarks(profile model.Profile) ([]model.Bookmark, []string) {
	path := artifact(profile, "bookmarks", "Bookmarks")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("%s: read Bookmarks: %v", profile.Browser, err)}
	}

	var file bookmarksFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: parse Bookmarks: %v", profile.Browser, profile.Name, err)}
	}

	var out []model.Bookmark
	var walk func(node bookmarkNode, folder string)
	walk = func(node bookmarkNode, folder string) {
		switch node.Type {
		case "url":
			out = append(out, model.Bookmark{
				Browser: profile.Browser,
				Profile: profile.Name,
				Folder:  folder,
				Title:   node.Name,
				URL:     node.URL,
				Added:   bookmarkTime(node.DateAdded),
			})
		case "folder":
			next := folder
			if node.Name != "" {
				if next == "" {
					next = node.Name
				} else {
					next = next + "/" + node.Name
				}
			}
			for _, child := range node.Children {
				walk(child, next)
			}
		}
	}
	for _, root := range file.Roots {
		walk(root, "")
	}
	return out, nil
}

// Autofill returns entries from the "autofill" table of Web Data.
func Autofill(profile model.Profile) ([]model.AutofillEntry, []string) {
	path := artifact(profile, "web_data", "Web Data")
	db, cleanup, err := dbsqlite.OpenReadOnly(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: open Web Data: %v", profile.Browser, err)}
	}
	defer cleanup()

	if !dbsqlite.HasTable(db, "autofill") {
		return nil, nil
	}
	countCol := "0"
	if dbsqlite.HasColumn(db, "autofill", "count") {
		countCol = "count"
	}
	rows, err := db.Query(fmt.Sprintf("SELECT name, value, %s FROM autofill", countCol))
	if err != nil {
		return nil, []string{fmt.Sprintf("%s/%s: query autofill: %v", profile.Browser, profile.Name, err)}
	}
	defer rows.Close()

	var out []model.AutofillEntry
	for rows.Next() {
		var (
			name, value sql.NullString
			count       sql.NullInt64
		)
		if err := rows.Scan(&name, &value, &count); err != nil {
			continue
		}
		if value.String == "" {
			continue
		}
		out = append(out, model.AutofillEntry{
			Browser: profile.Browser,
			Profile: profile.Name,
			Field:   name.String,
			Value:   value.String,
			Count:   count.Int64,
		})
	}
	return out, nil
}
