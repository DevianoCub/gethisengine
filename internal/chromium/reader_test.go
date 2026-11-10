package chromium

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"gethisengine/internal/crypt"
	"gethisengine/internal/model"
)

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func encryptV10(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{' '}, aes.BlockSize)
	padded := pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return append([]byte("v10"), out...)
}

func createDB(t *testing.T, path, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPasswordsAndHistory(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x11}, 16)

	db := createDB(t, filepath.Join(dir, "Login Data"), `
		CREATE TABLE logins (
			origin_url TEXT, action_url TEXT, username_value TEXT, password_value BLOB,
			signon_realm TEXT, date_created INTEGER, date_last_used INTEGER,
			times_used INTEGER, blacklisted_by_user INTEGER);
	`)
	encrypted := encryptV10(t, key, []byte("hunter2"))
	now := time.Now().UTC().Truncate(time.Millisecond)
	chromeNow := now.UnixMicro() + chromeEpochOffsetMicros
	if _, err := db.Exec(`INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?)`,
		"https://example.com/login", "https://example.com/session", "alice", encrypted,
		"https://example.com", chromeNow, chromeNow, 5, 0); err != nil {
		t.Fatal(err)
	}

	historyDB := createDB(t, filepath.Join(dir, "History"), `
		CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
	`)
	if _, err := historyDB.Exec(`INSERT INTO urls VALUES (?,?,?,?)`,
		"https://example.com", "Example", 3, chromeNow); err != nil {
		t.Fatal(err)
	}

	profile := model.Profile{
		Family: model.FamilyChromium, BrowserKey: "chrome", Browser: "Chrome",
		Name: "Default", Path: dir,
	}

	creds, warnings := Passwords(profile, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d credentials, want 1", len(creds))
	}
	if !creds[0].HasPassword || creds[0].Password != "" {
		t.Fatalf("unexpected credential without decryptor: %+v", creds[0])
	}

	decryptor := crypt.NewChromiumDecryptorWithKey(key, crypt.ModeCBC)
	creds, warnings = Passwords(profile, decryptor)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if creds[0].Password != "hunter2" {
		t.Fatalf("got password %q", creds[0].Password)
	}
	if creds[0].Username != "alice" || creds[0].TimesUsed != 5 {
		t.Fatalf("unexpected metadata: %+v", creds[0])
	}

	entries, warnings := History(profile, time.Time{}, 0)
	if len(warnings) != 0 || len(entries) != 1 {
		t.Fatalf("history=%d warnings=%v", len(entries), warnings)
	}
	if entries[0].URL != "https://example.com" || entries[0].VisitCount != 3 {
		t.Fatalf("unexpected history entry: %+v", entries[0])
	}

	future := time.Now().Add(time.Hour)
	entries, _ = History(profile, future, 0)
	if len(entries) != 0 {
		t.Fatalf("expected no entries after %v, got %d", future, len(entries))
	}

	entries, _ = History(profile, time.Time{}, 1)
	if len(entries) != 1 {
		t.Fatalf("limit not applied: %d", len(entries))
	}
}

func TestCookiesWithDomainHash(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x22}, 16)

	db := createDB(t, filepath.Join(dir, "Cookies"), `
		CREATE TABLE cookies (
			host_key TEXT, name TEXT, path TEXT, expires_utc INTEGER,
			is_secure INTEGER, is_httponly INTEGER, value TEXT, encrypted_value BLOB);
	`)
	host := ".example.com"
	sum := sha256.Sum256([]byte(host))
	plain := append(sum[:], []byte("cookie-value")...)
	encrypted := encryptV10(t, key, plain)
	if _, err := db.Exec(`INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)`,
		host, "session", "/", 0, 1, 1, "", encrypted); err != nil {
		t.Fatal(err)
	}

	profile := model.Profile{
		Family: model.FamilyChromium, BrowserKey: "chrome", Browser: "Chrome",
		Name: "Default", Path: dir,
	}
	decryptor := crypt.NewChromiumDecryptorWithKey(key, crypt.ModeCBC)
	cookies, warnings := Cookies(profile, decryptor)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	if cookies[0].Value != "cookie-value" {
		t.Fatalf("got cookie value %q", cookies[0].Value)
	}
}

func TestBookmarksAndAutofill(t *testing.T) {
	dir := t.TempDir()
	profile := model.Profile{
		Family: model.FamilyChromium, BrowserKey: "chrome", Browser: "Chrome",
		Name: "Default", Path: dir,
	}

	bookmarks := map[string]any{
		"roots": map[string]any{
			"bookmark_bar": map[string]any{
				"type": "folder", "name": "Bookmarks",
				"children": []any{
					map[string]any{"type": "url", "name": "Example", "url": "https://example.com", "date_added": int64(13350000000000000)},
					map[string]any{"type": "folder", "name": "Nested", "children": []any{
						map[string]any{"type": "url", "name": "Nested page", "url": "https://nested.example", "date_added": "13350000000000001"},
					}},
				},
			},
		},
	}
	data, err := json.Marshal(bookmarks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Bookmarks"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	found, warnings := Bookmarks(profile)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(found) != 2 {
		t.Fatalf("got %d bookmarks", len(found))
	}
	if found[0].Folder != "Bookmarks" || found[1].Folder != "Bookmarks/Nested" {
		t.Fatalf("unexpected folders: %q, %q", found[0].Folder, found[1].Folder)
	}
	if found[0].Added.IsZero() {
		t.Fatal("numeric date_added was not parsed")
	}

	db := createDB(t, filepath.Join(dir, "Web Data"), `
		CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER);
	`)
	if _, err := db.Exec(`INSERT INTO autofill VALUES ('email', 'alice@example.com', 4)`); err != nil {
		t.Fatal(err)
	}
	entries, warnings := Autofill(profile)
	if len(warnings) != 0 || len(entries) != 1 {
		t.Fatalf("autofill=%d warnings=%v", len(entries), warnings)
	}
	if entries[0].Field != "email" || entries[0].Value != "alice@example.com" {
		t.Fatalf("unexpected autofill entry: %+v", entries[0])
	}
}
