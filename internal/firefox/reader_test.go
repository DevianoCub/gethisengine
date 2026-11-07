package firefox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"gethisengine/internal/crypt/nss"
	"gethisengine/internal/model"
)

func randomKey(n int) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	return key
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	out := append([]byte(nil), data...)
	for i := 0; i < padding; i++ {
		out = append(out, byte(padding))
	}
	return out
}

type testEntry struct {
	KeyID  []byte
	Params struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
	Ciphertext []byte
}

func encryptLogin(t *testing.T, plaintext string, key []byte, oid asn1.ObjectIdentifier, ivLen, blockSize int) string {
	t.Helper()
	iv := randomKey(ivLen)
	var block cipher.Block
	var err error
	if blockSize == aes.BlockSize {
		block, err = aes.NewCipher(key)
	} else {
		block, err = des.NewTripleDESCipher(key[:24])
	}
	if err != nil {
		t.Fatal(err)
	}
	padded := pad([]byte(plaintext), blockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)

	entry := testEntry{KeyID: make([]byte, 16), Ciphertext: out}
	entry.Params.Algorithm = oid
	entry.Params.IV = iv
	der, err := asn1.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
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

func TestPasswordsWithKeys(t *testing.T) {
	dir := t.TempDir()
	key := randomKey(32)
	desKey := key[:24]

	user := encryptLogin(t, "alice", key, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, 16, aes.BlockSize)
	pass := encryptLogin(t, "hunter2", desKey, asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}, 8, des.BlockSize)

	payload := map[string]any{
		"logins": []map[string]any{{
			"hostname":          "https://example.com",
			"formSubmitURL":     "https://example.com/login",
			"encryptedUsername": user,
			"encryptedPassword": pass,
			"timeCreated":       1700000000000,
			"timeLastUsed":      1700000001000,
			"timesUsed":         4,
		}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logins.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	key4, err := nss.NewKey4WithKeys(key, desKey)
	if err != nil {
		t.Fatal(err)
	}

	profile := model.Profile{
		Family: model.FamilyFirefox, BrowserKey: "firefox", Browser: "Firefox",
		Name: "default", Path: dir,
	}
	creds, warnings := Passwords(profile, key4)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d credentials", len(creds))
	}
	if creds[0].Username != "alice" || creds[0].Password != "hunter2" {
		t.Fatalf("unexpected credentials: %+v", creds[0])
	}
	if creds[0].Created == nil || !creds[0].Created.Equal(time.UnixMilli(1700000000000)) {
		t.Fatalf("unexpected creation time: %v", creds[0].Created)
	}
	if creds[0].TimesUsed != 4 {
		t.Fatalf("unexpected times used: %d", creds[0].TimesUsed)
	}
}

func TestHistoryCookiesAndBookmarks(t *testing.T) {
	dir := t.TempDir()
	nowMicros := time.Now().UnixMicro()

	places := createDB(t, filepath.Join(dir, "places.sqlite"), `
		CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
		CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER);
	`)
	if _, err := places.Exec(`INSERT INTO moz_places VALUES (1,?,?,?,?)`,
		"https://example.com", "Example", 2, nowMicros); err != nil {
		t.Fatal(err)
	}
	if _, err := places.Exec(`INSERT INTO moz_bookmarks VALUES (10,2,NULL,0,'Menu',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := places.Exec(`INSERT INTO moz_bookmarks VALUES (11,1,1,10,'Example',?)`, nowMicros); err != nil {
		t.Fatal(err)
	}

	cookies := createDB(t, filepath.Join(dir, "cookies.sqlite"), `
		CREATE TABLE moz_cookies (host TEXT, name TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, value TEXT);
	`)
	if _, err := cookies.Exec(`INSERT INTO moz_cookies VALUES ('example.com','sid','/',?,1,1,'abc')`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	profile := model.Profile{
		Family: model.FamilyFirefox, BrowserKey: "firefox", Browser: "Firefox",
		Name: "default", Path: dir,
	}

	history, warnings := History(profile, time.Time{}, 0)
	if len(warnings) != 0 || len(history) != 1 {
		t.Fatalf("history=%d warnings=%v", len(history), warnings)
	}
	if history[0].URL != "https://example.com" || history[0].Title != "Example" {
		t.Fatalf("unexpected history: %+v", history[0])
	}
	if history[0].LastVisit.IsZero() {
		t.Fatal("history timestamp was not converted")
	}

	cookieList, warnings := Cookies(profile)
	if len(warnings) != 0 || len(cookieList) != 1 {
		t.Fatalf("cookies=%d warnings=%v", len(cookieList), warnings)
	}
	if cookieList[0].Value != "abc" || !cookieList[0].Secure || !cookieList[0].HTTPOnly {
		t.Fatalf("unexpected cookie: %+v", cookieList[0])
	}

	bookmarkList, warnings := Bookmarks(profile)
	if len(warnings) != 0 || len(bookmarkList) != 1 {
		t.Fatalf("bookmarks=%d warnings=%v", len(bookmarkList), warnings)
	}
	if bookmarkList[0].Folder != "Menu" || bookmarkList[0].URL != "https://example.com" {
		t.Fatalf("unexpected bookmark: %+v", bookmarkList[0])
	}
}
