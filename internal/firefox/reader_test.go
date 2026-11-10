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
	"strings"
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

func makeSecFields(t *testing.T, key, payload []byte) string {
	t.Helper()
	header := []byte(`{"alg":"dir","enc":"A256GCM"}`)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	iv := randomKey(12)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, iv, payload, []byte(encodedHeader))
	parts := []string{
		encodedHeader,
		"",
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(sealed[:len(sealed)-gcm.Overhead()]),
		base64.RawURLEncoding.EncodeToString(sealed[len(sealed)-gcm.Overhead():]),
	}
	return strings.Join(parts, ".")
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

func TestPasswordsFromLoginsDB(t *testing.T) {
	dir := t.TempDir()
	key := randomKey(32)
	key4, err := nss.NewKey4WithKeys(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := makeSecFields(t, key, []byte(`{"u":"alice","p":"hunter2"}`))
	second := makeSecFields(t, key, []byte(`{"u":"bob","p":"swordfish","formActionOrigin":"https://login.example.com"}`))
	account := makeSecFields(t, key, []byte(`{"u":"me@example.com","p":"{\"accountData\":{\"scopedKeys\":{}}}"}`))

	db := createDB(t, filepath.Join(dir, "logins.db"), `
		CREATE TABLE loginsL (
			id INTEGER PRIMARY KEY, origin TEXT, httpRealm TEXT, formActionOrigin TEXT,
			usernameField TEXT, passwordField TEXT, timesUsed INTEGER, timeCreated INTEGER,
			timeLastUsed INTEGER, timePasswordChanged INTEGER, timeLastBreachAlertDismissed INTEGER,
			secFields TEXT, guid TEXT, local_modified INTEGER, is_deleted INTEGER, sync_status INTEGER
		);
		CREATE TABLE loginsM (
			id INTEGER PRIMARY KEY, origin TEXT, httpRealm TEXT, formActionOrigin TEXT,
			usernameField TEXT, passwordField TEXT, timesUsed INTEGER, timeCreated INTEGER,
			timeLastUsed INTEGER, timePasswordChanged INTEGER, timeLastBreachAlertDismissed INTEGER,
			secFields TEXT, guid TEXT, server_modified INTEGER, is_overridden INTEGER, enc_unknown_fields TEXT
		);
	`)
	if _, err := db.Exec(`INSERT INTO loginsL VALUES
		(1,'https://example.com',NULL,'https://example.com','','',3,1700000000000,1700000001000,0,0,?,'g1',0,0,0)`, first); err != nil {
		t.Fatal(err)
	}
	// loginsM contains a mirrored copy of g1 and one new entry. The mirror
	// must not produce a duplicate.
	if _, err := db.Exec(`INSERT INTO loginsM VALUES
		(2,'https://example.com',NULL,'https://example.com','','',3,1700000000000,1700000001000,0,0,?,'g1',0,0,NULL)`, first); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO loginsM VALUES
		(3,'https://login.example.com',NULL,'https://login.example.com','','',1,1700000002000,1700000003000,0,0,?,'g2',0,0,NULL)`, second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO loginsM VALUES
		(4,'chrome://FirefoxAccounts','Firefox Accounts credentials',NULL,'','',1,1700000004000,1700000005000,0,0,?,'g3',0,0,NULL)`, account); err != nil {
		t.Fatal(err)
	}
	// A deleted local row must be skipped.
	if _, err := db.Exec(`INSERT INTO loginsL VALUES
		(5,'https://deleted.example.com',NULL,NULL,'','',0,0,0,0,0,?,'g4',0,1,0)`, first); err != nil {
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
	if len(creds) != 3 {
		t.Fatalf("got %d credentials, want 3: %+v", len(creds), creds)
	}
	byURL := make(map[string]model.Credential)
	for _, cred := range creds {
		byURL[cred.URL] = cred
	}
	if got := byURL["https://example.com"]; got.Username != "alice" || got.Password != "hunter2" || got.TimesUsed != 3 {
		t.Fatalf("unexpected first credential: %+v", got)
	}
	if got := byURL["https://login.example.com"]; got.Username != "bob" || got.Password != "swordfish" ||
		!strings.Contains(got.Note, "form action") {
		t.Fatalf("unexpected second credential: %+v", got)
	}
	if got := byURL["chrome://FirefoxAccounts"]; got.Username != "me@example.com" || got.Password != "" ||
		!strings.Contains(got.Note, "Mozilla Account") {
		t.Fatalf("unexpected account credential: %+v", got)
	}
	if _, ok := byURL["https://deleted.example.com"]; ok {
		t.Fatal("deleted login was not skipped")
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
