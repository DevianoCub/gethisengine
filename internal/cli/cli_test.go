package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func cliPad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func cliEncrypt(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{' '}, aes.BlockSize)
	padded := cliPad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return append([]byte("v10"), out...)
}

func cliDB(t *testing.T, path, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func cliWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeFixture builds a Chromium User Data tree with one profile.
func makeFixture(t *testing.T) (base string, keyHex string) {
	t.Helper()
	base = t.TempDir()
	profileDir := filepath.Join(base, "Default")

	cliWrite(t, filepath.Join(base, "Local State"), `{"profile":{"info_cache":{"Default":{"name":"Work"}}}}`)
	cliWrite(t, filepath.Join(profileDir, "Preferences"), `{}`)

	key := bytes.Repeat([]byte{0x5a}, 16)
	db := cliDB(t, filepath.Join(profileDir, "Login Data"), `
		CREATE TABLE logins (
			origin_url TEXT, action_url TEXT, username_value TEXT, password_value BLOB,
			signon_realm TEXT, date_created INTEGER, date_last_used INTEGER,
			times_used INTEGER, blacklisted_by_user INTEGER);
	`)
	if _, err := db.Exec(`INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?)`,
		"https://example.com", "https://example.com", "alice", cliEncrypt(t, key, []byte("hunter2")),
		"https://example.com", 0, 0, 1, 0); err != nil {
		t.Fatal(err)
	}

	history := cliDB(t, filepath.Join(profileDir, "History"), `
		CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
	`)
	if _, err := history.Exec(`INSERT INTO urls VALUES (?,?,?,?)`,
		"https://example.com", "Example", 1, time.Now().UnixMicro()+11644473600000000); err != nil {
		t.Fatal(err)
	}

	cookies := cliDB(t, filepath.Join(profileDir, "Cookies"), `
		CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, expires_utc INTEGER,
			is_secure INTEGER, is_httponly INTEGER, value TEXT, encrypted_value BLOB);
	`)
	if _, err := cookies.Exec(`INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)`,
		"example.com", "sid", "/", 0, 1, 1, "", cliEncrypt(t, key, []byte("cookie-secret"))); err != nil {
		t.Fatal(err)
	}

	bookmarks := map[string]any{
		"roots": map[string]any{
			"bookmark_bar": map[string]any{
				"type": "folder", "name": "Bar",
				"children": []any{
					map[string]any{"type": "url", "name": "Example", "url": "https://example.com", "date_added": "0"},
				},
			},
		},
	}
	data, err := json.Marshal(bookmarks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Bookmarks"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	autofill := cliDB(t, filepath.Join(profileDir, "Web Data"), `
		CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER);
	`)
	if _, err := autofill.Exec(`INSERT INTO autofill VALUES ('email','alice@example.com',2)`); err != nil {
		t.Fatal(err)
	}

	return base, hex.EncodeToString(key)
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := newRootCommand(&out, &errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestCLIEndToEnd(t *testing.T) {
	base, keyHex := makeFixture(t)

	out, _, err := runCLI(t, "scan", "--root", base, "--browser", "custom", "--format", "json")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(out, `"name": "Work"`) {
		t.Fatalf("scan output does not contain the profile: %s", out)
	}

	out, _, err = runCLI(t, "passwords", "--root", base, "--browser", "custom")
	if err != nil {
		t.Fatalf("passwords: %v", err)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatal("password leaked without --reveal")
	}
	if !strings.Contains(out, "********") {
		t.Fatalf("expected a masked password, got: %s", out)
	}

	out, _, err = runCLI(t, "passwords", "--root", base, "--browser", "custom", "--reveal", "--chromium-key-hex", keyHex)
	if err != nil {
		t.Fatalf("passwords --reveal: %v", err)
	}
	if !strings.Contains(out, "hunter2") {
		t.Fatalf("password not decrypted: %s", out)
	}

	out, _, err = runCLI(t, "history", "--root", base, "--browser", "custom", "--format", "json")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if !strings.Contains(out, "https://example.com") {
		t.Fatalf("history output is missing the URL: %s", out)
	}

	out, _, err = runCLI(t, "cookies", "--root", base, "--browser", "custom", "--reveal", "--chromium-key-hex", keyHex)
	if err != nil {
		t.Fatalf("cookies: %v", err)
	}
	if !strings.Contains(out, "cookie-secret") {
		t.Fatalf("cookie value not decrypted: %s", out)
	}

	out, _, err = runCLI(t, "bookmarks", "--root", base, "--browser", "custom")
	if err != nil {
		t.Fatalf("bookmarks: %v", err)
	}
	if !strings.Contains(out, "Example") {
		t.Fatalf("bookmark missing: %s", out)
	}

	out, _, err = runCLI(t, "autofill", "--root", base, "--browser", "custom")
	if err != nil {
		t.Fatalf("autofill: %v", err)
	}
	if !strings.Contains(out, "alice@example.com") {
		t.Fatalf("autofill entry missing: %s", out)
	}
}

func TestCLIDump(t *testing.T) {
	base, keyHex := makeFixture(t)
	outDir := t.TempDir()

	_, _, err := runCLI(t, "dump", "--root", base, "--browser", "custom",
		"--out", outDir, "--format", "both", "--reveal", "--chromium-key-hex", keyHex)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hunter2") {
		t.Fatal("dump report does not contain the decrypted password")
	}
	for _, name := range []string{"profiles.csv", "passwords.csv", "history.csv", "cookies.csv", "bookmarks.csv", "autofill.csv"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}
