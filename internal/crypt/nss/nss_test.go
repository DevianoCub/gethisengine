package nss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	_ "modernc.org/sqlite"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	out := append([]byte(nil), data...)
	for i := 0; i < padding; i++ {
		out = append(out, byte(padding))
	}
	return out
}

func cbcEncrypt(t *testing.T, block cipher.Block, iv, plaintext []byte) []byte {
	t.Helper()
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

type testPRF struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type testPBKDF2 struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        testPRF `asn1:"optional"`
}

type testKDF struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters testPBKDF2
}

type testScheme struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters []byte
}

type testPBES2 struct {
	KDF    testKDF
	Scheme testScheme
}

type testAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters testPBES2
}

type testEnvelope struct {
	Algorithm testAlgorithm
	Encrypted []byte
}

// pbeEncrypt produces the same DER structure that NSS writes into key4.db.
func pbeEncrypt(t *testing.T, plaintext, password, globalSalt []byte) []byte {
	t.Helper()
	entrySalt := randomBytes(t, 32)
	ivContent := randomBytes(t, 14)

	base := sha1.Sum(append(append([]byte(nil), globalSalt...), password...))
	key := pbkdf2.Key(base[:], entrySalt, 10000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := asn1.Marshal(ivContent)
	if err != nil {
		t.Fatal(err)
	}
	if len(iv) != aes.BlockSize {
		t.Fatalf("unexpected IV length %d", len(iv))
	}
	ciphertext := cbcEncrypt(t, block, iv, pkcs7Pad(plaintext, aes.BlockSize))

	envelope := testEnvelope{
		Algorithm: testAlgorithm{
			Algorithm: oidPBES2,
			Parameters: testPBES2{
				KDF: testKDF{
					Algorithm: oidPBKDF2,
					Parameters: testPBKDF2{
						Salt:       entrySalt,
						Iterations: 10000,
						KeyLength:  32,
						PRF:        testPRF{Algorithm: oidHMACSHA256, Params: asn1.NullRawValue},
					},
				},
				Scheme: testScheme{Algorithm: oidAES256CBC, Parameters: ivContent},
			},
		},
		Encrypted: ciphertext,
	}
	der, err := asn1.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type testLoginEnvelope struct {
	KeyID  []byte
	Params struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
	Ciphertext []byte
}

func encryptLogin(t *testing.T, plaintext string, key []byte, oid asn1.ObjectIdentifier, ivLen, blockSize int) string {
	t.Helper()
	iv := randomBytes(t, ivLen)
	var block cipher.Block
	var err error
	if blockSize == aes.BlockSize {
		block, err = aes.NewCipher(key[:32])
	} else {
		block, err = des.NewTripleDESCipher(key[:24])
	}
	if err != nil {
		t.Fatal(err)
	}
	entry := testLoginEnvelope{KeyID: ckaID, Ciphertext: cbcEncrypt(t, block, iv, pkcs7Pad([]byte(plaintext), blockSize))}
	entry.Params.Algorithm = oid
	entry.Params.IV = iv
	der, err := asn1.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func writeKey4(t *testing.T, dir string, password []byte, master []byte) string {
	t.Helper()
	globalSalt := randomBytes(t, 32)
	checkDER := pbeEncrypt(t, []byte("password-check\x02\x02"), password, globalSalt)
	masterDER := pbeEncrypt(t, master, password, globalSalt)

	path := filepath.Join(dir, "key4.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB);
		CREATE TABLE nssPrivate (id TEXT, a11 BLOB, a102 BLOB);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO metadata VALUES ('password', ?, ?)`, globalSalt, checkDER); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nssPrivate VALUES ('master', ?, ?)`, masterDER, ckaID); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKey4AndLogins(t *testing.T) {
	dir := t.TempDir()
	password := []byte("")
	master := randomBytes(t, 48)
	key4Path := writeKey4(t, dir, password, master)

	key, err := NewKey4(key4Path, "")
	if err != nil {
		t.Fatalf("NewKey4: %v", err)
	}

	aesEntry := encryptLogin(t, "alice", master, oidAES256CBC, 16, aes.BlockSize)
	desEntry := encryptLogin(t, "hunter2", master, oid3DESCBC, 8, des.BlockSize)

	file := map[string]any{
		"logins": []map[string]any{{
			"hostname":          "https://example.com",
			"formSubmitURL":     "https://example.com/login",
			"encryptedUsername": aesEntry,
			"encryptedPassword": desEntry,
			"timeCreated":       1700000000000,
			"timesUsed":         3,
		}},
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	loginsPath := filepath.Join(dir, "logins.json")
	if err := os.WriteFile(loginsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	user, err := key.Decrypt(aesEntry)
	if err != nil {
		t.Fatalf("decrypt AES username: %v", err)
	}
	if user != "alice" {
		t.Fatalf("got username %q", user)
	}
	pass, err := key.Decrypt(desEntry)
	if err != nil {
		t.Fatalf("decrypt 3DES password: %v", err)
	}
	if pass != "hunter2" {
		t.Fatalf("got password %q", pass)
	}
}

func TestWrongMasterPassword(t *testing.T) {
	dir := t.TempDir()
	key4Path := writeKey4(t, dir, []byte("correct"), randomBytes(t, 48))
	if _, err := NewKey4(key4Path, "wrong"); !errors.Is(err, ErrWrongMasterPassword) {
		t.Fatalf("got %v, want ErrWrongMasterPassword", err)
	}
}

func TestUnsupportedPBEScheme(t *testing.T) {
	envelope := struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		Encrypted []byte
	}{}
	envelope.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 99}
	envelope.Algorithm.Parameters = asn1.NullRawValue
	envelope.Encrypted = []byte{1, 2, 3}

	der, err := asn1.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decryptPBE(der, nil, nil); !errors.Is(err, errUnsupportedAlgorithm) {
		t.Fatalf("got %v, want errUnsupportedAlgorithm", err)
	}
}
