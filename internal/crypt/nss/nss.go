// Package nss decrypts Mozilla/Firefox NSS-protected login data.
//
// Modern Firefox stores the crypto material in key4.db (SQLite) and the
// encrypted logins in logins.json. This implementation parses key4.db
// directly and therefore does not depend on libnss being installed or on the
// browser running. The format is documented by the NSS sources and by the
// firepwd/firefox_decrypt projects.
package nss

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	dbsqlite "gethisengine/internal/sqlite"
)

var (
	oidPBEWithSHA1And3DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 5, 1, 3}
	oidPBES2              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oid3DESCBC            = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

var ckaID = []byte{
	0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}

// ErrWrongMasterPassword is returned when key4.db cannot be unlocked with the
// supplied (possibly empty) primary password.
var ErrWrongMasterPassword = errors.New("wrong Firefox primary (master) password")

var errUnsupportedAlgorithm = errors.New("unsupported PBE algorithm")

// Key4 holds the decrypted NSS master key material.
type Key4 struct {
	aesKey []byte // 32 bytes, used for AES-256-CBC logins (Firefox 144+)
	desKey []byte // 24 bytes, used for legacy 3DES logins
}

// NewKey4 unlocks key4.db using the given primary password ("" when none is
// configured) and returns a decryptor for logins.json entries.
func NewKey4(key4Path, masterPassword string) (*Key4, error) {
	db, cleanup, err := dbsqlite.OpenReadOnly(key4Path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var globalSalt, item2 []byte
	if err := db.QueryRow("SELECT item1, item2 FROM metadata WHERE id = 'password'").Scan(&globalSalt, &item2); err != nil {
		return nil, fmt.Errorf("read key4.db metadata: %w", err)
	}
	if len(item2) == 0 {
		return nil, errors.New("key4.db metadata is empty")
	}

	check, _, err := decryptPBE(item2, []byte(masterPassword), globalSalt)
	if err != nil {
		if errors.Is(err, errUnsupportedAlgorithm) {
			return nil, err
		}
		return nil, fmt.Errorf("%w (%v)", ErrWrongMasterPassword, err)
	}
	if !bytes.Equal(check, []byte("password-check\x02\x02")) {
		return nil, ErrWrongMasterPassword
	}

	rows, err := db.Query("SELECT a11, a102 FROM nssPrivate")
	if err != nil {
		return nil, fmt.Errorf("read key4.db nssPrivate: %w", err)
	}
	defer rows.Close()

	var master []byte
	for rows.Next() {
		var a11, a102 []byte
		if err := rows.Scan(&a11, &a102); err != nil {
			return nil, fmt.Errorf("scan key4.db nssPrivate: %w", err)
		}
		if len(a11) == 0 {
			continue
		}
		if len(a102) != 0 && !bytes.Equal(a102, ckaID) {
			continue
		}
		plain, _, err := decryptPBE(a11, []byte(masterPassword), globalSalt)
		if err != nil {
			return nil, fmt.Errorf("decrypt NSS master key: %w", err)
		}
		master = plain
		break
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(master) == 0 {
		return nil, errors.New("key4.db does not contain a usable master key")
	}

	key := &Key4{}
	if len(master) >= 32 {
		key.aesKey = append([]byte(nil), master[:32]...)
	}
	if len(master) >= 24 {
		key.desKey = append([]byte(nil), master[:24]...)
	}
	if key.aesKey == nil && key.desKey == nil {
		return nil, fmt.Errorf("unexpected NSS master key length %d", len(master))
	}
	return key, nil
}

// NewKey4WithKeys builds a decryptor from already-extracted key material.
// aesKey must be 32 bytes, desKey 24 bytes; either may be nil.
func NewKey4WithKeys(aesKey, desKey []byte) (*Key4, error) {
	if len(aesKey) != 0 && len(aesKey) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(aesKey))
	}
	if len(desKey) != 0 && len(desKey) != 24 {
		return nil, fmt.Errorf("3DES key must be 24 bytes, got %d", len(desKey))
	}
	if len(aesKey) == 0 && len(desKey) == 0 {
		return nil, errors.New("at least one NSS key is required")
	}
	return &Key4{
		aesKey: append([]byte(nil), aesKey...),
		desKey: append([]byte(nil), desKey...),
	}, nil
}

// Decrypt decrypts one base64-encoded logins.json field (username or
// password) and returns it as a string.
func (k *Key4) Decrypt(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	raw, err := decodeBase64(value)
	if err != nil {
		// Be lenient: a few tools write cleartext values into logins.json.
		return value, nil
	}

	var entry loginSecret
	if _, err := asn1.Unmarshal(raw, &entry); err != nil {
		return "", fmt.Errorf("parse login entry: %w", err)
	}

	blockSize := 8
	key := k.desKey
	switch {
	case entry.Params.Algorithm.Equal(oidAES256CBC):
		blockSize = aes.BlockSize
		key = k.aesKey
	case entry.Params.Algorithm.Equal(oid3DESCBC):
		blockSize = des.BlockSize
		key = k.desKey
	case len(entry.Params.IV) == aes.BlockSize && k.aesKey != nil:
		blockSize = aes.BlockSize
		key = k.aesKey
	}

	if len(key) == 0 {
		return "", errors.New("no suitable NSS key for this entry")
	}
	if len(entry.Params.IV) != blockSize {
		return "", fmt.Errorf("unexpected IV length %d for block size %d", len(entry.Params.IV), blockSize)
	}
	if len(entry.Ciphertext) == 0 || len(entry.Ciphertext)%blockSize != 0 {
		return "", errors.New("invalid ciphertext length")
	}

	var block cipher.Block
	if blockSize == aes.BlockSize {
		block, err = aes.NewCipher(key[:32])
	} else {
		block, err = des.NewTripleDESCipher(key[:24])
	}
	if err != nil {
		return "", err
	}

	out := make([]byte, len(entry.Ciphertext))
	cipher.NewCBCDecrypter(block, entry.Params.IV).CryptBlocks(out, entry.Ciphertext)
	out, err = unpad(out, blockSize)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func decodeBase64(value string) ([]byte, error) {
	if data, err := base64.StdEncoding.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

// ------------------------------------------------------------------ ASN.1

type pbeEncrypted struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	Encrypted []byte
}

type pbe3DESParams struct {
	Salt       []byte
	Iterations int
}

type pbkdf2PRF struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        pbkdf2PRF `asn1:"optional"`
}

type pbes2KDF struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbkdf2Params
}

type pbes2Scheme struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters []byte
}

type pbes2Params struct {
	KDF    pbes2KDF
	Scheme pbes2Scheme
}

type loginSecret struct {
	KeyID  []byte
	Params struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
	Ciphertext []byte
}

func decryptPBE(der, password, globalSalt []byte) ([]byte, string, error) {
	var pbe pbeEncrypted
	if _, err := asn1.Unmarshal(der, &pbe); err != nil {
		return nil, "", fmt.Errorf("parse PBE structure: %w", err)
	}

	switch {
	case pbe.Algorithm.Algorithm.Equal(oidPBEWithSHA1And3DES):
		var params pbe3DESParams
		if _, err := asn1.Unmarshal(pbe.Algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, "", fmt.Errorf("parse 3DES PBE parameters: %w", err)
		}
		key, iv := derive3DESKey(globalSalt, password, params.Salt)
		block, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, "", err
		}
		if len(pbe.Encrypted)%des.BlockSize != 0 {
			return nil, "", errors.New("invalid 3DES ciphertext length")
		}
		out := make([]byte, len(pbe.Encrypted))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, pbe.Encrypted)
		out, err = unpad(out, des.BlockSize)
		return out, "3DES", err

	case pbe.Algorithm.Algorithm.Equal(oidPBES2):
		var params pbes2Params
		if _, err := asn1.Unmarshal(pbe.Algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, "", fmt.Errorf("parse PBES2 parameters: %w", err)
		}
		if !params.KDF.Algorithm.Equal(oidPBKDF2) {
			return nil, "", fmt.Errorf("%w: KDF %v", errUnsupportedAlgorithm, params.KDF.Algorithm)
		}
		if !params.Scheme.Algorithm.Equal(oidAES256CBC) {
			return nil, "", fmt.Errorf("%w: cipher %v", errUnsupportedAlgorithm, params.Scheme.Algorithm)
		}

		keyLen := params.KDF.Parameters.KeyLength
		if keyLen == 0 {
			keyLen = 32
		}
		var hashFn func() hash.Hash = sha256.New
		if len(params.KDF.Parameters.PRF.Algorithm) != 0 && !params.KDF.Parameters.PRF.Algorithm.Equal(oidHMACSHA256) {
			hashFn = sha1.New
		}

		base := sha1.Sum(append(append([]byte(nil), globalSalt...), password...))
		key := pbkdf2.Key(base[:], params.KDF.Parameters.Salt,
			params.KDF.Parameters.Iterations, keyLen, hashFn)

		iv, err := asn1.Marshal(params.Scheme.Parameters)
		if err != nil {
			return nil, "", fmt.Errorf("reconstruct AES IV: %w", err)
		}
		if len(iv) != aes.BlockSize {
			return nil, "", fmt.Errorf("unexpected AES IV length %d", len(iv))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, "", err
		}
		if len(pbe.Encrypted)%aes.BlockSize != 0 {
			return nil, "", errors.New("invalid AES ciphertext length")
		}
		out := make([]byte, len(pbe.Encrypted))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, pbe.Encrypted)
		out, err = unpad(out, aes.BlockSize)
		return out, "AES-256", err

	default:
		return nil, "", fmt.Errorf("%w: %v", errUnsupportedAlgorithm, pbe.Algorithm.Algorithm)
	}
}

func derive3DESKey(globalSalt, password, entrySalt []byte) (key, iv []byte) {
	hp := sha1.Sum(append(append([]byte(nil), globalSalt...), password...))

	pes := make([]byte, 20)
	copy(pes, entrySalt)

	chp := sha1.Sum(append(append([]byte(nil), hp[:]...), entrySalt...))

	mac := hmac.New(sha1.New, chp[:])
	mac.Write(pes)
	mac.Write(entrySalt)
	k1 := mac.Sum(nil)

	mac = hmac.New(sha1.New, chp[:])
	mac.Write(pes)
	tk := mac.Sum(nil)

	mac = hmac.New(sha1.New, chp[:])
	mac.Write(tk)
	mac.Write(entrySalt)
	k2 := mac.Sum(nil)

	k := append(k1, k2...)
	return k[:24], k[24:32]
}

func unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}
