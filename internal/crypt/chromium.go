// Package crypt implements the platform-specific key handling and payload
// decryption needed to read Chromium's saved passwords/cookies and Firefox's
// NSS-protected logins.
package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Chromium payload encryption modes.
const (
	ModeCBC = iota // v10/v11, AES-CBC, used on Linux and macOS
	ModeGCM        // v10/v11, AES-256-GCM, used on Windows
)

var (
	// ErrAppBound is returned for Chrome 127+ "v20" payloads, which are
	// encrypted with a key bound to the application and cannot be decrypted
	// from a normal user session.
	ErrAppBound = errors.New("payload uses app-bound encryption (v20) and cannot be decrypted without Chrome's elevation service")
)

// ChromiumOptions controls how the Chromium master key is obtained.
type ChromiumOptions struct {
	// App is the keyring/keychain application identifier, e.g. "chrome".
	App string
	// LocalStatePath points at the browser's Local State file (Windows only).
	LocalStatePath string
	// KeyringPassword overrides automatic keyring lookup.
	KeyringPassword string
	// ForcePeanuts forces the legacy Linux fallback password.
	ForcePeanuts bool
}

// ChromiumDecryptor decrypts v10/v11 payloads for one Chromium installation.
type ChromiumDecryptor struct {
	key     []byte
	mode    int
	source  string
	warning string
}

// NewChromiumDecryptorWithKey builds a decryptor from an explicit key. It is
// mainly useful for tests and for callers that already know the key.
func NewChromiumDecryptorWithKey(key []byte, mode int) *ChromiumDecryptor {
	return &ChromiumDecryptor{key: key, mode: mode, source: "explicit key"}
}

// NewChromiumDecryptor obtains the master key using the platform key store.
func NewChromiumDecryptor(opts ChromiumOptions) (*ChromiumDecryptor, error) {
	key, mode, source, warning, err := platformChromiumKey(opts)
	if err != nil {
		return nil, err
	}
	return &ChromiumDecryptor{key: key, mode: mode, source: source, warning: warning}, nil
}

// Source describes where the key came from.
func (d *ChromiumDecryptor) Source() string { return d.source }

// Warning returns a non-fatal note about key retrieval, if any.
func (d *ChromiumDecryptor) Warning() string { return d.warning }

// Decrypt returns the cleartext for a Chromium encrypted value.
func (d *ChromiumDecryptor) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	if bytes.HasPrefix(blob, []byte("v20")) {
		return nil, ErrAppBound
	}
	if bytes.HasPrefix(blob, []byte("v10")) || bytes.HasPrefix(blob, []byte("v11")) {
		payload := blob[3:]
		switch d.mode {
		case ModeCBC:
			return decryptCBC(d.key, payload)
		case ModeGCM:
			return decryptGCM(d.key, payload)
		default:
			return nil, fmt.Errorf("unknown decryption mode %d", d.mode)
		}
	}

	// Pre-Chrome 80 Windows values are raw DPAPI blobs.
	if out, handled, err := legacyDecrypt(blob); handled {
		return out, err
	}
	return nil, fmt.Errorf("unknown encryption prefix %x", firstBytes(blob, 4))
}

func deriveLinuxKey(password string) []byte {
	return pbkdf2.Key([]byte(password), []byte("saltysalt"), 1, 16, sha1.New)
}

func deriveDarwinKey(password string) []byte {
	return pbkdf2.Key([]byte(password), []byte("saltysalt"), 1003, 16, sha1.New)
}

func decryptCBC(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid CBC payload length %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := bytes.Repeat([]byte{' '}, aes.BlockSize)
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return pkcs7Unpad(out, aes.BlockSize)
}

func decryptGCM(key, data []byte) ([]byte, error) {
	if len(data) < 12+16 {
		return nil, fmt.Errorf("invalid GCM payload length %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := data[:12]
	return gcm.Open(nil, nonce, data[12:], nil)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
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

func firstBytes(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}
