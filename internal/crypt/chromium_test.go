package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func encryptCBC(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	iv := bytes.Repeat([]byte{' '}, aes.BlockSize)
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

func TestDecryptCBC(t *testing.T) {
	key := deriveLinuxKey("correct horse battery staple")
	plaintext := []byte("hunter2")
	blob := append([]byte("v10"), encryptCBC(t, key, pkcs7Pad(plaintext, aes.BlockSize))...)

	dec := NewChromiumDecryptorWithKey(key, ModeCBC)
	got, err := dec.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestDecryptGCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x01}, gcm.NonceSize())
	plaintext := []byte("secret cookie value")
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	blob := append([]byte("v10"), nonce...)
	blob = append(blob, sealed...)

	dec := NewChromiumDecryptorWithKey(key, ModeGCM)
	got, err := dec.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestDecryptAppBound(t *testing.T) {
	dec := NewChromiumDecryptorWithKey(make([]byte, 32), ModeGCM)
	_, err := dec.Decrypt(append([]byte("v20"), make([]byte, 64)...))
	if !errors.Is(err, ErrAppBound) {
		t.Fatalf("got %v, want ErrAppBound", err)
	}
}

func TestDecryptUnknownPrefix(t *testing.T) {
	dec := NewChromiumDecryptorWithKey(make([]byte, 16), ModeCBC)
	if _, err := dec.Decrypt([]byte("nope")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDeriveKeysAreStable(t *testing.T) {
	linux1 := deriveLinuxKey("pw")
	linux2 := deriveLinuxKey("pw")
	if !bytes.Equal(linux1, linux2) || len(linux1) != 16 {
		t.Fatalf("unexpected Linux key derivation: %x", linux1)
	}
	darwin := deriveDarwinKey("pw")
	if len(darwin) != 16 {
		t.Fatalf("unexpected macOS key length: %d", len(darwin))
	}
	if bytes.Equal(linux1, darwin) {
		t.Fatal("Linux and macOS derivations should differ (1 vs 1003 iterations)")
	}
}
