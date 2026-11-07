//go:build windows

package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformChromiumKey(opts ChromiumOptions) ([]byte, int, string, string, error) {
	if opts.LocalStatePath == "" {
		return nil, ModeGCM, "", "", errors.New("Local State path is required on Windows")
	}
	data, err := os.ReadFile(opts.LocalStatePath)
	if err != nil {
		return nil, ModeGCM, "", "", fmt.Errorf("read Local State: %w", err)
	}
	var state struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
			AuditEnabled bool   `json:"audit_enabled"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, ModeGCM, "", "", fmt.Errorf("parse Local State: %w", err)
	}
	if state.OSCrypt.EncryptedKey == "" {
		return nil, ModeGCM, "", "", errors.New("Local State does not contain os_crypt.encrypted_key")
	}

	raw, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, ModeGCM, "", "", fmt.Errorf("decode encrypted_key: %w", err)
	}
	if !bytes.HasPrefix(raw, []byte("DPAPI")) {
		return nil, ModeGCM, "", "", errors.New("unexpected encrypted_key format (missing DPAPI prefix)")
	}
	key, err := dpapiUnprotect(raw[len("DPAPI"):])
	if err != nil {
		return nil, ModeGCM, "", "", fmt.Errorf("DPAPI unprotect: %w", err)
	}
	if len(key) != 32 {
		return nil, ModeGCM, "", "", fmt.Errorf("unexpected master key length %d", len(key))
	}
	return key, ModeGCM, "Windows DPAPI", "", nil
}

func legacyDecrypt(blob []byte) ([]byte, bool, error) {
	if len(blob) >= 4 && blob[0] == 1 && blob[1] == 0 && blob[2] == 0 && blob[3] == 0 {
		out, err := dpapiUnprotect(blob)
		return out, true, err
	}
	return nil, false, nil
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var procCryptUnprotectData = windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptUnprotectData")

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DPAPI blob")
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob

	r1, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description
		0, // optional entropy
		0, // reserved
		0, // prompt
		0, // flags
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		if callErr != nil {
			return nil, callErr
		}
		return nil, errors.New("CryptUnprotectData failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))

	if out.pbData == nil || out.cbData == 0 {
		return nil, errors.New("CryptUnprotectData returned an empty blob")
	}
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}
