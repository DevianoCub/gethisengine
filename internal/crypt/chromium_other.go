//go:build !linux && !darwin && !windows

package crypt

import (
	"fmt"
	"runtime"
)

func platformChromiumKey(ChromiumOptions) ([]byte, int, string, string, error) {
	return nil, ModeCBC, "", "", fmt.Errorf("Chromium key retrieval is not implemented on %s", runtime.GOOS)
}

func legacyDecrypt([]byte) ([]byte, bool, error) { return nil, false, nil }
