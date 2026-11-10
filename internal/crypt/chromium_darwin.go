//go:build darwin

package crypt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func platformChromiumKey(opts ChromiumOptions) ([]byte, int, string, string, error) {
	if opts.KeyringPassword != "" {
		return deriveDarwinKey(opts.KeyringPassword), ModeCBC, "password supplied on the command line", "", nil
	}
	apps := opts.KeychainApps
	if len(apps) == 0 {
		apps = []string{opts.App}
	}
	var lastErr error
	for _, app := range apps {
		if app == "" {
			continue
		}
		pass, err := keychainPassword(app)
		if err == nil && pass != "" {
			return deriveDarwinKey(pass), ModeCBC, "macOS Keychain (" + app + ")", "", nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("keychain item not found")
	}
	return nil, ModeCBC, "", "", fmt.Errorf("read macOS Keychain entry for %s: %w", strings.Join(apps, ", "), lastErr)
}

// keychainPassword reads the "<App> Safe Storage" item from the login
// keychain. The `security` tool ships with macOS, so no cgo is required.
func keychainPassword(app string) (string, error) {
	service := app + " Safe Storage"
	attempts := [][]string{
		{"find-generic-password", "-w", "-s", service, "-a", app},
		{"find-generic-password", "-w", "-s", service},
	}
	var lastErr error
	for _, args := range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, "security", args...).Output()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		value := strings.TrimRight(string(out), "\r\n")
		if value != "" {
			return value, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("keychain item not found")
	}
	return "", lastErr
}

func legacyDecrypt([]byte) ([]byte, bool, error) { return nil, false, nil }
