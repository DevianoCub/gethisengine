//go:build linux

package crypt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

var (
	errKeyringLocked      = errors.New("keyring item is locked; unlock it or pass --keyring-password")
	errKeyringUnavailable = errors.New("Secret Service is unavailable")
	errKeyringNotFound    = errors.New("keyring item not found")
)

func platformChromiumKey(opts ChromiumOptions) ([]byte, int, string, string, error) {
	if opts.ForcePeanuts {
		return deriveLinuxKey("peanuts"), ModeCBC, `"peanuts" (forced by --peanuts)`,
			`keyring lookup disabled; using the legacy "peanuts" password`, nil
	}
	if opts.KeyringPassword != "" {
		return deriveLinuxKey(opts.KeyringPassword), ModeCBC, "password supplied on the command line", "", nil
	}

	apps := opts.Apps
	if len(apps) == 0 {
		apps = []string{opts.App}
	}
	var lockedErr error
	for _, app := range apps {
		if app == "" {
			continue
		}
		pass, err := secretServicePassword(app)
		if err == nil && pass != "" {
			return deriveLinuxKey(pass), ModeCBC, "Secret Service (" + app + ")", "", nil
		}
		if errors.Is(err, errKeyringLocked) {
			// Do not try the same item through secret-tool: it would also
			// block or fail. Remember it and report a useful error later.
			lockedErr = err
			continue
		}
		pass, err = secretToolPassword(app)
		if err == nil && pass != "" {
			return deriveLinuxKey(pass), ModeCBC, "secret-tool (" + app + ")", "", nil
		}
	}
	if lockedErr != nil {
		return nil, ModeCBC, "", "", lockedErr
	}
	return deriveLinuxKey("peanuts"), ModeCBC, `"peanuts" (keyring item not found)`,
		`no Secret Service item for ` + quoteList(apps) + `; fell back to the legacy "peanuts" password`, nil
}

func quoteList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, `"`+value+`"`)
	}
	return strings.Join(quoted, ", ")
}

const (
	secretServiceName = "org.freedesktop.secrets"
	secretServicePath = dbus.ObjectPath("/org/freedesktop/secrets")
)

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// secretServicePassword queries the freedesktop Secret Service (GNOME
// Keyring, KWallet's Secret Service bridge, KeePassXC, ...). The error
// distinguishes an absent item from a locked collection so the caller does
// not fall back to the legacy "peanuts" password while a real item exists.
func secretServicePassword(app string) (string, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errKeyringUnavailable, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	service := conn.Object(secretServiceName, secretServicePath)
	var (
		output  dbus.Variant
		session dbus.ObjectPath
	)
	if err := service.CallWithContext(ctx, "org.freedesktop.Secret.Service.OpenSession", 0,
		"plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", fmt.Errorf("%w: %v", errKeyringUnavailable, err)
	}
	defer func() {
		_ = conn.Object(secretServiceName, session).
			CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0)
	}()

	attributes := []map[string]string{
		{"application": app},
		{"xdg:schema": "chrome_libsecret_os_crypt_password_v2", "application": app},
		{"xdg:schema": "chrome_libsecret_os_crypt_password_v1", "application": app},
	}

	foundLocked := false
	lastErr := error(nil)
	for _, attrs := range attributes {
		var unlocked, locked []dbus.ObjectPath
		if err := service.CallWithContext(ctx, "org.freedesktop.Secret.Service.SearchItems", 0, attrs).
			Store(&unlocked, &locked); err != nil {
			lastErr = err
			continue
		}
		if len(unlocked) == 0 {
			if len(locked) > 0 {
				foundLocked = true
			}
			continue
		}
		item := conn.Object(secretServiceName, unlocked[0])
		var secret dbusSecret
		if err := item.CallWithContext(ctx, "org.freedesktop.Secret.Item.GetSecret", 0, session).
			Store(&secret); err != nil {
			lastErr = err
			continue
		}
		if len(secret.Value) == 0 {
			continue
		}
		return string(secret.Value), nil
	}
	if foundLocked {
		return "", errKeyringLocked
	}
	if lastErr != nil {
		return "", fmt.Errorf("%w: %v", errKeyringNotFound, lastErr)
	}
	return "", errKeyringNotFound
}

// secretToolPassword is a fallback for systems where the D-Bus API is
// restricted but libsecret's CLI helper is available.
func secretToolPassword(app string) (string, error) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return "", errKeyringNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "secret-tool", "lookup", "application", app).Output()
	if err != nil {
		return "", errKeyringNotFound
	}
	value := strings.TrimRight(string(out), "\r\n")
	if value == "" {
		return "", errKeyringNotFound
	}
	return value, nil
}

func legacyDecrypt([]byte) ([]byte, bool, error) { return nil, false, nil }
