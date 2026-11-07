//go:build linux

package crypt

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

func platformChromiumKey(opts ChromiumOptions) ([]byte, int, string, string, error) {
	if opts.ForcePeanuts {
		return deriveLinuxKey("peanuts"), ModeCBC, `"peanuts" (forced by --peanuts)`,
			`keyring lookup disabled; using the legacy "peanuts" password`, nil
	}
	if opts.KeyringPassword != "" {
		return deriveLinuxKey(opts.KeyringPassword), ModeCBC, "password supplied on the command line", "", nil
	}
	if pass, ok := secretServicePassword(opts.App); ok {
		return deriveLinuxKey(pass), ModeCBC, "Secret Service (" + opts.App + ")", "", nil
	}
	if pass, ok := secretToolPassword(opts.App); ok {
		return deriveLinuxKey(pass), ModeCBC, "secret-tool (" + opts.App + ")", "", nil
	}
	return deriveLinuxKey("peanuts"), ModeCBC, `"peanuts" (keyring item not found)`,
		`no Secret Service item for "` + opts.App + `"; fell back to the legacy "peanuts" password`, nil
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
// Keyring, KWallet's Secret Service bridge, KeePassXC, ...).
func secretServicePassword(app string) (string, bool) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return "", false
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
		return "", false
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

	for _, attrs := range attributes {
		var unlocked, locked []dbus.ObjectPath
		if err := service.CallWithContext(ctx, "org.freedesktop.Secret.Service.SearchItems", 0, attrs).
			Store(&unlocked, &locked); err != nil {
			continue
		}
		if len(unlocked) == 0 {
			continue
		}
		item := conn.Object(secretServiceName, unlocked[0])
		var secret dbusSecret
		if err := item.CallWithContext(ctx, "org.freedesktop.Secret.Item.GetSecret", 0, session).
			Store(&secret); err != nil {
			continue
		}
		if len(secret.Value) == 0 {
			continue
		}
		return string(secret.Value), true
	}
	return "", false
}

// secretToolPassword is a fallback for systems where the D-Bus API is
// restricted but libsecret's CLI helper is available.
func secretToolPassword(app string) (string, bool) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "secret-tool", "lookup", "application", app).Output()
	if err != nil {
		return "", false
	}
	value := strings.TrimRight(string(out), "\r\n")
	if value == "" {
		return "", false
	}
	return value, true
}

func legacyDecrypt([]byte) ([]byte, bool, error) { return nil, false, nil }
