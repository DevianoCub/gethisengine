package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gethisengine/internal/model"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFindChromiumProfile(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "Local State"), `{"profile":{"info_cache":{"Default":{"name":"Work"},"Profile 1":{"name":"Play"}}}}`)
	writeFile(t, filepath.Join(base, "Default", "Preferences"), `{}`)
	writeFile(t, filepath.Join(base, "Default", "Login Data"), "")
	writeFile(t, filepath.Join(base, "Profile 1", "Preferences"), `{}`)
	writeFile(t, filepath.Join(base, "Guest Profile", "Preferences"), `{}`)

	profiles, warnings := Find([]string{base})
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}

	var found []model.Profile
	for _, profile := range profiles {
		if profile.Family == FamilyChromium && profile.BrowserKey == "custom" {
			found = append(found, profile)
		}
	}
	if len(found) != 2 {
		t.Fatalf("got %d Chromium profiles, want 2: %+v", len(found), found)
	}

	byName := map[string]model.Profile{}
	for _, profile := range found {
		byName[profile.Name] = profile
	}
	if _, ok := byName["Work"]; !ok {
		t.Fatalf("missing Work profile: %+v", found)
	}
	if !byName["Work"].IsDefault {
		t.Fatal("Default directory should be marked as default")
	}
	if _, ok := byName["Play"]; !ok {
		t.Fatalf("missing Play profile: %+v", found)
	}
	if _, ok := byName["Guest Profile"]; ok {
		t.Fatal("guest profile must be skipped")
	}
}

func TestFindFirefoxProfiles(t *testing.T) {
	base := t.TempDir()
	relative := filepath.Join(base, "abc.default")
	absolute := t.TempDir()
	writeFile(t, filepath.Join(relative, "prefs.js"), "")
	writeFile(t, filepath.Join(absolute, "prefs.js"), "")

	writeFile(t, filepath.Join(base, "profiles.ini"), `[Profile0]
Name=Personal
IsRelative=1
Path=abc.default
Default=1

[Profile1]
Name=Work
IsRelative=0
Path=`+absolute+`
`)

	profiles, warnings := Find([]string{base})
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}

	var found []model.Profile
	for _, profile := range profiles {
		if profile.Family == FamilyFirefox && profile.BrowserKey == "custom" {
			found = append(found, profile)
		}
	}
	if len(found) != 2 {
		t.Fatalf("got %d Firefox profiles, want 2: %+v", len(found), found)
	}
	for _, profile := range found {
		if profile.Name == "Personal" && !profile.IsDefault {
			t.Fatal("Personal should be the default profile")
		}
	}
}

func TestCustomRootRejectsUnknownDirectory(t *testing.T) {
	dir := t.TempDir()
	profiles, warnings := Find([]string{dir})
	for _, profile := range profiles {
		if profile.Path == dir {
			t.Fatalf("unexpected profile for unrecognised root: %+v", profile)
		}
	}
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning, "does not look like a browser profile") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning for an unrecognised directory, got %v", warnings)
	}
}
