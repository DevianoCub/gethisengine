package discover

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"gethisengine/internal/model"
)

// Find scans every known browser for the current OS and returns the profiles
// it could find. Unreadable or surprising locations produce warnings instead
// of aborting the scan.
func Find(extraRoots []string) ([]model.Profile, []string) {
	var profiles []model.Profile
	var warnings []string
	seen := make(map[string]bool)

	add := func(p model.Profile) {
		key := p.Family + "\x00" + dedupePath(p.Path)
		if seen[key] {
			return
		}
		seen[key] = true
		profiles = append(profiles, p)
	}

	for _, spec := range Specs() {
		for _, base := range spec.MatchBasesForOS() {
			info, err := os.Stat(base)
			if err != nil || !info.IsDir() {
				continue
			}
			found, warns := profilesInBase(spec, base)
			warnings = append(warnings, warns...)
			for _, p := range found {
				add(p)
			}
		}
	}

	for _, root := range extraRoots {
		if root == "" {
			continue
		}
		root = expand(root)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			warnings = append(warnings, fmt.Sprintf("custom root %q is not a directory", root))
			continue
		}
		found, warns := profilesInCustomRoot(root)
		warnings = append(warnings, warns...)
		for _, p := range found {
			add(p)
		}
	}

	sort.SliceStable(profiles, func(i, j int) bool {
		a, b := profiles[i], profiles[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Path < b.Path
	})
	return profiles, warnings
}

// profilesInCustomRoot recognises a handful of layouts: a Chromium "User
// Data" directory, a single Chromium profile, a Firefox profile directory or
// a Firefox base directory with profiles.ini.
func profilesInCustomRoot(root string) ([]model.Profile, []string) {
	customChromium := Spec{Family: FamilyChromium, Key: "custom", Name: "Chromium (custom)"}
	customFirefox := Spec{Family: FamilyFirefox, Key: "custom", Name: "Firefox (custom)"}

	switch {
	case fileExists(filepath.Join(root, "profiles.ini")):
		return firefoxProfiles(customFirefox, root), nil
	case fileExists(filepath.Join(root, "Local State")) || fileExists(filepath.Join(root, "User Data")):
		return chromiumProfiles(customChromium, root), nil
	case isFirefoxProfileDir(root):
		return firefoxProfiles(customFirefox, root), nil
	case isChromiumProfileDir(root):
		return chromiumProfiles(customChromium, root), nil
	case hasChildDir(root, isFirefoxProfileDir):
		return firefoxProfiles(customFirefox, root), nil
	case hasChildDir(root, isChromiumProfileDir):
		return chromiumProfiles(customChromium, root), nil
	default:
		return nil, []string{fmt.Sprintf("custom root %q does not look like a browser profile", root)}
	}
}

func hasChildDir(root string, predicate func(string) bool) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && predicate(filepath.Join(root, entry.Name())) {
			return true
		}
	}
	return false
}

func dedupePath(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(cleaned)
	}
	return cleaned
}

func profilesInBase(spec Spec, base string) ([]model.Profile, []string) {
	switch spec.Family {
	case FamilyChromium:
		return chromiumProfiles(spec, base), nil
	case FamilyFirefox:
		return firefoxProfiles(spec, base), nil
	default:
		return nil, []string{fmt.Sprintf("unknown browser family %q for %s", spec.Family, spec.Name)}
	}
}

// ------------------------------------------------------------------ Chromium

type localState struct {
	Profile struct {
		InfoCache map[string]struct {
			Name string `json:"name"`
		} `json:"info_cache"`
	} `json:"profile"`
}

func chromiumProfiles(spec Spec, base string) []model.Profile {
	names := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(base, "Local State")); err == nil {
		var ls localState
		if json.Unmarshal(data, &ls) == nil {
			for dir, info := range ls.Profile.InfoCache {
				if info.Name != "" {
					names[dir] = info.Name
				}
			}
		}
	}

	var out []model.Profile
	makeProfile := func(dir, name string, isDefault bool) model.Profile {
		return model.Profile{
			Family:     spec.Family,
			BrowserKey: spec.Key,
			Browser:    spec.Name,
			Aliases:    append([]string(nil), spec.Aliases...),
			Name:       name,
			Path:       dir,
			IsDefault:  isDefault,
			Artifacts:  chromiumArtifacts(dir),
		}
	}

	// The caller may have pointed us directly at a profile directory.
	if isChromiumProfileDir(base) {
		name := names[filepath.Base(base)]
		if name == "" {
			name = filepath.Base(base)
		}
		return []model.Profile{makeProfile(base, name, filepath.Base(base) == "Default")}
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		if skipChromiumDir(dirName) {
			continue
		}
		dir := filepath.Join(base, dirName)
		if !isChromiumProfileDir(dir) {
			continue
		}
		name := names[dirName]
		if name == "" {
			name = dirName
		}
		out = append(out, makeProfile(dir, name, dirName == "Default"))
	}
	return out
}

func skipChromiumDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "Guest Profile", "System Profile", "Snapshot", "Crashpad":
		return true
	}
	return false
}

func isChromiumProfileDir(dir string) bool {
	for _, marker := range []string{"Preferences", "Login Data", "History", "Web Data", "Cookies"} {
		if fileExists(filepath.Join(dir, marker)) {
			return true
		}
	}
	return false
}

func chromiumArtifacts(dir string) map[string]string {
	candidates := map[string]string{
		"logins":      "Login Data",
		"history":     "History",
		"cookies":     "Cookies",
		"bookmarks":   "Bookmarks",
		"web_data":    "Web Data",
		"preferences": "Preferences",
	}
	out := make(map[string]string)
	for key, name := range candidates {
		path := filepath.Join(dir, name)
		if fileExists(path) {
			out[key] = path
		}
	}
	return out
}

// ------------------------------------------------------------------ Firefox

func firefoxProfiles(spec Spec, base string) []model.Profile {
	var out []model.Profile

	iniPath := filepath.Join(base, "profiles.ini")
	if fileExists(iniPath) {
		sections, order, err := parseINI(iniPath)
		if err == nil {
			defaults := make(map[string]bool)
			for _, section := range order {
				if !strings.HasPrefix(strings.ToLower(section), "install") {
					continue
				}
				if def := sections[section]["default"]; def != "" {
					defaults[filepath.Clean(def)] = true
				}
			}

			for _, section := range order {
				if !strings.HasPrefix(strings.ToLower(section), "profile") {
					continue
				}
				values := sections[section]
				rel := values["path"]
				if rel == "" {
					continue
				}
				dir := rel
				if filepath.IsAbs(rel) || values["isrelative"] == "0" {
					dir = filepath.Clean(rel)
				} else {
					dir = filepath.Join(base, rel)
				}
				if !isFirefoxProfileDir(dir) {
					continue
				}
				name := values["name"]
				if name == "" {
					name = filepath.Base(dir)
				}
				isDefault := values["default"] == "1" || defaults[filepath.Clean(dir)]
				out = append(out, newFirefoxProfile(spec, dir, name, isDefault))
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// No usable profiles.ini: fall back to walking the directory.
	if isFirefoxProfileDir(base) {
		return []model.Profile{newFirefoxProfile(spec, base, filepath.Base(base), false)}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dir := filepath.Join(base, entry.Name())
		if !isFirefoxProfileDir(dir) {
			continue
		}
		out = append(out, newFirefoxProfile(spec, dir, entry.Name(), false))
	}
	return out
}

func newFirefoxProfile(spec Spec, dir, name string, isDefault bool) model.Profile {
	return model.Profile{
		Family:     spec.Family,
		BrowserKey: spec.Key,
		Browser:    spec.Name,
		Aliases:    append([]string(nil), spec.Aliases...),
		Name:       name,
		Path:       dir,
		IsDefault:  isDefault,
		Artifacts:  firefoxArtifacts(dir),
	}
}

func isFirefoxProfileDir(dir string) bool {
	for _, marker := range []string{"prefs.js", "places.sqlite", "logins.json", "logins.db", "key4.db", "cookies.sqlite"} {
		if fileExists(filepath.Join(dir, marker)) {
			return true
		}
	}
	return false
}

func firefoxArtifacts(dir string) map[string]string {
	candidates := map[string]string{
		"logins":      "logins.json",
		"logins_db":   "logins.db",
		"key4":        "key4.db",
		"key3":        "key3.db",
		"signons":     "signons.sqlite",
		"places":      "places.sqlite",
		"cookies":     "cookies.sqlite",
		"formhistory": "formhistory.sqlite",
		"prefs":       "prefs.js",
	}
	out := make(map[string]string)
	for key, name := range candidates {
		path := filepath.Join(dir, name)
		if fileExists(path) {
			out[key] = path
		}
	}
	return out
}

// ------------------------------------------------------------------ helpers

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseINI(path string) (map[string]map[string]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	sections := make(map[string]map[string]string)
	var order []string
	section := ""

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := sections[section]; !ok {
				sections[section] = make(map[string]string)
				order = append(order, section)
			}
			continue
		}
		if section == "" {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			sections[section][key] = value
		}
	}
	return sections, order, scanner.Err()
}
