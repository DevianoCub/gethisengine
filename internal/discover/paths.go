package discover

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Spec describes one browser (or browser flavour) and where its data lives.
type Spec struct {
	Family          string
	Key             string
	Name            string
	LinuxKeyringApp string
	DarwinKeychain  string

	// Base directories. For Chromium these are the "User Data" directories
	// that contain Local State and the profile subdirectories. For Firefox
	// these are the directories that contain profiles.ini.
	Linux   []string
	Darwin  []string
	Windows []string
}

// Specs returns every known browser, independent of the current OS.
func Specs() []Spec {
	return []Spec{
		// ---------------------------------------------------------------- Chromium
		{
			Family: FamilyChromium, Key: "chrome", Name: "Google Chrome",
			LinuxKeyringApp: "chrome", DarwinKeychain: "Chrome",
			Linux: []string{
				"{config}/google-chrome",
				"{home}/.var/app/com.google.Chrome/config/google-chrome",
			},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome"},
			Windows: []string{"{local}/Google/Chrome/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-beta", Name: "Google Chrome Beta",
			LinuxKeyringApp: "chrome", DarwinKeychain: "Chrome",
			Linux:   []string{"{config}/google-chrome-beta"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Beta"},
			Windows: []string{"{local}/Google/Chrome Beta/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-dev", Name: "Google Chrome Dev",
			LinuxKeyringApp: "chrome", DarwinKeychain: "Chrome",
			Linux:   []string{"{config}/google-chrome-unstable"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Dev"},
			Windows: []string{"{local}/Google/Chrome Dev/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-canary", Name: "Google Chrome Canary",
			LinuxKeyringApp: "chrome", DarwinKeychain: "Chrome",
			Linux:   []string{"{config}/google-chrome-canary"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Canary"},
			Windows: []string{"{local}/Google/Chrome SxS/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chromium", Name: "Chromium",
			LinuxKeyringApp: "chromium", DarwinKeychain: "Chromium",
			Linux: []string{
				"{config}/chromium",
				"{home}/snap/chromium/common/chromium",
				"{home}/.var/app/org.chromium.Chromium/config/chromium",
			},
			Darwin:  []string{"{home}/Library/Application Support/Chromium"},
			Windows: []string{"{local}/Chromium/User Data"},
		},
		{
			Family: FamilyChromium, Key: "brave", Name: "Brave",
			LinuxKeyringApp: "brave", DarwinKeychain: "Brave",
			Linux: []string{
				"{config}/BraveSoftware/Brave-Browser",
				"{home}/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
			},
			Darwin:  []string{"{home}/Library/Application Support/BraveSoftware/Brave-Browser"},
			Windows: []string{"{local}/BraveSoftware/Brave-Browser/User Data"},
		},
		{
			Family: FamilyChromium, Key: "edge", Name: "Microsoft Edge",
			LinuxKeyringApp: "microsoft-edge", DarwinKeychain: "Microsoft Edge",
			Linux: []string{
				"{config}/microsoft-edge",
				"{home}/.var/app/com.microsoft.Edge/config/microsoft-edge",
			},
			Darwin:  []string{"{home}/Library/Application Support/Microsoft Edge"},
			Windows: []string{"{local}/Microsoft/Edge/User Data"},
		},
		{
			Family: FamilyChromium, Key: "vivaldi", Name: "Vivaldi",
			LinuxKeyringApp: "vivaldi", DarwinKeychain: "Vivaldi",
			Linux: []string{
				"{config}/vivaldi",
				"{home}/.var/app/com.vivaldi.Vivaldi/config/vivaldi",
			},
			Darwin:  []string{"{home}/Library/Application Support/Vivaldi"},
			Windows: []string{"{local}/Vivaldi/User Data"},
		},
		{
			Family: FamilyChromium, Key: "opera", Name: "Opera",
			LinuxKeyringApp: "opera", DarwinKeychain: "Opera",
			Linux: []string{
				"{config}/opera",
				"{home}/.var/app/com.opera.Opera/config/opera",
			},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.Opera"},
			Windows: []string{"{appdata}/Opera Software/Opera Stable"},
		},
		{
			Family: FamilyChromium, Key: "opera-gx", Name: "Opera GX",
			LinuxKeyringApp: "opera", DarwinKeychain: "Opera",
			Linux:   []string{"{config}/opera-gx"},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.OperaGX"},
			Windows: []string{"{appdata}/Opera Software/Opera GX Stable"},
		},
		{
			Family: FamilyChromium, Key: "yandex", Name: "Yandex Browser",
			LinuxKeyringApp: "yandex-browser", DarwinKeychain: "Yandex",
			Linux:   []string{"{config}/yandex-browser"},
			Darwin:  []string{"{home}/Library/Application Support/Yandex/YandexBrowser"},
			Windows: []string{"{local}/Yandex/YandexBrowser/User Data"},
		},
		{
			Family: FamilyChromium, Key: "thorium", Name: "Thorium",
			LinuxKeyringApp: "thorium", DarwinKeychain: "Thorium",
			Linux:   []string{"{config}/thorium"},
			Darwin:  []string{"{home}/Library/Application Support/Thorium"},
			Windows: []string{"{local}/Thorium/User Data"},
		},
		{
			Family: FamilyChromium, Key: "arc", Name: "Arc",
			LinuxKeyringApp: "arc", DarwinKeychain: "Arc",
			Linux:   []string{"{config}/Arc"},
			Darwin:  []string{"{home}/Library/Application Support/Arc"},
			Windows: []string{"{local}/Arc/User Data"},
		},

		// ---------------------------------------------------------------- Firefox
		{
			Family: FamilyFirefox, Key: "firefox", Name: "Firefox",
			Linux: []string{
				"{home}/.mozilla/firefox",
				"{home}/snap/firefox/common/.mozilla/firefox",
				"{home}/.var/app/org.mozilla.firefox/.mozilla/firefox",
				"{home}/.mozilla/icecat",
			},
			Darwin:  []string{"{home}/Library/Application Support/Firefox"},
			Windows: []string{"{appdata}/Mozilla/Firefox"},
		},
		{
			Family: FamilyFirefox, Key: "librewolf", Name: "LibreWolf",
			Linux: []string{
				"{home}/.librewolf",
				"{home}/.var/app/io.gitlab.librewolf-community/.librewolf",
			},
			Darwin:  []string{"{home}/Library/Application Support/LibreWolf"},
			Windows: []string{"{appdata}/LibreWolf"},
		},
		{
			Family: FamilyFirefox, Key: "waterfox", Name: "Waterfox",
			Linux:   []string{"{home}/.waterfox"},
			Darwin:  []string{"{home}/Library/Application Support/Waterfox"},
			Windows: []string{"{appdata}/Waterfox"},
		},
		{
			Family: FamilyFirefox, Key: "floorp", Name: "Floorp",
			Linux: []string{
				"{home}/.floorp",
				"{home}/.var/app/one.ablaze.floorp/.floorp",
			},
			Darwin:  []string{"{home}/Library/Application Support/Floorp"},
			Windows: []string{"{appdata}/Floorp"},
		},
		{
			Family: FamilyFirefox, Key: "zen", Name: "Zen Browser",
			Linux: []string{
				"{home}/.zen",
				"{home}/.var/app/app.zen_browser.zen/.zen",
			},
			Darwin:  []string{"{home}/Library/Application Support/Zen"},
			Windows: []string{"{appdata}/Zen"},
		},
		{
			Family: FamilyFirefox, Key: "palemoon", Name: "Pale Moon",
			Linux:   []string{"{home}/.palemoon"},
			Darwin:  []string{"{home}/Library/Application Support/Pale Moon"},
			Windows: []string{"{appdata}/Moonchild Productions/Pale Moon"},
		},
		{
			Family: FamilyFirefox, Key: "seamonkey", Name: "SeaMonkey",
			Linux:   []string{"{home}/.seamonkey"},
			Darwin:  []string{"{home}/Library/Application Support/SeaMonkey"},
			Windows: []string{"{appdata}/Mozilla/SeaMonkey"},
		},
	}
}

// Family constants duplicated here to keep the discover package free of
// import cycles while still being readable.
const (
	FamilyChromium = "chromium"
	FamilyFirefox  = "firefox"
)

// Lookup returns the spec with the given browser key.
func Lookup(key string) (Spec, bool) {
	for _, spec := range Specs() {
		if spec.Key == key {
			return spec, true
		}
	}
	return Spec{}, false
}

// BasesForOS returns the base directories of a spec for the current OS.
func (s Spec) BasesForOS() []string {
	var raw []string
	switch runtime.GOOS {
	case "darwin":
		raw = s.Darwin
	case "windows":
		raw = s.Windows
	default:
		raw = s.Linux
	}
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, expand(p))
	}
	return out
}

// expand resolves the placeholders used in the path registry.
func expand(path string) string {
	home, _ := os.UserHomeDir()
	config, _ := os.UserConfigDir()

	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		local = config
	}
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		appdata = config
	}
	share := os.Getenv("XDG_DATA_HOME")
	if share == "" && home != "" {
		share = filepath.Join(home, ".local", "share")
	}

	replacer := strings.NewReplacer(
		"{home}", home,
		"{config}", config,
		"{local}", local,
		"{appdata}", appdata,
		"{share}", share,
	)
	return filepath.Clean(replacer.Replace(path))
}
