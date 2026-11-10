package discover

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Spec describes one browser (or browser flavour) and where its data lives.
type Spec struct {
	Family string
	Key    string
	Name   string

	// Key-store identifiers. The first entry is the canonical name; the
	// fallbacks cover forks that reuse the upstream Chromium application id.
	LinuxKeyringApp  string
	LinuxKeyringApps []string
	DarwinKeychain   string
	DarwinKeychains  []string
	Aliases          []string

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
			LinuxKeyringApp: "chrome", LinuxKeyringApps: []string{"chrome"},
			DarwinKeychain: "Chrome", DarwinKeychains: []string{"Chrome"},
			Linux: []string{
				"{config}/google-chrome",
				"{home}/.var/app/com.google.Chrome/config/google-chrome",
			},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome"},
			Windows: []string{"{local}/Google/Chrome/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-beta", Name: "Google Chrome Beta",
			LinuxKeyringApp: "chrome", LinuxKeyringApps: []string{"chrome"},
			DarwinKeychain: "Chrome", DarwinKeychains: []string{"Chrome"},
			Linux:   []string{"{config}/google-chrome-beta"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Beta"},
			Windows: []string{"{local}/Google/Chrome Beta/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-dev", Name: "Google Chrome Dev",
			LinuxKeyringApp: "chrome", LinuxKeyringApps: []string{"chrome"},
			DarwinKeychain: "Chrome", DarwinKeychains: []string{"Chrome"},
			Linux:   []string{"{config}/google-chrome-unstable"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Dev"},
			Windows: []string{"{local}/Google/Chrome Dev/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chrome-canary", Name: "Google Chrome Canary",
			LinuxKeyringApp: "chrome", LinuxKeyringApps: []string{"chrome"},
			DarwinKeychain: "Chrome", DarwinKeychains: []string{"Chrome"},
			Linux:   []string{"{config}/google-chrome-canary"},
			Darwin:  []string{"{home}/Library/Application Support/Google/Chrome Canary"},
			Windows: []string{"{local}/Google/Chrome SxS/User Data"},
		},
		{
			Family: FamilyChromium, Key: "chromium", Name: "Chromium",
			LinuxKeyringApp: "chromium", LinuxKeyringApps: []string{"chromium", "chrome"},
			DarwinKeychain: "Chromium", DarwinKeychains: []string{"Chromium", "Chrome"},
			Aliases: []string{"ungoogled-chromium", "ungoogled", "ug"},
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
			LinuxKeyringApp: "brave", LinuxKeyringApps: []string{"brave", "chrome"},
			DarwinKeychain: "Brave", DarwinKeychains: []string{"Brave", "Chrome"},
			Linux: []string{
				"{config}/BraveSoftware/Brave-Browser",
				"{home}/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
			},
			Darwin:  []string{"{home}/Library/Application Support/BraveSoftware/Brave-Browser"},
			Windows: []string{"{local}/BraveSoftware/Brave-Browser/User Data"},
		},
		{
			Family: FamilyChromium, Key: "brave-beta", Name: "Brave Beta",
			LinuxKeyringApp: "brave", LinuxKeyringApps: []string{"brave", "chrome"},
			DarwinKeychain: "Brave", DarwinKeychains: []string{"Brave", "Chrome"},
			Linux:   []string{"{config}/BraveSoftware/Brave-Browser-Beta"},
			Darwin:  []string{"{home}/Library/Application Support/BraveSoftware/Brave-Browser-Beta"},
			Windows: []string{"{local}/BraveSoftware/Brave-Browser-Beta/User Data"},
		},
		{
			Family: FamilyChromium, Key: "brave-dev", Name: "Brave Dev",
			LinuxKeyringApp: "brave", LinuxKeyringApps: []string{"brave", "chrome"},
			DarwinKeychain: "Brave", DarwinKeychains: []string{"Brave", "Chrome"},
			Linux:   []string{"{config}/BraveSoftware/Brave-Browser-Dev"},
			Darwin:  []string{"{home}/Library/Application Support/BraveSoftware/Brave-Browser-Dev"},
			Windows: []string{"{local}/BraveSoftware/Brave-Browser-Dev/User Data"},
		},
		{
			Family: FamilyChromium, Key: "brave-nightly", Name: "Brave Nightly",
			LinuxKeyringApp: "brave", LinuxKeyringApps: []string{"brave", "chrome"},
			DarwinKeychain: "Brave", DarwinKeychains: []string{"Brave", "Chrome"},
			Linux:   []string{"{config}/BraveSoftware/Brave-Browser-Nightly"},
			Darwin:  []string{"{home}/Library/Application Support/BraveSoftware/Brave-Browser-Nightly"},
			Windows: []string{"{local}/BraveSoftware/Brave-Browser-Nightly/User Data"},
		},
		{
			Family: FamilyChromium, Key: "edge", Name: "Microsoft Edge",
			LinuxKeyringApp: "microsoft-edge", LinuxKeyringApps: []string{"microsoft-edge", "chrome"},
			DarwinKeychain: "Microsoft Edge", DarwinKeychains: []string{"Microsoft Edge", "Chrome"},
			Linux: []string{
				"{config}/microsoft-edge",
				"{home}/.var/app/com.microsoft.Edge/config/microsoft-edge",
			},
			Darwin:  []string{"{home}/Library/Application Support/Microsoft Edge"},
			Windows: []string{"{local}/Microsoft/Edge/User Data"},
		},
		{
			Family: FamilyChromium, Key: "edge-beta", Name: "Microsoft Edge Beta",
			LinuxKeyringApp: "microsoft-edge", LinuxKeyringApps: []string{"microsoft-edge", "chrome"},
			DarwinKeychain: "Microsoft Edge Beta", DarwinKeychains: []string{"Microsoft Edge Beta", "Chrome"},
			Linux:   []string{"{config}/microsoft-edge-beta"},
			Darwin:  []string{"{home}/Library/Application Support/Microsoft Edge Beta"},
			Windows: []string{"{local}/Microsoft/Edge Beta/User Data"},
		},
		{
			Family: FamilyChromium, Key: "edge-dev", Name: "Microsoft Edge Dev",
			LinuxKeyringApp: "microsoft-edge", LinuxKeyringApps: []string{"microsoft-edge", "chrome"},
			DarwinKeychain: "Microsoft Edge Dev", DarwinKeychains: []string{"Microsoft Edge Dev", "Chrome"},
			Linux:   []string{"{config}/microsoft-edge-dev"},
			Darwin:  []string{"{home}/Library/Application Support/Microsoft Edge Dev"},
			Windows: []string{"{local}/Microsoft/Edge Dev/User Data"},
		},
		{
			Family: FamilyChromium, Key: "edge-canary", Name: "Microsoft Edge Canary",
			LinuxKeyringApp: "microsoft-edge", LinuxKeyringApps: []string{"microsoft-edge", "chrome"},
			DarwinKeychain: "Microsoft Edge Canary", DarwinKeychains: []string{"Microsoft Edge Canary", "Chrome"},
			Linux:   []string{"{config}/microsoft-edge-canary"},
			Darwin:  []string{"{home}/Library/Application Support/Microsoft Edge Canary"},
			Windows: []string{"{local}/Microsoft/Edge SxS/User Data"},
		},
		{
			Family: FamilyChromium, Key: "vivaldi", Name: "Vivaldi",
			LinuxKeyringApp: "vivaldi", LinuxKeyringApps: []string{"vivaldi", "chrome"},
			DarwinKeychain: "Vivaldi", DarwinKeychains: []string{"Vivaldi", "Chrome"},
			Linux: []string{
				"{config}/vivaldi",
				"{home}/snap/vivaldi/current/.config/vivaldi",
				"{home}/.var/app/com.vivaldi.Vivaldi/config/vivaldi",
			},
			Darwin:  []string{"{home}/Library/Application Support/Vivaldi"},
			Windows: []string{"{local}/Vivaldi/User Data"},
		},
		{
			Family: FamilyChromium, Key: "vivaldi-snapshot", Name: "Vivaldi Snapshot",
			LinuxKeyringApp: "vivaldi", LinuxKeyringApps: []string{"vivaldi", "chrome"},
			DarwinKeychain: "Vivaldi", DarwinKeychains: []string{"Vivaldi", "Chrome"},
			Linux:   []string{"{config}/vivaldi-snapshot"},
			Darwin:  []string{"{home}/Library/Application Support/Vivaldi Snapshot"},
			Windows: []string{"{local}/Vivaldi Snapshot/User Data"},
		},
		{
			Family: FamilyChromium, Key: "opera", Name: "Opera",
			LinuxKeyringApp: "opera", LinuxKeyringApps: []string{"opera", "chrome"},
			DarwinKeychain: "Opera", DarwinKeychains: []string{"Opera", "Chrome"},
			Linux: []string{
				"{config}/opera",
				"{home}/.var/app/com.opera.Opera/config/opera",
			},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.Opera"},
			Windows: []string{"{appdata}/Opera Software/Opera Stable"},
		},
		{
			Family: FamilyChromium, Key: "opera-beta", Name: "Opera Beta",
			LinuxKeyringApp: "opera", LinuxKeyringApps: []string{"opera", "chrome"},
			DarwinKeychain: "Opera", DarwinKeychains: []string{"Opera", "Chrome"},
			Linux:   []string{"{config}/opera-beta"},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.OperaNext"},
			Windows: []string{"{appdata}/Opera Software/Opera Beta"},
		},
		{
			Family: FamilyChromium, Key: "opera-developer", Name: "Opera Developer",
			LinuxKeyringApp: "opera", LinuxKeyringApps: []string{"opera", "chrome"},
			DarwinKeychain: "Opera", DarwinKeychains: []string{"Opera", "Chrome"},
			Linux:   []string{"{config}/opera-developer"},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.OperaDeveloper"},
			Windows: []string{"{appdata}/Opera Software/Opera Developer"},
		},
		{
			Family: FamilyChromium, Key: "opera-gx", Name: "Opera GX",
			LinuxKeyringApp: "opera", LinuxKeyringApps: []string{"opera", "chrome"},
			DarwinKeychain: "Opera", DarwinKeychains: []string{"Opera", "Chrome"},
			Linux:   []string{"{config}/opera-gx"},
			Darwin:  []string{"{home}/Library/Application Support/com.operasoftware.OperaGX"},
			Windows: []string{"{appdata}/Opera Software/Opera GX Stable"},
		},
		{
			Family: FamilyChromium, Key: "yandex", Name: "Yandex Browser",
			LinuxKeyringApp: "yandex-browser", LinuxKeyringApps: []string{"yandex-browser", "chrome"},
			DarwinKeychain: "Yandex", DarwinKeychains: []string{"Yandex", "Yandex Browser", "Chrome"},
			Linux: []string{
				"{config}/yandex-browser",
				"{home}/.var/app/ru.yandex.Browser/config/yandex-browser",
			},
			Darwin:  []string{"{home}/Library/Application Support/Yandex/YandexBrowser"},
			Windows: []string{"{local}/Yandex/YandexBrowser/User Data"},
		},
		{
			Family: FamilyChromium, Key: "yandex-beta", Name: "Yandex Browser Beta",
			LinuxKeyringApp: "yandex-browser", LinuxKeyringApps: []string{"yandex-browser", "chrome"},
			DarwinKeychain: "Yandex", DarwinKeychains: []string{"Yandex", "Yandex Browser", "Chrome"},
			Linux:   []string{"{config}/yandex-browser-beta"},
			Darwin:  []string{"{home}/Library/Application Support/Yandex/YandexBrowserBeta"},
			Windows: []string{"{local}/Yandex/YandexBrowserBeta/User Data"},
		},
		{
			Family: FamilyChromium, Key: "helium", Name: "Helium",
			LinuxKeyringApp:  "helium",
			LinuxKeyringApps: []string{"helium", "net.imput.helium", "chromium", "chrome"},
			DarwinKeychain:   "Helium",
			DarwinKeychains:  []string{"Helium", "net.imput.helium", "Chromium", "Chrome"},
			Aliases:          []string{"net.imput.helium"},
			Linux: []string{
				"{config}/net.imput.helium",
				"{home}/.var/app/net.imput.helium/config/net.imput.helium",
			},
			Darwin: []string{
				"{home}/Library/Application Support/net.imput.helium",
			},
			Windows: []string{
				"{local}/net.imput.helium",
				"{local}/net.imput.helium/User Data",
				"{local}/imput/Helium/User Data",
			},
		},
		{
			Family: FamilyChromium, Key: "ungoogled-chromium", Name: "Ungoogled Chromium",
			LinuxKeyringApp: "chromium", LinuxKeyringApps: []string{"chromium", "chrome"},
			DarwinKeychain: "Chromium", DarwinKeychains: []string{"Chromium", "Chrome"},
			Aliases: []string{"ungoogled", "ug"},
			Linux: []string{
				"{config}/ungoogled-chromium",
				"{home}/.var/app/io.github.ungoogled_software.ungoogled_chromium/config/chromium",
				"{home}/.var/app/io.github.ungoogled_software.ungoogled_chromium/config/ungoogled-chromium",
			},
			Darwin: []string{
				"{home}/Library/Application Support/ungoogled-chromium",
			},
			Windows: []string{
				"{local}/ungoogled-chromium/User Data",
			},
		},
		{
			Family: FamilyChromium, Key: "thorium", Name: "Thorium",
			LinuxKeyringApp: "thorium", LinuxKeyringApps: []string{"thorium", "chromium", "chrome"},
			DarwinKeychain: "Thorium", DarwinKeychains: []string{"Thorium", "Chromium", "Chrome"},
			Linux:   []string{"{config}/thorium"},
			Darwin:  []string{"{home}/Library/Application Support/Thorium"},
			Windows: []string{"{local}/Thorium/User Data"},
		},
		{
			Family: FamilyChromium, Key: "arc", Name: "Arc",
			LinuxKeyringApp: "arc", LinuxKeyringApps: []string{"arc", "chrome"},
			DarwinKeychain: "Arc", DarwinKeychains: []string{"Arc", "Chrome"},
			Linux:   []string{"{config}/Arc"},
			Darwin:  []string{"{home}/Library/Application Support/Arc"},
			Windows: []string{"{local}/Arc/User Data"},
		},

		// ---------------------------------------------------------------- Firefox
		{
			Family: FamilyFirefox, Key: "firefox", Name: "Firefox",
			Aliases: []string{"mozilla"},
			Linux: []string{
				"{home}/.mozilla/firefox",
				"{config}/mozilla/firefox",
				"{home}/.mozilla/firefox-beta",
				"{home}/.mozilla/firefox-trunk",
				"{home}/snap/firefox/common/.mozilla/firefox",
				"{home}/.var/app/org.mozilla.firefox/.mozilla/firefox",
				"{home}/.mozilla/icecat",
				"{config}/mozilla/icecat",
			},
			Darwin: []string{
				"{home}/Library/Application Support/Firefox",
				"{home}/Library/Application Support/Firefox Developer Edition",
				"{home}/Library/Application Support/Firefox Nightly",
			},
			Windows: []string{
				"{appdata}/Mozilla/Firefox",
				"{appdata}/Mozilla/Firefox Developer Edition",
				"{appdata}/Mozilla/Firefox Nightly",
			},
		},
		{
			Family: FamilyFirefox, Key: "librewolf", Name: "LibreWolf",
			Linux: []string{
				"{home}/.librewolf",
				"{config}/librewolf",
				"{home}/snap/librewolf/common/.librewolf",
				"{home}/.var/app/io.gitlab.librewolf-community/.librewolf",
			},
			Darwin:  []string{"{home}/Library/Application Support/LibreWolf"},
			Windows: []string{"{appdata}/LibreWolf"},
		},
		{
			Family: FamilyFirefox, Key: "waterfox", Name: "Waterfox",
			Linux: []string{
				"{home}/.waterfox",
				"{config}/waterfox",
			},
			Darwin:  []string{"{home}/Library/Application Support/Waterfox"},
			Windows: []string{"{appdata}/Waterfox"},
		},
		{
			Family: FamilyFirefox, Key: "floorp", Name: "Floorp",
			Linux: []string{
				"{home}/.floorp",
				"{config}/floorp",
				"{home}/.var/app/one.ablaze.floorp/.floorp",
			},
			Darwin:  []string{"{home}/Library/Application Support/Floorp"},
			Windows: []string{"{appdata}/Floorp"},
		},
		{
			Family: FamilyFirefox, Key: "zen", Name: "Zen Browser",
			Linux: []string{
				"{home}/.zen",
				"{config}/zen",
				"{home}/.var/app/app.zen_browser.zen/.zen",
			},
			Darwin:  []string{"{home}/Library/Application Support/Zen"},
			Windows: []string{"{appdata}/Zen"},
		},
		{
			Family: FamilyFirefox, Key: "palemoon", Name: "Pale Moon",
			Linux: []string{
				"{home}/.palemoon",
				"{config}/palemoon",
			},
			Darwin:  []string{"{home}/Library/Application Support/Pale Moon"},
			Windows: []string{"{appdata}/Moonchild Productions/Pale Moon"},
		},
		{
			Family: FamilyFirefox, Key: "seamonkey", Name: "SeaMonkey",
			Linux: []string{
				"{home}/.seamonkey",
				"{config}/seamonkey",
			},
			Darwin:  []string{"{home}/Library/Application Support/SeaMonkey"},
			Windows: []string{"{appdata}/Mozilla/SeaMonkey"},
		},
		{
			Family: FamilyFirefox, Key: "tor-browser", Name: "Tor Browser",
			Aliases: []string{"tor", "tbb"},
			Linux: []string{
				"{home}/tor-browser/Browser/TorBrowser/Data/Browser",
				"{home}/tor-browser_*/Browser/TorBrowser/Data/Browser",
				"{home}/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{home}/.tb/tor-browser/Browser/TorBrowser/Data/Browser",
				"{share}/torbrowser/tbb/*/tor-browser/Browser/TorBrowser/Data/Browser",
				"{home}/.var/app/org.torproject.torbrowser-launcher/data/torbrowser/tbb/*/tor-browser/Browser/TorBrowser/Data/Browser",
				"{home}/.var/app/com.github.micahflee.torbrowser-launcher/data/torbrowser/tbb/*/tor-browser/Browser/TorBrowser/Data/Browser",
			},
			Darwin: []string{
				"{home}/Library/Application Support/TorBrowser-Data/Browser",
				"{home}/Library/Application Support/TorBrowser-Data",
				"{home}/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{home}/Downloads/Tor Browser/Browser/TorBrowser/Data/Browser",
			},
			Windows: []string{
				"{appdata}/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{local}/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{appdata}/Tor Browser/TorBrowser-Data/Browser",
				"{local}/Tor Browser/TorBrowser-Data/Browser",
				"{home}/Desktop/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{home}/Downloads/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{home}/tor-browser/Browser/TorBrowser/Data/Browser",
				"{home}/Tor Browser/Browser/TorBrowser/Data/Browser",
				"{home}/tor-browser_*/Browser/TorBrowser/Data/Browser",
				"{programfiles}/Tor Browser/Browser/TorBrowser/Data/Browser",
			},
		},
		{
			Family: FamilyFirefox, Key: "mullvad-browser", Name: "Mullvad Browser",
			Aliases: []string{"mullvad"},
			Linux: []string{
				"{home}/.mullvad/mullvadbrowser",
				"{home}/.mullvad-browser/.mullvad/mullvadbrowser",
				"{home}/.var/app/net.mullvad.MullvadBrowser/.mullvad/mullvadbrowser",
				"{home}/.var/app/net.mullvad.MullvadBrowser/.mullvad-browser/.mullvad/mullvadbrowser",
				"{home}/mullvad-browser/Browser/TorBrowser/Data/Browser",
				"{home}/mullvad-browser_*/Browser/TorBrowser/Data/Browser",
				"{home}/Desktop/Mullvad Browser/Browser/TorBrowser/Data/Browser",
				"{home}/Downloads/Mullvad Browser/Browser/TorBrowser/Data/Browser",
			},
			Darwin: []string{
				"{home}/Library/Application Support/MullvadBrowser",
				"{home}/Library/Application Support/MullvadBrowser/Profiles",
				"{home}/Library/Application Support/Mullvad Browser",
				"{home}/Desktop/Mullvad Browser/Browser/TorBrowser/Data/Browser",
				"{home}/Downloads/Mullvad Browser/Browser/TorBrowser/Data/Browser",
			},
			Windows: []string{
				"{appdata}/Mullvad/MullvadBrowser",
				"{appdata}/Mullvad/MullvadBrowser/Profiles",
				"{local}/Mullvad/MullvadBrowser",
				"{home}/Desktop/Mullvad Browser/Browser/TorBrowser/Data/Browser",
				"{home}/Downloads/Mullvad Browser/Browser/TorBrowser/Data/Browser",
				"{home}/mullvad-browser/Browser/TorBrowser/Data/Browser",
				"{programfiles}/Mullvad Browser/Browser/TorBrowser/Data/Browser",
			},
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

// LinuxKeyringCandidates returns the keyring application ids to try.
func (s Spec) LinuxKeyringCandidates() []string {
	return uniqueStrings(append([]string{s.LinuxKeyringApp}, s.LinuxKeyringApps...)...)
}

// DarwinKeychainCandidates returns the Keychain application names to try.
func (s Spec) DarwinKeychainCandidates() []string {
	return uniqueStrings(append([]string{s.DarwinKeychain}, s.DarwinKeychains...)...)
}

func uniqueStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
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

// MatchBasesForOS expands placeholders and shell-style wildcards. The
// wildcard support lets the registry find portable Tor/Mullvad installations
// (for example ~/tor-browser_en-US) without walking the whole home directory.
func (s Spec) MatchBasesForOS() []string {
	out := make([]string, 0)
	seen := make(map[string]bool)
	for _, pattern := range s.BasesForOS() {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
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
	programFiles := os.Getenv("ProgramFiles")
	programFiles86 := os.Getenv("ProgramFiles(x86)")

	replacer := strings.NewReplacer(
		"{home}", home,
		"{config}", config,
		"{local}", local,
		"{appdata}", appdata,
		"{share}", share,
		"{programfiles}", programFiles,
		"{programfiles86}", programFiles86,
	)
	return filepath.Clean(replacer.Replace(path))
}
