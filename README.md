# gethisengine

[Русская версия](README_ru.md)

`gethisengine` is a cross-platform Go CLI that discovers browser profiles on
the local machine and extracts saved logins, history, cookies, bookmarks and
form autofill data.

It supports Chromium-based and Firefox-based browsers on Linux, macOS and
Windows. Everything runs locally: the tool does **not** make network requests,
does **not** modify profiles, and copies SQLite databases to a temporary
directory before opening them.

> **Legal notice.** Use this tool only on devices you own or are explicitly
> authorised to audit. Accessing someone else's browser data without permission
> may be illegal in your jurisdiction.

## Features

- Automatic discovery of Chromium and Firefox profiles on Linux, macOS and
  Windows, including XDG paths, Flatpak, Snap, portable installations and
  custom `--root` locations.
- Saved passwords, history, cookies, bookmarks and autofill entries.
- Chromium decryption through Secret Service / macOS Keychain / Windows DPAPI.
- Firefox `key4.db` parsing in pure Go, with both `logins.json` and the newer
  Firefox 144+ `logins.db` password store.
- Table, JSON and CSV output. The `dump` command writes a complete report.
- A full-screen interactive TUI (`gethisengine tui`) for browsing the results.
- Secrets are hidden by default. Passwords are decrypted and cookie values are
  revealed only with `--reveal`.
- Single static binaries, no CGO, no libnss or browser installation required.

## Supported browsers

| Engine | Browsers and channels |
|---|---|
| Chromium | Google Chrome (stable, beta, dev, canary), Chromium, Brave (stable, beta, dev, nightly), Microsoft Edge (stable, beta, dev, canary), Vivaldi (stable, snapshot), Opera (stable, beta, developer, GX), Yandex Browser (stable, beta), Helium, Ungoogled Chromium, Thorium, Arc |
| Firefox | Firefox, LibreWolf, Waterfox, Floorp, Zen Browser, Pale Moon, SeaMonkey, Tor Browser, Mullvad Browser |

Notes:

- Ungoogled Chromium and Chromium often share the same data directory. Such a
  profile is reported once as Chromium and also matches the aliases
  `ungoogled`, `ungoogled-chromium` and `ug`.
- Tor Browser also matches `tor`/`tbb`, Mullvad Browser matches `mullvad`, and
  Helium matches `net.imput.helium`.
- Stable/beta/dev/nightly paths are discovered independently, so multiple
  channels can be present at the same time.
- Safari, Thunderbird, browser extensions and non-browser applications are out
  of scope.

## Requirements

- Go 1.26 or newer.
- Linux, macOS or Windows.
- CGO is not required. Build with `CGO_ENABLED=0`.

## Build

With the included `shell.nix`:

```sh
nix-shell --run 'go build -trimpath -o bin/gethisengine ./cmd/gethisengine'
```

With a normal Go toolchain:

```sh
CGO_ENABLED=0 go build -trimpath -o bin/gethisengine ./cmd/gethisengine
```

Using the Makefile:

```sh
make build          # native binary
make test           # go test ./...
make vet            # go vet ./...
make cross          # linux/darwin/windows binaries in dist/
```

Cross-compilation examples:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o gethisengine.exe ./cmd/gethisengine
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o gethisengine-macos ./cmd/gethisengine
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o gethisengine-linux-arm64 ./cmd/gethisengine
```

## Usage

```sh
# Find every known profile
gethisengine scan

# Machine-readable profile list
gethisengine scan --format json

# History from Brave since a given date
gethisengine history --browser brave --since 2026-10-01 --limit 100

# Saved logins (passwords stay masked)
gethisengine passwords

# Decrypt and reveal passwords
gethisengine passwords --reveal

# Cookies (values stay masked unless --reveal is used)
gethisengine cookies --browser firefox

# Full report directory (JSON + CSV)
gethisengine dump --out ./report --format both --reveal

# Interactive browser
gethisengine tui
```

### Interactive TUI

`gethisengine tui` uses the same read-only extractors as the regular commands
but presents the data in a full-screen terminal browser. It requires an
interactive terminal; use the normal commands in scripts.

| Key | Action |
|---|---|
| `1` … `6` | Profiles, Passwords, History, Cookies, Bookmarks, Autofill |
| `↑`/`↓` or `j`/`k` | Scroll one line |
| `PgUp`/`PgDn` | Scroll ten lines |
| `g`/`G` | Jump to the top/bottom |
| `r` | Toggle reveal mode and reload |
| `R` | Reload the data |
| `q` / `Ctrl-C` | Quit |

The `--browser`, `--profile`, `--root`, `--since`, `--limit` and key-related
flags work with `tui` as well.

### Commands

| Command | Description |
|---|---|
| `scan` | List discovered profiles and the artifacts found in each one |
| `passwords` | Extract saved logins; passwords require `--reveal` |
| `history` | Extract browser history |
| `cookies` | Extract cookies; values require `--reveal` |
| `bookmarks` | Extract bookmarks |
| `autofill` | Extract saved form/autofill entries |
| `dump` | Write all data into a report directory (`json`, `csv` or `both`) |
| `tui` | Open the full-screen interactive terminal browser |

### Global flags

| Flag | Purpose |
|---|---|
| `--browser chrome,brave,firefox` | Filter by browser key, family or alias |
| `--profile Default` | Filter by profile name or directory name |
| `--root PATH` | Add a custom User Data / Firefox profile / `profiles.ini` root |
| `--reveal` | Decrypt passwords and reveal cookie values |
| `--format table\|json\|csv` | Output format (`dump`: `json\|csv\|both`) |
| `--out FILE` | Write output to a file (`dump`: directory) |
| `--keyring-password` | Supply the Linux keyring password instead of using Secret Service |
| `--peanuts` | Force the legacy Linux `peanuts` password |
| `--chromium-key-hex` | Use a known Chromium master key (hex) instead of keyring/DPAPI |
| `--master-password` | Firefox Primary Password |
| `--quiet` | Suppress warnings |
| `--since`, `--limit` | History filters (also used by `dump`) |

Browser aliases are accepted by `--browser`, for example:

```sh
gethisengine passwords --browser ungoogled
gethisengine history --browser tor
gethisengine cookies --browser mullvad
gethisengine passwords --browser helium
```

## How keys are obtained

### Chromium

- **Linux:** the encryption password is read from the freedesktop Secret
  Service (GNOME Keyring, KWallet's Secret Service bridge, KeePassXC, …).
  `gethisengine` tries several application IDs per browser (for example
  `helium`, `chromium`, `chrome`) because forks sometimes register under the
  upstream name. The password is then used with PBKDF2-SHA1 (one iteration,
  salt `saltysalt`, 16-byte key) and AES-128-CBC.
- **macOS:** the `<Browser> Safe Storage` item is read from the login Keychain
  with the built-in `security` tool, then PBKDF2-SHA1 (1003 iterations,
  `saltysalt`) and AES-128-CBC are used.
- **Windows:** `os_crypt.encrypted_key` from `Local State` is unwrapped with
  DPAPI and used for AES-256-GCM. Legacy pre-Chrome-80 entries are decrypted
  directly with DPAPI.
- If no Secret Service item exists, Linux falls back to the legacy `peanuts`
  password with a warning. A locked keyring is reported as an error instead of
  producing misleading output.

If the master key is already known, pass it directly:

```sh
gethisengine passwords --reveal --chromium-key-hex <hex>
```

On Linux and macOS the key is 16 bytes (CBC); on Windows it is 32 bytes (GCM).

### Firefox

`key4.db` is parsed directly in pure Go, without libnss:

- PBES2/PBKDF2 with the PRF advertised in the file (SHA-1/SHA-256/SHA-384/
  SHA-512 are supported).
- SHA-1 seed for a normal 20-byte global salt, SHA-384 seed for a 48-byte salt
  created by a Primary Password.
- 3DES-CBC and AES-256-CBC wrapped master keys.
- Multiple `nssPrivate` rows are tried, which covers Firefox builds that store
  a legacy 3DES key first and an AES key second, or use a different `CKA_ID`.

Saved logins are read from:

- `logins.json` on older profiles; and
- `logins.db` (Firefox 144+), including the `dir`/`A256GCM` JWE values in the
  `secFields` column of `loginsL`/`loginsM`.

If a Firefox Primary Password is set, pass it with `--master-password`.

## Security and privacy

- Read-only: profile databases and their WAL/SHM companions are copied to a
  temporary directory; the originals are never written to.
- Local-only: there are no network requests, telemetry or update checks.
- Secrets are hidden by default; only `--reveal` decrypts passwords and cookie
  values.
- Output files are created with mode `0600`.
- Do not run the tool on a machine you do not trust. Decrypted secrets exist in
  process memory and are not explicitly zeroed after use.

## Report format

`dump --format json` produces a stable `report.json`:

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-07T09:18:40Z",
  "hostname": "...",
  "profiles": [],
  "passwords": [],
  "history": [],
  "cookies": [],
  "bookmarks": [],
  "autofill": [],
  "warnings": []
}
```

`dump --format csv` writes separate files: `profiles.csv`, `passwords.csv`,
`history.csv`, `cookies.csv`, `bookmarks.csv` and `autofill.csv`.
`dump --format both` writes both representations.

## Limitations

- **App-bound encryption** (`v20` values on Windows Chrome 127+) is not
  supported; those entries are reported as errors while the rest of the profile
  is still readable.
- Legacy Firefox `key3.db` and `signons.sqlite` stores are not supported.
- A locked Linux keyring or macOS Keychain must be unlocked first. For Linux,
  `--keyring-password` can be used as an alternative.
- Windows profiles belonging to another user cannot be decrypted without that
  user's DPAPI context.
- Some Flatpak/Snap sandboxes hide browser directories from the host. Use
  `--root` with the visible path if automatic discovery misses a profile.
- Tor Browser and Mullvad Browser commonly use private browsing, so they may
  legitimately contain little or no history.
- Safari, Thunderbird, extensions and mobile browsers are not supported.

## Troubleshooting

**No profiles found**

Run `gethisengine scan --format json` and inspect the `path` values. Add a
custom root when a browser uses an unusual location:

```sh
gethisengine scan --root /path/to/User\ Data
gethisengine scan --root /path/to/firefox/profile
gethisengine scan --root /path/to/profiles.ini-parent
```

On NixOS and other distributions, browser data can live under XDG directories,
Flatpak application data, Snap directories or a home-manager profile. The
built-in registry covers those common locations instead of hardcoding one
distribution's path.

**Passwords are empty or decryption fails**

- Verify that the profile actually has saved logins.
- On Linux, unlock the keyring or pass `--keyring-password`.
- On Windows, `v20` app-bound values cannot be decrypted by this tool.
- For Firefox, check whether a Primary Password is set and pass
  `--master-password`.

**Wrong Firefox Primary Password**

The error message is intentional: the `key4.db` password-check record did not
match. Retry with the correct `--master-password`.

## Development

```sh
nix-shell ~/Developer/shell.nix --run 'go test ./...'
nix-shell ~/Developer/shell.nix --run 'go test -race ./...'
nix-shell ~/Developer/shell.nix --run 'go vet ./...'
make cross
```

Tests use synthetic profiles with known keys, so they do not depend on installed
browsers or on the developer's own data. Coverage includes Chromium CBC/GCM,
Chromium readers, Firefox NSS `key4.db`, `logins.json`, `logins.db` JWE,
discovery and an end-to-end CLI test.

## License

MIT. See [LICENSE](LICENSE).
