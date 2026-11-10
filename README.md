# gethisengine

Кроссплатформенная утилита на Go, которая находит профили браузеров на
устройстве и извлекает из них сохранённые логины, историю, cookies,
закладки и данные автозаполнения.

Поддерживаются браузеры на Chromium и Firefox. Утилита работает локально,
не делает сетевых запросов и **никогда не изменяет профили**: базы данных
копируются во временный каталог и открываются в режиме `immutable`.

> **Важно.** Инструмент предназначен для собственных устройств и
> авторизованного аудита/восстановления данных. Использование на чужих
> устройствах без разрешения может нарушать закон.

## Возможности

- Автообнаружение профилей Chromium- и Firefox-браузеров на Linux, macOS и
  Windows, включая Flatpak и Snap.
- История, cookies, закладки, автозаполнение и сохранённые логины.
- Расшифровка паролей Chromium (Secret Service / Keychain / DPAPI) и Firefox
  (`key4.db`, NSS) — по явному флагу `--reveal`.
- Вывод в таблицу, JSON или CSV; команда `dump` собирает полный отчёт.
- Секреты по умолчанию скрыты, значения cookie и пароли маскируются.

## Поддерживаемые браузеры

| Семейство | Браузеры |
|---|---|
| Chromium | Google Chrome (stable/beta/dev/canary), Chromium, Brave, Microsoft Edge, Vivaldi, Opera, Opera GX, Yandex Browser, Thorium, Arc |
| Firefox | Firefox, LibreWolf, Waterfox, Floorp, Zen Browser, Pale Moon, SeaMonkey |

Safari не поддерживается (другое хранилище и шифрование).

## Сборка

В репозитории есть `shell.nix`:

```sh
nix-shell --run 'go build -o bin/gethisengine ./cmd/gethisengine'
```

Или обычным Go 1.26+:

```sh
go build -o bin/gethisengine ./cmd/gethisengine
```

Кросс-компиляция (чистый Go, без CGO):

```sh
GOOS=windows GOARCH=amd64 go build -o gethisengine.exe ./cmd/gethisengine
GOOS=darwin  GOARCH=arm64 go build -o gethisengine-macos ./cmd/gethisengine
```

## Использование

```sh
# Найти все профили
gethisengine scan

# То же в JSON
gethisengine scan --format json

# История за последний месяц, только Brave
gethisengine history --browser brave --since 2026-10-01 --limit 100

# Сохранённые логины (пароли скрыты)
gethisengine passwords

# Расшифровать пароли
gethisengine passwords --reveal

# Cookies (значения скрыты)
gethisengine cookies --browser chromium

# Полный отчёт в каталог
gethisengine dump --out ./report --format both --reveal
```

Полезные глобальные флаги:

| Флаг | Назначение |
|---|---|
| `--browser chrome,brave,firefox` | фильтр по ключу браузера или семейству |
| `--profile Default` | фильтр по имени профиля |
| `--root PATH` | дополнительный путь (User Data, профиль Firefox или база с `profiles.ini`) |
| `--reveal` | расшифровать пароли и значения cookie |
| `--format table\|json\|csv` | формат вывода (`dump`: `json\|csv\|both`) |
| `--out FILE` | записать результат в файл (для `dump` — в каталог) |
| `--keyring-password` | пароль Linux-keyring вместо запроса Secret Service |
| `--peanuts` | принудительно использовать legacy-пароль `peanuts` |
| `--chromium-key-hex` | использовать известный master-ключ Chromium (hex) вместо keyring/DPAPI |
| `--master-password` | primary password Firefox |
| `--quiet` | не печатать предупреждения |
| `--since`, `--limit` | фильтр истории (для `history` и `dump`) |

## Как получаются ключи

**Chromium**

- **Linux:** пароль из freedesktop Secret Service (GNOME Keyring, KWallet,
  KeePassXC) для приложения `chrome`, `chromium`, `brave`, `microsoft-edge`,
  `vivaldi`, `opera`, `yandex-browser`, ... Затем PBKDF2-SHA1 (1 итерация,
  `saltysalt`, 16 байт) и AES-128-CBC. Если элемент не найден — legacy
  fallback `peanuts` (с предупреждением).- **macOS:** пароль из Keychain (`security find-generic-password`), PBKDF2
  SHA1 1003 итерации, AES-128-CBC.
- **Windows:** `os_crypt.encrypted_key` из `Local State` расшифровывается
  через DPAPI и используется для AES-256-GCM. Старые профили (до Chrome 80)
  читаются напрямую через DPAPI.

Если master-ключ уже известен, его можно передать напрямую:
`--chromium-key-hex <hex>`. На Linux/macOS это 16-байтовый ключ (CBC), на
Windows — 32-байтовый (GCM).

**Firefox**

`key4.db` разбирается напрямую (без libnss): PBES2/PBKDF2-HMAC-SHA256 →
AES-256-CBC, плюс legacy 3DES. `logins.json` расшифровывается мастер-ключом
NSS. Если задан primary password, передайте его через `--master-password`.

## Ограничения

- **App-bound encryption (Chrome 127+, Windows, префикс `v20`)** не
  поддерживается: для неё нужен elevation-сервис Chrome. Такие записи
  помечаются ошибкой, остальные данные читаются нормально.
- Заблокированный keyring/Keychain: значения останутся скрытыми, утилита
  покажет предупреждение. Для Linux можно передать `--keyring-password`.
- Legacy `key3.db`/`signons.sqlite` (очень старые Firefox) не читаются.
- Профили других пользователей Windows нельзя расшифровать без их DPAPI-
  контекста.
- Safari, расширения и Thunderbird не входят в область действия.

## Формат отчёта

`dump --format json` создаёт `report.json` со стабильной схемой:

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

`dump --format csv` пишет отдельные файлы: `profiles.csv`, `passwords.csv`,
`history.csv`, `cookies.csv`, `bookmarks.csv`, `autofill.csv`.

## Разработка

```sh
nix-shell --run 'go test ./...'
nix-shell --run 'go vet ./...'
```

Тесты используют синтетические профили с известными ключами, поэтому не
зависят от установленных браузеров. Crypto-тесты покрывают Chromium CBC/GCM
и полный цикл Firefox `key4.db` + `logins.json`.
