# gethisengine

[English version](README.md)

`gethisengine` — кроссплатформенная утилита на Go, которая находит профили
браузеров на локальной машине и извлекает из них сохранённые логины, историю,
cookies, закладки и данные автозаполнения форм.

Поддерживаются браузеры на Chromium и Firefox для Linux, macOS и Windows.
Всё работает локально: утилита **не делает сетевых запросов**, **не изменяет
профили** и копирует SQLite-базы во временный каталог перед открытием.

> **Важно.** Используйте инструмент только на собственных устройствах или на
> устройствах, аудит которых вам явно разрешён. Доступ к чужим данным браузера
> без разрешения может нарушать закон.

## Возможности

- Автообнаружение профилей Chromium и Firefox на Linux, macOS и Windows,
  включая XDG-пути, Flatpak, Snap, переносимые установки и произвольные
  каталоги через `--root`.
- Сохранённые пароли, история, cookies, закладки и автозаполнение.
- Расшифровка Chromium через Secret Service / macOS Keychain / Windows DPAPI.
- Разбор Firefox `key4.db` на чистом Go, поддержка `logins.json` и нового
  хранилища `logins.db` (Firefox 144+).
- Вывод в таблицу, JSON и CSV. Команда `dump` собирает полный отчёт.
- Полноэкранный интерактивный TUI (`gethisengine tui`) для просмотра данных.
- Секреты скрыты по умолчанию. Пароли расшифровываются, а значения cookie
  показываются только с флагом `--reveal`.
- Статические бинарники без CGO; libnss и установленный браузер не нужны.

## Поддерживаемые браузеры

| Движок | Браузеры и каналы |
|---|---|
| Chromium | Google Chrome (stable, beta, dev, canary), Chromium, Brave (stable, beta, dev, nightly), Microsoft Edge (stable, beta, dev, canary), Vivaldi (stable, snapshot), Opera (stable, beta, developer, GX), Yandex Browser (stable, beta), Helium, Ungoogled Chromium, Thorium, Arc |
| Firefox | Firefox, LibreWolf, Waterfox, Floorp, Zen Browser, Pale Moon, SeaMonkey, Tor Browser, Mullvad Browser |

Примечания:

- Ungoogled Chromium и Chromium часто используют один и тот же каталог данных.
  Такой профиль показывается один раз как Chromium и дополнительно совпадает
  с алиасами `ungoogled`, `ungoogled-chromium` и `ug`.
- Tor Browser также совпадает с `tor`/`tbb`, Mullvad Browser — с `mullvad`,
  Helium — с `net.imput.helium`.
- Пути stable/beta/dev/nightly ищутся независимо, поэтому несколько каналов
  могут быть найдены одновременно.
- Safari, Thunderbird, расширения браузеров и мобильные браузеры не
  поддерживаются.

## Требования

- Go 1.26 или новее.
- Linux, macOS или Windows.
- CGO не требуется. Сборка с `CGO_ENABLED=0`.

## Сборка

Через приложенный `shell.nix`:

```sh
nix-shell --run 'go build -trimpath -o bin/gethisengine ./cmd/gethisengine'
```

Обычным Go:

```sh
CGO_ENABLED=0 go build -trimpath -o bin/gethisengine ./cmd/gethisengine
```

Через Makefile:

```sh
make build          # локальный бинарник
make test           # go test ./...
make vet            # go vet ./...
make cross          # бинарники для linux/darwin/windows в dist/
```

Примеры кросс-компиляции:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o gethisengine.exe ./cmd/gethisengine
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o gethisengine-macos ./cmd/gethisengine
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o gethisengine-linux-arm64 ./cmd/gethisengine
```

## Использование

```sh
# Найти все известные профили
gethisengine scan

# Список профилей в JSON
gethisengine scan --format json

# История Brave с указанной даты
gethisengine history --browser brave --since 2026-10-01 --limit 100

# Сохранённые логины (пароли замаскированы)
gethisengine passwords

# Расшифровать и показать пароли
gethisengine passwords --reveal

# Cookies (значения скрыты без --reveal)
gethisengine cookies --browser firefox

# Полный отчёт в каталог (JSON + CSV)
gethisengine dump --out ./report --format both --reveal

# Интерактивный просмотр
gethisengine tui
```

### Интерактивный TUI

`gethisengine tui` использует те же read-only-экстракторы, что и обычные
команды, но показывает данные в полноэкранном терминальном браузере. Нужен
интерактивный терминал; в скриптах используйте обычные команды.

| Клавиша | Действие |
|---|---|
| `1` … `6` | Profiles, Passwords, History, Cookies, Bookmarks, Autofill |
| `↑`/`↓` или `j`/`k` | Прокрутка на одну строку |
| `PgUp`/`PgDn` | Прокрутка на десять строк |
| `g`/`G` | В начало/в конец |
| `r` | Переключить режим reveal и перезагрузить данные |
| `R` | Перезагрузить данные |
| `q` / `Ctrl-C` | Выход |

Флаги `--browser`, `--profile`, `--root`, `--since`, `--limit` и флаги ключей
также работают с `tui`.

### Команды

| Команда | Назначение |
|---|---|
| `scan` | Показать найденные профили и найденные в них артефакты |
| `passwords` | Извлечь сохранённые логины; пароли требуют `--reveal` |
| `history` | Извлечь историю посещений |
| `cookies` | Извлечь cookies; значения требуют `--reveal` |
| `bookmarks` | Извлечь закладки |
| `autofill` | Извлечь сохранённые данные форм |
| `dump` | Записать все данные в каталог отчёта (`json`, `csv` или `both`) |
| `tui` | Открыть полноэкранный интерактивный терминальный браузер |

### Глобальные флаги

| Флаг | Назначение |
|---|---|
| `--browser chrome,brave,firefox` | Фильтр по ключу браузера, семейству или алиасу |
| `--profile Default` | Фильтр по имени профиля или имени каталога |
| `--root PATH` | Добавить произвольный User Data / профиль Firefox / каталог с `profiles.ini` |
| `--reveal` | Расшифровать пароли и показать значения cookie |
| `--format table\|json\|csv` | Формат вывода (`dump`: `json\|csv\|both`) |
| `--out FILE` | Записать результат в файл (для `dump` — в каталог) |
| `--keyring-password` | Передать пароль Linux-keyring вместо Secret Service |
| `--peanuts` | Принудительно использовать legacy-пароль Linux `peanuts` |
| `--chromium-key-hex` | Использовать известный master-ключ Chromium (hex) вместо keyring/DPAPI |
| `--master-password` | Primary Password Firefox |
| `--quiet` | Не печатать предупреждения |
| `--since`, `--limit` | Фильтры истории (также используются в `dump`) |

Алиасы браузеров принимаются в `--browser`, например:

```sh
gethisengine passwords --browser ungoogled
gethisengine history --browser tor
gethisengine cookies --browser mullvad
gethisengine passwords --browser helium
```

## Как получаются ключи

### Chromium

- **Linux:** пароль шифрования читается из freedesktop Secret Service (GNOME
  Keyring, Secret Service-мост KWallet, KeePassXC и т. п.). Утилита пробует
  несколько идентификаторов приложений на браузер (например, `helium`,
  `chromium`, `chrome`), потому что форки иногда регистрируются под именем
  upstream-браузера. Затем используется PBKDF2-SHA1 (одна итерация, соль
  `saltysalt`, 16-байтовый ключ) и AES-128-CBC.
- **macOS:** элемент `<Browser> Safe Storage` читается из login Keychain
  встроенной утилитой `security`, затем применяются PBKDF2-SHA1 (1003
  итерации, `saltysalt`) и AES-128-CBC.
- **Windows:** `os_crypt.encrypted_key` из `Local State` распаковывается через
  DPAPI и используется для AES-256-GCM. Старые записи (до Chrome 80)
  расшифровываются напрямую через DPAPI.
- Если элемента Secret Service нет, Linux откатывается на legacy-пароль
  `peanuts` с предупреждением. Заблокированный keyring считается ошибкой, а не
  поводом выдавать заведомо неверный результат.

Если master-ключ уже известен, его можно передать напрямую:

```sh
gethisengine passwords --reveal --chromium-key-hex <hex>
```

В Linux и macOS ключ 16-байтовый (CBC), в Windows — 32-байтовый (GCM).

### Firefox

`key4.db` разбирается напрямую на чистом Go, без libnss:

- PBES2/PBKDF2 с PRF из файла (поддерживаются SHA-1/SHA-256/SHA-384/SHA-512).
- Seed SHA-1 для обычной 20-байтовой глобальной соли и SHA-384 для 48-байтовой
  соли, созданной Primary Password.
- Master-ключи, обёрнутые в 3DES-CBC и AES-256-CBC.
- Пробуются все строки `nssPrivate`, что покрывает сборки Firefox, где сначала
  лежит legacy 3DES-ключ, а затем AES-ключ, или используется другой `CKA_ID`.

Сохранённые логины читаются из:

- `logins.json` в старых профилях;
- `logins.db` (Firefox 144+), включая JWE `dir`/`A256GCM` в колонке
  `secFields` таблиц `loginsL`/`loginsM`.

Если в Firefox задан Primary Password, передайте его через
`--master-password`.

## Безопасность и приватность

- Только чтение: базы профиля и сопутствующие WAL/SHM-файлы копируются во
  временный каталог; оригиналы никогда не изменяются.
- Только локально: нет сетевых запросов, телеметрии и проверок обновлений.
- Секреты скрыты по умолчанию; только `--reveal` расшифровывает пароли и
  показывает значения cookie.
- Выходные файлы создаются с правами `0600`.
- Не запускайте утилиту на недоверенной машине. Расшифрованные секреты
  находятся в памяти процесса и не затираются явно после использования.

## Формат отчёта

`dump --format json` создаёт стабильный `report.json`:

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
`history.csv`, `cookies.csv`, `bookmarks.csv` и `autofill.csv`.
`dump --format both` создаёт оба представления.

## Ограничения

- **App-bound encryption** (`v20` в Windows Chrome 127+) не поддерживается:
  такие записи помечаются ошибкой, остальные данные профиля читаются нормально.
- Legacy-хранилища Firefox `key3.db` и `signons.sqlite` не поддерживаются.
- Заблокированный Linux keyring или macOS Keychain нужно сначала разблокировать.
  В Linux можно передать `--keyring-password`.
- Профили Windows другого пользователя нельзя расшифровать без его контекста
  DPAPI.
- Некоторые песочницы Flatpak/Snap скрывают каталоги браузера от хоста.
  Используйте `--root` с видимым путём, если автообнаружение не нашло профиль.
- Tor Browser и Mullvad Browser часто работают в приватном режиме, поэтому
  история может быть пустой или очень короткой.
- Safari, Thunderbird, расширения и мобильные браузеры не поддерживаются.

## Решение проблем

**Профили не найдены**

Запустите `gethisengine scan --format json` и посмотрите значения `path`.
Добавьте произвольный корень, если браузер использует необычное место:

```sh
gethisengine scan --root /path/to/User\ Data
gethisengine scan --root /path/to/firefox/profile
gethisengine scan --root /path/to/profiles.ini-parent
```

В NixOS и других дистрибутивах данные браузера могут находиться в XDG-каталогах,
в данных Flatpak, в каталогах Snap или в профиле home-manager. Встроенный
реестр покрывает эти распространённые места, а не жёстко привязан к путям
одного дистрибутива.

**Пароли пустые или расшифровка не удалась**

- Убедитесь, что в профиле действительно есть сохранённые логины.
- В Linux разблокируйте keyring или передайте `--keyring-password`.
- В Windows значения `v20` с app-bound encryption этим инструментом не
  расшифровываются.
- В Firefox проверьте, задан ли Primary Password, и передайте
  `--master-password`.

**Неверный Primary Password Firefox**

Сообщение об ошибке намеренное: запись password-check в `key4.db` не совпала.
Повторите с правильным `--master-password`.

## Разработка

```sh
nix-shell ~/Developer/shell.nix --run 'go test ./...'
nix-shell ~/Developer/shell.nix --run 'go test -race ./...'
nix-shell ~/Developer/shell.nix --run 'go vet ./...'
make cross
```

Тесты используют синтетические профили с известными ключами, поэтому не
зависят от установленных браузеров и от данных разработчика. Покрытие включает
Chromium CBC/GCM, читатели Chromium, Firefox NSS `key4.db`, `logins.json`,
JWE `logins.db`, обнаружение профилей и end-to-end тест CLI.

## Лицензия

MIT. См. [LICENSE](LICENSE).
