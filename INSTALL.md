# Установка Rust-версии TG WS

## Инструкция по установке

Выполните по SSH от root на OpenWrt или Keenetic с Entware:

```sh
wget -O /tmp/tgws-install.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/install.sh && sh /tmp/tgws-install.sh
```

Команда использует последний стабильный Rust-релиз. Исходники находятся
в ветке `main`, прежняя Python-версия сохранена в `legacy-py`.

Панель после установки: **`http://<IP-роутера>:1434/`** → **«Открыть Telegram»**.
Порт прокси: `1433/TCP`. Установщик сам выбирает архитектуру, проверяет SHA-256
и включает автозапуск.

## Инструкция по обновлению

В панели рядом с текущей версией нажмите **«Обновить»**, когда появится новая
версия. Проверка последнего релиза выполняется при открытии панели, её результат
кешируется на 5 минут. Кнопка «Проверить» запускает новую проверку вручную.
Проверка сама ничего не устанавливает: установка начинается только по кнопке
«Обновить». Панель покажет ход операции и перезагрузится после запуска новой версии.

Проверяется последний опубликованный стабильный релиз GitHub с тегом `vX.Y.Z`.
Нужны готовый архив для архитектуры роутера и `SHA256SUMS`; коммит или push в
ветку, черновик и предварительный релиз не становятся обновлением для панели.

Для обновления через SSH загрузите актуальный установщик и запустите его:

```sh
wget -O /tmp/tgws-install.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/install.sh && sh /tmp/tgws-install.sh
```

Настройки, секрет и пароль панели сохраняются. При ошибке запуска установщик
восстанавливает прежние файлы сервиса.

Обновление из панели доступно для штатного размещения файлов и сервиса в OpenWrt
или Entware, когда процесс работает от root. При запуске вне штатного размещения,
без root или на Windows используйте подходящий способ установки вместо кнопки.
Во время перезапуска связь с панелью ненадолго прервётся;
она ждёт подключения до 6 минут, после чего сообщает о необходимости проверить
роутер. Настройки и перезапуск прокси на время установки недоступны.

Текущая версия встроена в бинарник из `Cargo.toml` при сборке.
Релизный тег совпадает с версией сборки с префиксом `v`; следующему
обновлению нужна большая версия. Старые Python-релизы не содержат нужных пакетов.

## Инструкция по удалению

Удаление сервиса с сохранением настроек, по SSH от root:

```sh
wget -O /tmp/tgws-uninstall.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/uninstall.sh && sh /tmp/tgws-uninstall.sh
```

Полное удаление **вместе с настройками, секретом и журналом**:

```sh
wget -O /tmp/tgws-uninstall.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/uninstall.sh && sh /tmp/tgws-uninstall.sh --purge
```

Из рабочей копии запустите `sh scripts/uninstall.sh`, из распакованного релизного архива —
`sh uninstall.sh`; для полного удаления добавьте `--purge`.
Удаление не деинсталлирует Python, OpenSSL и другие общие пакеты.

## Требования и выбор системы

Один исполняемый файл содержит прокси, TLS и веб-панель. Python и сборка на
роутере не нужны. Для загрузки нужны `wget` с HTTPS, доверенные
CA-сертификаты, `tar` и `sha256sum` (обычно уже есть в BusyBox).

OpenWrt с `procd` определяется автоматически; Keenetic должен уже иметь
работающий Entware, смонтированный в `/opt`. Если на OpenWrt дополнительно
установлен Entware, по умолчанию выбирается native OpenWrt. Явный выбор:

```sh
sh /tmp/tgws-install.sh --system entware
# или
sh /tmp/tgws-install.sh --system openwrt
```

Если имеющийся `wget` не поддерживает HTTPS, установите `wget-ssl` и `ca-certificates`
через пакетный менеджер своей системы. Для Entware:

```sh
opkg update
opkg install wget-ssl ca-certificates
```

Если после установки по-прежнему запускается системный `wget` без HTTPS,
повторите команду загрузки с `/opt/bin/wget` вместо `wget`.
[Подробности в документации Entware](https://github.com/Entware/Entware/wiki/Using-HTTPS-with-opkg).

На OpenWrt используйте `opkg` или `apk`, в зависимости от версии прошивки.
Установщик не меняет firewall: прокси и панель должны быть доступны только
из нужной вам сети. Не открывайте порт панели в WAN.

## Файлы и первый запуск

| | OpenWrt | Keenetic / Entware |
|---|---|---|
| Программа | `/usr/bin/tgwsproxy` | `/opt/bin/tgwsproxy` |
| Настройки | `/etc/tgwsproxy/config.json` | `/opt/etc/tgwsproxy/config.json` |
| Сервис | `/etc/init.d/tgwsproxy` | `/opt/etc/init.d/S99tgwsproxy` |
| Журнал | `logread -e tgwsproxy` | `/tmp/tgwsproxy.log` |

Панель по умолчанию: `http://<IP-роутера>:1434/`. Порт прокси: `1433`.
При первой установке панель доступна из LAN без пароля. Установите логин/пароль
в разделе «Доступ к панели». POST-запросы защищены отдельным CSRF-токеном.
Секрет и пароль находятся в `config.json`; храните этот файл как пароль.
Существующие настройки Python-версии сохраняются.

Команды для Entware:

```sh
/opt/etc/init.d/S99tgwsproxy status
/opt/bin/tgwsproxy --config /opt/etc/tgwsproxy/config.json --print-link
/opt/etc/init.d/S99tgwsproxy restart
```

Команды для OpenWrt:

```sh
/etc/init.d/tgwsproxy status
/usr/bin/tgwsproxy --config /etc/tgwsproxy/config.json --print-link
/etc/init.d/tgwsproxy restart
```

## Как проходит обновление и откат

Установщик один раз определяет тег последнего
релиза, затем загружает архив и `SHA256SUMS` именно этого тега. Проверка
контрольной суммы обнаруживает повреждённую загрузку; это не независимая
цифровая подпись.

До остановки старого сервиса проверяются запуск нового бинарника и
совместимость существующего конфига. Файлы заменяются атомарным rename;
при ошибке запуска восстанавливаются прежние бинарник и init-скрипт.
Ранее запущенный сервис после отката запускается снова. Проверка старта
подтверждает живой процесс, но не доступность Telegram у конкретного провайдера.

Для установки конкретной версии:

```sh
sh /tmp/tgws-install.sh --version v2.1.1
```

`config.json`, secret, пароль панели и незнакомые прежние поля не
перезаписываются установщиком. Python и общие библиотеки не удаляются:
они могут использоваться другими приложениями. Установка блокируется,
если уже идёт другая установка или удаление.

Если после аварийного отключения остался каталог
`/opt/var/run/tgwsproxy-install.lock` (Entware) или
`/var/run/tgwsproxy-install.lock` (OpenWrt), сначала убедитесь, что процесс
из его файла `pid` уже завершён; затем удалите этот каталог и повторите команду.

## Поддерживаемые сборки

| Имя архива | CPU / ABI |
|---|---|
| `tgwsproxy-mips.tar.gz` | MIPS32r2, big endian, soft float |
| `tgwsproxy-mipsel.tar.gz` | MIPS32r2, little endian, soft float |
| `tgwsproxy-arm.tar.gz` | ARMv5TE и новее, soft float |
| `tgwsproxy-armv7.tar.gz` | ARMv7-A, soft float |
| `tgwsproxy-aarch64.tar.gz` | AArch64 |
| `tgwsproxy-x86_64.tar.gz` | x86-64 |

MIPS byte order определяется по ELF-заголовку системной программы, поскольку
`uname -m` иногда выводит `mips` для обеих разновидностей. ARM-сборки не требуют
hard-float ABI. Ручной выбор допустим, если CPU уже проверен:

```sh
sh /tmp/tgws-install.sh --arch mipsel
```

Все релизные сборки используют static musl и включённый OpenSSL.
Совместимость с конкретной старой прошивкой, ядром и объёмом RAM надо
проверять на устройстве. MIPS32r1 и 64-битные MIPS отдельными сборками
не представлены. Измеренный размер каждого бинарника и архива сохраняется
в `build-<arch>.txt` в релизе. До выполнения CI эти размеры не заявляются.

## Локальная установка и сборка

Из распакованного релизного архива:

```sh
sh install.sh --binary ./tgwsproxy
```

Из рабочей копии с готовым бинарником:

```sh
sh scripts/install.sh --binary /tmp/tgwsproxy
```

Опция `--no-start` оставляет установленный сервис остановленным. Пара
`--root /absolute/staging --no-start` раскладывает файлы в отдельном каталоге
без root и без обращения к сервисам основной системы.

Cross-сборка Linux-релизов требует Docker, Rust, `cross` и `jq` на рабочем компьютере:

```sh
rustup toolchain install nightly-2026-09-01 --profile minimal --component rust-src
cargo install cross --git https://github.com/cross-rs/cross --rev 8c1a8aa4b661711f4b7b6ac07c2e8929ce2f7d27 --locked
bash scripts/build-release.sh mipsel
```

ARM64 также собирается без Docker на ARM64 Linux. Например, на Ubuntu 24.04 ARM:

```sh
sudo apt-get install musl-tools build-essential perl jq binutils file
rustup toolchain install 1.97.0 --profile minimal --target aarch64-unknown-linux-musl
bash scripts/build-release.sh aarch64 native
```

Именно этот вариант использует ARM64 job в GitHub Actions. Он запускает весь
набор Rust-тестов на ARM64, включая аппаратное AES. Ручной запуск workflow с
`arch=aarch64` собирает только эту архитектуру; релизный тег всегда собирает все шесть.

В `Cross.toml` MIPS использует `build-std`: Rust не распространяет готовый
`std` для этих Tier 3 целей. Скрипт дополнительно отключает self-contained
поиск CRT, чтобы linker использовал CRT из cross sysroot. Все шесть целей
собираются в CI; до публикации выполняются проверка static ELF и запуск CLI
на ARM64 Linux либо через QEMU для cross-сборок. Это не заменяет испытаний на физическом роутере.

Rust nightly и версия `cross` зафиксированы. Теги контейнеров cross `main`
могут обновляться; фактически использованный digest сохраняется в отчёте
сборки. Поэтому побитовая воспроизводимость между разными датами не заявляется.

Офлайн-проверка установщика:

```sh
sh scripts/test-installer.sh
```

## Диагностика

```sh
# Entware
/opt/bin/tgwsproxy --config /opt/etc/tgwsproxy/config.json --check-config
tail -n 50 /tmp/tgwsproxy.log

# OpenWrt
/usr/bin/tgwsproxy --config /etc/tgwsproxy/config.json --check-config
logread -e tgwsproxy
```

Ошибка `Exec format error` означает неверный CPU/ABI, `Illegal instruction`
— неподдерживаемые инструкции, ошибка bind — занятый порт. Ошибки сертификата
требуют корректных даты/времени и CA-сертификатов. После изменения конфига
перезапустите сервис.
