# TG WS Proxy · Rust для OpenWrt / Keenetic

## Инструкция по установке

Через SSH **от root** на OpenWrt или Keenetic с уже установленным Entware:

```sh
wget -O /tmp/tgws-install.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/install.sh && sh /tmp/tgws-install.sh
```

**Для этой команды нужен опубликованный Rust-релиз с `install.sh` и бинарными
архивами.** Пока изменения находятся только в ветке `rust`, старый Python-релиз
этих файлов не содержит. Порядок выпуска — ниже; публикация не происходит при
обычном коммите или пуше ветки.

После установки: **`http://<IP-роутера>:1434/`** → **«Открыть Telegram»**.
Прокси слушает **1433/TCP**. Используйте LAN-адрес роутера. Проброс портов в WAN
не нужен. Установщик выбирает архитектуру, сверяет SHA-256, создаёт случайный
секрет и подключает автозапуск. Нужны `wget` с HTTPS и CA-сертификаты.

## Инструкция по обновлению

Повторно загрузите установщик последнего релиза и запустите его по SSH от root:

```sh
wget -O /tmp/tgws-install.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/install.sh && sh /tmp/tgws-install.sh
```

Настройки, секрет и пароль панели сохраняются. При ошибке запуска установщик
восстанавливает прежние файлы сервиса. Как и установка, эта команда требует
опубликованного Rust-релиза.

## Инструкция по удалению

Выполните по SSH от root; настройки сохранятся для повторной установки:

```sh
wget -O /tmp/tgws-uninstall.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/uninstall.sh && sh /tmp/tgws-uninstall.sh
```

Для полного удаления **вместе с настройками, секретом и журналом**:

```sh
wget -O /tmp/tgws-uninstall.sh https://github.com/Omn1z/tg-ws-keenetic/releases/latest/download/uninstall.sh && sh /tmp/tgws-uninstall.sh --purge
```

Скрипт `uninstall.sh` появится по этой ссылке с первым Rust-релизом.
Python и другие общие пакеты не удаляются. Если установили из рабочей копии,
используйте её `sh scripts/uninstall.sh` (полное удаление: добавьте `--purge`).

## О проекте

MTProto → WebSocket прокси Telegram **на самом роутере**. Один нативный бинарник
со встроенной небольшой веб-панелью. Не нужны Python, Node.js, Git или компилятор
на роутере. Ветка `rust` заменяет прежнюю реализацию на Python.

Сетевой протокол перенесён из [Flowseal/tg-ws-proxy v1.10.2](https://github.com/Flowseal/tg-ws-proxy/tree/v1.10.2),
коммит `f200e33fd283143a9f101d62aaf9d8c1468a23fe` от 7 сентября 2026 года.
На 14 сентября это последний релиз и HEAD upstream. Для сверки также использованы
наработки [NFQWS2 Strategy Selector](https://github.com/Omn1z/nfqws2-keenetic-strategy-selector).
Это самостоятельный сервис: NFQWS2 для его запуска не требуется.

| Система | Бинарник | Конфигурация | Сервис |
|---|---|---|---|
| Keenetic / Entware | `/opt/bin/tgwsproxy` | `/opt/etc/tgwsproxy/config.json` | `/opt/etc/init.d/S99tgwsproxy` |
| OpenWrt | `/usr/bin/tgwsproxy` | `/etc/tgwsproxy/config.json` | `/etc/init.d/tgwsproxy` (procd) |

Если на OpenWrt одновременно установлен Entware, укажите систему явно:
`sh /tmp/tgws-install.sh --system openwrt` или `--system entware`.
Подробности, установка выбранной версии, локального бинарника и удаление —
[INSTALL.md](INSTALL.md).

Проверено на Keenetic ARM64: установка и перезапуск, встроенная панель и
настоящий обмен MTProto с Telegram DC2/DC4 через WebSocket. Бинарник с TLS —
5,21 МиБ, RSS после двух коротких проверок без активных клиентов — 6,75 МиБ.
Условия измерения и ограничения — в [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Что изменилось

- **Rust и один асинхронный цикл Tokio.** Отдельного процесса для панели нет;
  DNS использует не более двух вспомогательных потоков Tokio со стеком 256 КиБ;
  неактивные потоки освобождаются через 10 секунд.
- **Ограниченная память на поток.** Два буфера по 16 КиБ по умолчанию; MTProto
  передаётся частями без накопления полного сообщения, даже для больших медиа.
  У TLS, Fake TLS, ОС и задач есть дополнительные расходы памяти.
- **AES-256-CTR на месте.** Обфускация снимается и накладывается в одном буфере.
  Содержимое MTProto остаётся зашифрованным Telegram. Третий AES-проход для
  определения границ пакетов не нужен.
- **Пул по требованию.** По умолчанию `pool_size=0`: нет заранее открытых WS.
  Можно включить до четырёх прогретых соединений на каждый DC/тип трафика.
- **Лимит 64 клиента**, ограниченные HTTP/WS-заголовки, таймауты и отмена задач
  при перезапуске. Счётчики трафика 64-битные и работают на 32-битном MIPS.
- **Небольшая панель**: ссылка Telegram, трафик, настройки, секрет, пароль и
  перезапуск. Без CDN, шрифтов, графических библиотек, npm и фоновой проверки
  обновлений GitHub на каждом открытии. Опрос раз в 5 секунд, только в видимой вкладке.
- **Актуальные маршруты**: media DC, автоматические/принудительные тестовые DC,
  `/apiws_test`, CF proxy/Worker списки, резервный TCP, SNI fronting, обновление
  резервных доменов раз в час, восстановление пула и задержки повторных попыток.
- **Fake TLS**, PROXY protocol v1, WebSocket continuation, ping/pong,
  проверка HTTP Upgrade и потоковое маскирование кадров.

Границы переноса и отличия от upstream описаны в [docs/UPSTREAM.md](docs/UPSTREAM.md).

## Слабые роутеры и архитектуры

Релизный workflow собирает статические musl-бинарники:

| Архив | Целевая архитектура |
|---|---|
| `tgwsproxy-mipsel.tar.gz` | MIPS32r2, little endian, soft float — многие Keenetic |
| `tgwsproxy-mips.tar.gz` | MIPS32r2, big endian, soft float — OpenWrt |
| `tgwsproxy-arm.tar.gz` | ARMv5TE и новее, soft float |
| `tgwsproxy-armv7.tar.gz` | ARMv7, soft float |
| `tgwsproxy-aarch64.tar.gz` | ARM64 |
| `tgwsproxy-x86_64.tar.gz` | x86-64 |

**MIPS32r1 и устройства без Linux/Entware не поддерживаются.** Одинаковое имя
архитектуры не гарантирует совместимость со всеми старыми ядрами. Перед публикацией
workflow проверяет ELF на отсутствие динамических зависимостей, запускает бинарник
под QEMU и проверяет конфигурацию. Это не заменяет проверку на физическом роутере.

На устройствах с небольшим объёмом RAM начните с:

```json
{"buffer_size":4096,"pool_size":0,"max_connections":16}
```

Это фрагмент настроек: измените поля существующего конфига или задайте их в панели.
Не заменяйте весь файл этим фрагментом — в нём хранится секрет.
Больший буфер и пул иногда ускоряют передачу/подключение, но расходуют больше RAM.
Размер Linux-бинарника, RSS и скорость зависят от архитектуры, TLS и нагрузки;
цифры с Windows нельзя переносить на MIPS. [Как измерять](docs/PERFORMANCE.md).

## Настройка и управление

```sh
# Entware
/opt/etc/init.d/S99tgwsproxy restart
/opt/etc/init.d/S99tgwsproxy status

# OpenWrt
/etc/init.d/tgwsproxy restart
/etc/init.d/tgwsproxy status
logread -e tgwsproxy
```

Панель доступна из LAN без пароля при первой установке. В разделе «Доступ к
панели» можно задать логин/пароль. Для удалённого доступа используйте SSH-туннель;
HTTP Basic Auth не шифрует соединение. POST-запросы защищены CSRF-токеном;
панель принимает Host с IP роутера или явно заданным `link_host`.

Сохранение перезапускает прокси и переподключает клиентов. Секрет остаётся прежним,
пока вы не нажмёте «Сменить секрет». `web_host`/`web_port` меняются в JSON-файле
с перезапуском сервиса. `SIGHUP` перечитывает остальные настройки.

Основные поля JSON:

| Поле | По умолчанию | Назначение |
|---|---|---|
| `host`, `port` | `0.0.0.0`, `1433` | MTProto listener |
| `web_host`, `web_port` | `0.0.0.0`, `1434` | Панель |
| `secret` | случайные 16 байт в hex | Сохраняется при установке/обновлении |
| `buffer_size` | `16384` | Буфер направления, 4096–262144 байт |
| `pool_size` | `0` | Прогретые WS на DC/тип, 0–4 |
| `max_connections` | `64` | Максимум принятых клиентов, 1–1024 |
| `connect_timeout_secs` | `10` | Таймаут подключения к одному адресу |
| `idle_timeout_secs` | `300` | Таймаут отсутствия трафика |
| `dc_redirects` | DC2/DC4 → `149.154.167.220` | IP для прямого WS; `{}` включает только fallback |
| `cfproxy` | `true` | Использовать резервные CF-домены |
| `cfproxy_user_domains` | `[]` | Свои CF-домены; пусто — встроенный список |
| `cfproxy_worker_domains` | `[]` | Свои Worker-домены |
| `domain_refresh` | `true` | Ежечасное обновление встроенного списка |
| `sni_fronting` | `false` | Альтернативный SNI при сбоях прямого WS |
| `force_test_dc` | `false` | Принудительный режим тестовых DC |
| `fake_tls_domain` | `""` | Маскировка Fake TLS, пусто — выключена |
| `proxy_protocol` | `false` | Ожидать PROXY v1 перед handshake |
| `link_host` | `""` | Имя/IP в tg://, пусто — адрес открытой панели |
| `web_user`, `web_password` | `admin`, `""` | HTTP Basic Auth панели |
| `verbose` | `false` | Диагностика в stderr/системном журнале |

Старые одиночные `cfproxy_user_domain`/`cfproxy_worker_domain` преобразуются в
списки. Явный пустой список имеет приоритет. Старые secret, порты и DC-редиректы
сохраняются. Поля Python-логирования и самообновления остаются в JSON для
совместимости, но Rust их не исполняет: журналом управляет сервис, обновлением —
release installer. Некорректный файл даёт ошибку, а не новый случайный secret.

## Сборка и выпуск

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked

# Без панели; vendored TLS сохраняется
cargo build --release --locked --no-default-features --features vendored-tls

# Альтернативный профиль для сравнения скорости и размера
cargo build --profile speed --locked
```

На Linux для нативной сборки нужны Rust, C toolchain, make и Perl для vendored
OpenSSL; `--no-default-features --features webui` позволяет использовать системный
OpenSSL. Статические релизы не требуют OpenSSL-пакета на роутере, но проверяемым
TLS-подключениям к CF/GitHub нужен системный набор CA-сертификатов.

Релизный профиль: `opt-level=z`, fat LTO, один codegen unit, `panic=abort`, strip;
AES/CTR/SHA-256 сохраняют `opt-level=3`. TLS использует OpenSSL на Linux: это
позволяет собирать один и тот же код для MIPS и ARM. ARM64 автоматически использует
аппаратное AES, когда его поддерживает процессор; для остальных ARM64 остаётся
программная реализация. ARM64 собирается и тестируется на родном Linux runner,
остальные архитектуры — через cross/QEMU. Инструкции и закреплённые версии
инструментов — в `.github/workflows/release.yml`.

После успешной проверки всех архитектур обновите версию в `Cargo.toml` и
`Cargo.lock`, создайте тег `v2.0.0` (или следующую версию) на проверенном коммите
ветки `rust` и отправьте его в GitHub. Workflow публикует архивы, установщик и
`SHA256SUMS` только для тега; `workflow_dispatch` позволяет сначала проверить сборки.

CLI: `--config PATH`, `--init-config`, `--check-config`, `--print-link`,
`--no-webui`, `--version`. Обычный запуск работает в foreground.

## Лицензия

MIT. [LICENSE](LICENSE), [LICENSE.upstream](LICENSE.upstream),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
