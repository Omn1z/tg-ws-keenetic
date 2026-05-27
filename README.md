# tgwsproxy для Keenetic Entware

Telegram MTProto → WebSocket прокси, который запускается **прямо на роутере**
(Keenetic с Entware, ARM/MIPS). Никаких ПК, никаких облачных VPS — Telegram
с любого устройства в LAN ходит через `<router-ip>:1433`, а настройка
делается из браузера на `http://<router-ip>:1434/`.

Форк-переписывание [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy):
тот же протокол, та же crypto-схема, но без GUI/tray, без Windows-специфики,
с раздельной структурой модулей и web UI вместо системного трея.

## Что в комплекте

- `tgwsproxy/` — Python-пакет (≈ 1300 строк, разбито на 14 модулей)
- `webui/` — статический фронтенд (HTML + CSS + JS, без сборщиков)
- `etc/init.d/S99tgwsproxy` — init-скрипт Entware
- `scripts/install.sh`, `scripts/uninstall.sh` — установка/удаление
- `etc/tgwsproxy/config.json.example` — пример конфига

## Что важно знать

| Параметр | Значение по умолчанию | Комментарий |
|---|---|---|
| Порт прокси | `1433` | привязан к `0.0.0.0`, доступен с LAN |
| Порт веб-UI | `1434` | привязан к `0.0.0.0`, можно ограничить логином/паролем |
| Конфиг | `/opt/etc/tgwsproxy/config.json` | редактируется через web UI |
| Логи | `/opt/var/log/tgwsproxy/` | с авто-ротацией |
| Код | `/opt/share/tgwsproxy/` | обновляется через `scripts/install.sh` |
| Зависимости | `python3`, `python3-cryptography` | оба ставятся через `opkg` |

## Установка

На роутере с Entware (через SSH):

```sh
# 1) Зависимости (если ещё не стоят)
opkg update
opkg install python3 python3-cryptography git

# 2) Получить код
cd /opt/tmp
git clone https://github.com/<your-fork>/tg-ws-keenetic.git
cd tg-ws-keenetic

# 3) Установить
sh scripts/install.sh
```

Скрипт:

1. Проверит, что Python и `cryptography` установлены.
2. Скопирует код в `/opt/share/tgwsproxy/`.
3. Положит init-скрипт в `/opt/etc/init.d/S99tgwsproxy`.
4. Сгенерирует дефолтный `config.json` (с уникальным secret), если его нет.
5. Запустит сервис.

После установки откройте `http://<router-ip>:1434/` — увидите статус,
ссылку для Telegram и форму настроек.

## Управление сервисом

```sh
/opt/etc/init.d/S99tgwsproxy start
/opt/etc/init.d/S99tgwsproxy stop
/opt/etc/init.d/S99tgwsproxy restart
/opt/etc/init.d/S99tgwsproxy status
```

В Keenetic OS такие скрипты в `/opt/etc/init.d/` подхватываются
автоматически при старте Entware — отдельно настраивать autostart не нужно.

## Подключение Telegram

В вебе кнопка **«Скопировать»** даёт ссылку вида:

    tg://proxy?server=192.168.1.1&port=1433&secret=dd<32-hex>

Откройте её в Telegram (например, отправьте в «Избранное» и тапните) —
прокси добавится автоматически.

Ручная настройка:

- **Тип**: MTProto
- **Сервер**: IP роутера в LAN (часто `192.168.1.1`)
- **Порт**: `1433` (или ваш)
- **Secret**: из вебинтерфейса

## Архитектура

```
[ Telegram ] ──tcp──> [ Keenetic :1433 ]
                          ├─ MTProto handshake auth (HMAC + AES-CTR)
                          ├─ Re-encryption (client_key ↔ upstream_key)
                          └─ WSS to kws*.web.telegram.org:443
                                  ↑ pool с warmup
                                  ↓ fallback:
                                     1. Cloudflare Worker (опц.)
                                     2. CF-proxied домен (опц.)
                                     3. прямой TCP на IP DC
```

Веб-UI на :1434 — отдельный asyncio HTTP-сервер в том же процессе.
Сохранение конфига перезапускает только сервер прокси, UI остаётся
доступным.

## Безопасность веб-интерфейса

По умолчанию UI слушает `0.0.0.0:1434` и **без пароля**. Это нормально
для домашней сети, но если вы пробросили порт наружу — обязательно
заполните `web_user`/`web_password` (Basic Auth).

Ещё надёжнее — оставить `web_host = 127.0.0.1` и ходить в UI через
SSH-туннель:

```sh
ssh -L 1434:127.0.0.1:1434 root@<router>
```

## Конфигурация — все поля

| Поле | Тип | Описание |
|---|---|---|
| `host`, `port` | str, int | На каком адресе/порту слушать MTProto-клиентов |
| `web_host`, `web_port` | str, int | Адрес/порт веб-UI |
| `secret` | hex(32) | MTProto-секрет, генерируется автоматически |
| `dc_redirects` | dict | DC → IP, куда подключаемся для WS |
| `buffer_size` | int | Размер SO_RCVBUF/SO_SNDBUF (для медленного ARM 64-256 KB) |
| `pool_size` | int | Сколько WS-коннектов держать «горячими» на каждый DC |
| `cfproxy` | bool | Пытаться ли CF-проксированные домены при сбое прямого WS |
| `cfproxy_user_domain` | str | Свой CF-домен (перебивает встроенный пул) |
| `cfproxy_worker_domain` | str | Свой CF Worker URL (пробуется первым) |
| `fake_tls_domain` | str | SNI для Fake-TLS маскировки; пусто = выкл. |
| `proxy_protocol` | bool | Принимать PROXY protocol v1 (если за nginx/haproxy) |
| `log_file`, `log_max_mb`, `log_backups` | | Ротация логов |
| `verbose` | bool | DEBUG-логи (шумно) |
| `web_user`, `web_password` | str | Basic Auth для веб-UI; пустой пароль = выкл. |

## Удаление

```sh
sh scripts/uninstall.sh           # снять сервис, оставить конфиг и логи
sh scripts/uninstall.sh --purge   # снести всё
```

## Совместимость

- **Архитектура**: ARM (тестировано на Keenetic с Cortex-A53), MIPS теоретически
  тоже работает, но AES-CTR через `python3-cryptography` будет заметно медленнее.
- **Минимум RAM**: ≈ 30 MB на процесс при `pool_size=4`.
- **Python**: 3.9+ (Entware на момент написания даёт 3.11).

## CLI

```
python3 -m tgwsproxy --help
python3 -m tgwsproxy --init-config           # создать config.json
python3 -m tgwsproxy --print-link            # вывести tg://proxy ссылку
python3 -m tgwsproxy --no-webui              # только прокси, без UI
python3 -m tgwsproxy --config /path.json
```

## Лицензия

MIT. Совместима с лицензией оригинального проекта Flowseal/tg-ws-proxy.
