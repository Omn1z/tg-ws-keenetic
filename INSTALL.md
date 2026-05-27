# Подробная установка на Keenetic (Entware)

Пошагово, с диагностикой типовых проблем.

## 1. Подготовка роутера

### 1.1. Entware

Если Entware ещё нет — установите по официальной инструкции
[help.keenetic.com](https://help.keenetic.com/hc/ru/articles/360021214160).
Кратко:

1. В веб-интерфейсе роутера: **Системные настройки → Параметры системы →
   Изменить набор компонентов**.
2. Включите модули **«OPKG»** и **«SFTP-сервер»** (последний — чтобы
   удобно копировать файлы).
3. Подключите USB-накопитель (минимум 256 MB свободного места).
4. **Приложения → USB-накопители и принтеры → ваш диск → ⚙ →
   Установить Entware**.
5. После установки откройте SSH:

   ```sh
   ssh root@192.168.1.1
   ```

Проверка:

```sh
opkg --version
# Выведет: opkg version 0.x.x  -> ok
```

### 1.2. Зависимости

```sh
opkg update
opkg install python3 python3-cryptography git
```

> `python3-cryptography` тянет нативный C-модуль с AES — на ARM она
> работает быстро. Без неё не запустится.

Проверка:

```sh
python3 -c "import cryptography; print(cryptography.__version__)"
# Должна вывести версию, например: 41.0.3
```

## 2. Получение кода

Вариант А — клонировать репозиторий:

```sh
cd /opt/tmp
git clone https://github.com/<your-fork>/tg-ws-keenetic.git
cd tg-ws-keenetic
```

Вариант Б — скачать ZIP-архив через SFTP в `/opt/tmp/` и распаковать:

```sh
cd /opt/tmp
unzip tg-ws-keenetic.zip
cd tg-ws-keenetic
```

## 3. Установка

```sh
sh scripts/install.sh
```

Что произойдёт:

1. Проверится наличие `python3` и `python3-cryptography`.
2. Создадутся каталоги:
   - `/opt/share/tgwsproxy/` (код)
   - `/opt/etc/tgwsproxy/` (конфиг)
   - `/opt/var/log/tgwsproxy/` (логи)
   - `/opt/var/run/` (PID-файл)
3. Скопируются `tgwsproxy/` и `webui/` в `/opt/share/tgwsproxy/`.
4. Установится init-скрипт `/opt/etc/init.d/S99tgwsproxy`.
5. Сгенерируется `config.json` с уникальным secret (если ещё нет).
6. Запустится сервис.

## 4. Первая проверка

```sh
/opt/etc/init.d/S99tgwsproxy status
# tgwsproxy is running (PID ....)
```

Из браузера на устройстве в LAN:

```
http://192.168.1.1:1434/
```

Должна открыться страница со статусом **online**, ссылкой `tg://proxy?...`
и формой настроек.

В Telegram:

1. Нажмите **«Скопировать»** в web UI.
2. Откройте Telegram → отправьте ссылку в «Избранное».
3. Кликните по ссылке → подтвердите подключение.

## 5. Диагностика

### Сервис не стартует

```sh
tail -n 50 /opt/var/log/tgwsproxy/stdout.log
tail -n 50 /opt/var/log/tgwsproxy/tgwsproxy.log
```

Типовые ошибки:

| Сообщение | Что значит | Что делать |
|---|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | пакет не установлен | `opkg install python3-cryptography` |
| `OSError: [Errno 98] Address already in use` | порт 1433/1434 занят | измените порт в `config.json` |
| `Cannot persist config to ...: Read-only file system` | не примонтирован `/opt` | проверьте USB-накопитель |

### Telegram не подключается

1. На роутере: `netstat -lntp | grep python3` — должно быть две строки
   с портами `1433` и `1434`.
2. С устройства в LAN: `telnet 192.168.1.1 1433` — должно открыть
   соединение (не отказать).
3. Если порты слушаются, но Telegram молчит — проверьте, что в
   `config.json` правильный secret и DC IP не блокируется провайдером.

### Сильно медленно / лагает

- Поднимите `pool_size` до 8.
- Увеличьте `buffer_size` до `524288` (512 KB).
- Включите Fake TLS (`fake_tls_domain = "your.domain"`) — иногда
  помогает обойти DPI.

## 6. Обновление

```sh
cd /opt/tmp/tg-ws-keenetic
git pull
sh scripts/install.sh
```

`config.json` сохранится (скрипт не перезаписывает существующий конфиг).

## 7. Удаление

```sh
cd /opt/tmp/tg-ws-keenetic
sh scripts/uninstall.sh           # сервис уйдёт, конфиг останется
sh scripts/uninstall.sh --purge   # снести вообще всё
```

## 8. Бэкап настроек

Конфиг — один JSON-файл:

```sh
cat /opt/etc/tgwsproxy/config.json > /opt/share/tgwsproxy-config.backup.json
```

Восстановить:

```sh
cp /opt/share/tgwsproxy-config.backup.json /opt/etc/tgwsproxy/config.json
/opt/etc/init.d/S99tgwsproxy restart
```
