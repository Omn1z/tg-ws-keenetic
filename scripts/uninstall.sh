#!/bin/sh
# Remove tgwsproxy from Entware. Keeps the config file by default.

set -e

INSTALL_ROOT=/opt/share/tgwsproxy
CONFIG_DIR=/opt/etc/tgwsproxy
INIT_SCRIPT=/opt/etc/init.d/S99tgwsproxy
LOG_DIR=/opt/var/log/tgwsproxy
PIDFILE=/opt/var/run/tgwsproxy.pid

REMOVE_CONFIG=no
REMOVE_LOGS=no

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)  REMOVE_CONFIG=yes; REMOVE_LOGS=yes ;;
        --logs)   REMOVE_LOGS=yes ;;
        --config) REMOVE_CONFIG=yes ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--purge | --logs | --config]
  (default)  Stop service, remove code and init script, keep config and logs
  --logs     Also remove the log directory
  --config   Also remove the config directory
  --purge    Remove everything (code, init, config, logs)
EOF
            exit 0
            ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

echo "Stopping tgwsproxy..."
if [ -x "$INIT_SCRIPT" ]; then
    "$INIT_SCRIPT" stop || true
fi
rm -f "$PIDFILE"

echo "Removing init script..."
rm -f "$INIT_SCRIPT"

echo "Removing code at $INSTALL_ROOT..."
rm -rf "$INSTALL_ROOT"

if [ "$REMOVE_CONFIG" = yes ]; then
    echo "Removing config at $CONFIG_DIR..."
    rm -rf "$CONFIG_DIR"
else
    echo "Keeping config at $CONFIG_DIR (use --config or --purge to remove)."
fi

if [ "$REMOVE_LOGS" = yes ]; then
    echo "Removing logs at $LOG_DIR..."
    rm -rf "$LOG_DIR"
else
    echo "Keeping logs at $LOG_DIR (use --logs or --purge to remove)."
fi

echo "Done."
