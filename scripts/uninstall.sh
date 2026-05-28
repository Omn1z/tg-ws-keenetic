#!/bin/sh
# Remove tgwsproxy from Entware.
#
# By default keeps the config and logs (so a later reinstall picks up your
# settings). Flags let you purge those, and optionally remove the opkg
# Python packages that were installed for tgwsproxy.

set -e

INSTALL_ROOT=/opt/share/tgwsproxy
CONFIG_DIR=/opt/etc/tgwsproxy
INIT_SCRIPT=/opt/etc/init.d/S99tgwsproxy
LOG_DIR=/opt/var/log/tgwsproxy
PIDFILE=/opt/var/run/tgwsproxy.pid
STAGING_GLOB=/opt/tmp/tgwsproxy-update-*

REMOVE_CONFIG=no
REMOVE_LOGS=no
REMOVE_PACKAGES=no

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)    REMOVE_CONFIG=yes; REMOVE_LOGS=yes ;;
        --logs)     REMOVE_LOGS=yes ;;
        --config)   REMOVE_CONFIG=yes ;;
        --packages) REMOVE_PACKAGES=yes ;;
        -h|--help)
            cat <<EOF
Usage: $0 [options]
  (default)   Stop service, remove code + init script, keep config and logs
  --config    Also remove the config directory ($CONFIG_DIR)
  --logs      Also remove the log directory ($LOG_DIR)
  --purge     Remove code, init, config and logs (everything tgwsproxy owns)
  --packages  Also 'opkg remove' python3-cryptography and python3
              (WARNING: other Entware tools may depend on python3)
EOF
            exit 0
            ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

echo "==> Stopping tgwsproxy service"
if [ -x "$INIT_SCRIPT" ]; then
    "$INIT_SCRIPT" stop || true
fi

# Belt-and-suspenders: kill any stray process even if the pidfile is stale.
STRAYS=$(ps w 2>/dev/null | grep '[t]gwsproxy' | awk '{print $1}')
if [ -n "$STRAYS" ]; then
    echo "    killing leftover processes: $STRAYS"
    for pid in $STRAYS; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 2
    for pid in $STRAYS; do
        kill -KILL "$pid" 2>/dev/null || true
    done
fi
rm -f "$PIDFILE"

echo "==> Removing init script"
rm -f "$INIT_SCRIPT"

echo "==> Removing code at $INSTALL_ROOT"
rm -rf "$INSTALL_ROOT"

echo "==> Cleaning update staging dirs"
# 'rm -rf glob' is safe here: if nothing matches, the literal glob path
# simply doesn't exist and rm -f stays quiet.
for d in $STAGING_GLOB; do
    [ -e "$d" ] && rm -rf "$d"
done
echo "    done"

if [ "$REMOVE_CONFIG" = yes ]; then
    echo "==> Removing config at $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
else
    echo "==> Keeping config at $CONFIG_DIR (use --config or --purge to remove)"
fi

if [ "$REMOVE_LOGS" = yes ]; then
    echo "==> Removing logs at $LOG_DIR"
    rm -rf "$LOG_DIR"
else
    echo "==> Keeping logs at $LOG_DIR (use --logs or --purge to remove)"
fi

if [ "$REMOVE_PACKAGES" = yes ]; then
    echo "==> Removing the Python stack (python3-* + libpython3)"
    # The python3 metapackage alone leaves python3-light and ~25 submodules
    # behind, so enumerate every installed python3-* package and drop them
    # together. Nothing outside the Python ecosystem depends on these.
    PYPKGS=$(opkg list-installed 2>/dev/null | awk '/^python3/ {print $1}')
    if [ -n "$PYPKGS" ]; then
        echo "    packages: $(echo $PYPKGS | tr '\n' ' ')libpython3"
        # shellcheck disable=SC2086
        opkg remove $PYPKGS libpython3 \
            --force-removal-of-dependent-packages 2>&1 | sed 's/^/    /' || \
            echo "    (some packages could not be removed)"
    else
        echo "    no python3 packages installed"
    fi
    echo "    NOTE: shared C libs pulled in as deps (libffi, libopenssl,"
    echo "    zlib, etc.) are left in place — they may be used by other"
    echo "    Entware tools. Remove manually if you are sure."
else
    echo "==> Keeping python3 / python3-cryptography (use --packages to remove)"
fi

echo
echo "tgwsproxy removed."
if [ "$REMOVE_CONFIG" != yes ]; then
    echo "  Config kept at:  $CONFIG_DIR/config.json"
fi
if [ "$REMOVE_LOGS" != yes ]; then
    echo "  Logs kept at:    $LOG_DIR/"
fi
