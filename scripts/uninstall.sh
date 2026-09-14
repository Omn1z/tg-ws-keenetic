#!/bin/sh
# Removes only tgwsproxy files. Shared Python/OpenSSL/CA packages are untouched.
set -eu
SYSTEM=auto
ROOT=
PURGE=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --system|--root)
            [ "$#" -ge 2 ] || { echo "Missing option value" >&2; exit 1; }
            case "$1" in --system) SYSTEM=$2 ;; --root) ROOT=$2 ;; esac
            shift 2 ;;
        --purge) PURGE=1; shift ;;
        --help|-h) echo "Usage: sh uninstall.sh [--system openwrt|entware] [--purge] [--root DIR]"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
if [ -n "$ROOT" ]; then
    case "$ROOT" in /*) ;; *) echo "--root must be absolute" >&2; exit 1 ;; esac
    ROOT=$(cd "$ROOT" && pwd -P)
    [ "$ROOT" != / ] || exit 1
else
    [ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
fi
if [ "$SYSTEM" = auto ]; then
    if [ -f /etc/openwrt_release ] && [ -x /sbin/procd ]; then SYSTEM=openwrt
    elif [ -x /opt/bin/opkg ]; then SYSTEM=entware
    else echo "Specify --system openwrt or --system entware" >&2; exit 1
    fi
fi
case "$SYSTEM" in
    openwrt) BIN=$ROOT/usr/bin/tgwsproxy; CONFIG_DIR=$ROOT/etc/tgwsproxy; INIT=$ROOT/etc/init.d/tgwsproxy; RUN_DIR=$ROOT/var/run ;;
    entware) BIN=$ROOT/opt/bin/tgwsproxy; CONFIG_DIR=$ROOT/opt/etc/tgwsproxy; INIT=$ROOT/opt/etc/init.d/S99tgwsproxy; RUN_DIR=$ROOT/opt/var/run ;;
    *) echo "Unknown system: $SYSTEM" >&2; exit 1 ;;
esac
mkdir -p "$RUN_DIR"
LOCK=$RUN_DIR/tgwsproxy-install.lock
mkdir "$LOCK" 2>/dev/null || { echo "Another install/uninstall is active ($LOCK)" >&2; exit 1; }
printf '%s\n' "$$" > "$LOCK/pid"
trap 'rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null || :' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
if [ -z "$ROOT" ] && [ -x "$INIT" ]; then
    "$INIT" stop
    [ "$SYSTEM" != openwrt ] || "$INIT" disable
fi
rm -f "$BIN" "$INIT" "$RUN_DIR/tgwsproxy.pid"
if [ "$SYSTEM" = entware ]; then
    # The old installer exclusively owned this source directory.
    rm -rf "$ROOT/opt/share/tgwsproxy"
fi
if [ "$PURGE" = 1 ]; then
    rm -rf "$CONFIG_DIR"
    [ "$SYSTEM" != entware ] || rm -rf "$ROOT/opt/var/log/tgwsproxy"
    rm -f "$ROOT/tmp/tgwsproxy.log"
else
    echo "Kept configuration: $CONFIG_DIR/config.json"
fi
echo "tgwsproxy removed. Shared packages were kept."
