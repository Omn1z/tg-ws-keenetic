#!/bin/sh
# Detached by the Rust backend. All downloads/checksums are already complete.
# Arguments: STATE_DIR SYSTEM TAG PAYLOAD_DIR
set -eu
umask 077

[ "$#" = 4 ] || { echo 'Usage: update-worker.sh STATE_DIR SYSTEM TAG PAYLOAD_DIR' >&2; exit 2; }
STATE_DIR=$1
SYSTEM=$2
TAG=$3
PAYLOAD_DIR=$4
case "$SYSTEM" in
    entware) BIN_DIR=/opt/bin; EXPECTED_STATE=/opt/var/run/tgwsproxy-update; TEMPLATE=S99tgwsproxy ;;
    openwrt) BIN_DIR=/usr/bin; EXPECTED_STATE=/var/run/tgwsproxy-update; TEMPLATE=tgwsproxy ;;
    *) echo 'Unsupported update system' >&2; exit 2 ;;
esac
[ "$STATE_DIR" = "$EXPECTED_STATE" ] && [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || {
    echo 'Invalid update state directory' >&2; exit 2;
}
case "$TAG" in ''|*[!A-Za-z0-9_.-]*) echo 'Invalid update tag' >&2; exit 2 ;; esac

LOCK=$STATE_DIR/worker.lock
# Do not change the other worker's stage, pid, log, lock, or payload.
mkdir "$LOCK" 2>/dev/null || { echo 'Another update worker is active' >&2; exit 1; }
CLEAN_PAYLOAD=0
COMPLETE=0

write_state() {
    printf '%s\n' "$2" > "$STATE_DIR/$1.$$"
    mv -f "$STATE_DIR/$1.$$" "$STATE_DIR/$1"
}
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    # Cleanup must continue even if the filesystem became read-only or full.
    set +e
    if [ "$COMPLETE" != 1 ]; then
        write_state error.txt 'Update failed; see the updater log.'
        write_state stage error
        [ "$result" != 0 ] || result=1
    fi
    if [ "$CLEAN_PAYLOAD" = 1 ]; then
        # This canonical, direct child of BIN_DIR was validated before use.
        rm -rf "$PAYLOAD_DIR"
    fi
    rm -f "$STATE_DIR/stage.$$" "$STATE_DIR/target.$$" "$STATE_DIR/pid.$$" "$STATE_DIR/error.txt.$$" "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || :
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
printf '%s\n' "$$" > "$LOCK/pid"
write_state target "$TAG"
write_state pid "$$"
write_state stage installing
rm -f "$STATE_DIR/error.txt"

fail() { printf '%s\n' "$1" >> "$STATE_DIR/log"; exit 1; }
# Reject relative paths, traversal, nested paths, symlinks, and another package's
# directory. Cleanup is enabled only after all ownership-boundary checks pass.
case "$PAYLOAD_DIR" in "$BIN_DIR"/.tgwsproxy-update.*) ;; *) fail 'Invalid update payload path' ;; esac
suffix=${PAYLOAD_DIR#"$BIN_DIR"/.tgwsproxy-update.}
case "$suffix" in ''|*/*) fail 'Invalid update payload directory name' ;; esac
[ -d "$PAYLOAD_DIR" ] && [ ! -L "$PAYLOAD_DIR" ] || fail 'Update payload is not a private directory'
CANONICAL_BIN=$(CDPATH='' cd -- "$BIN_DIR" && pwd -P) || fail 'Cannot resolve executable directory'
CANONICAL_PAYLOAD=$(CDPATH='' cd -- "$PAYLOAD_DIR" && pwd -P) || fail 'Cannot resolve payload directory'
[ "${CANONICAL_PAYLOAD%/*}" = "$CANONICAL_BIN" ] || fail 'Update payload escaped executable directory'
PAYLOAD_DIR=$CANONICAL_PAYLOAD
CLEAN_PAYLOAD=1
for file in "$PAYLOAD_DIR/tgwsproxy" "$PAYLOAD_DIR/install.sh" "$PAYLOAD_DIR/etc/init.d/$TEMPLATE"; do
    [ -f "$file" ] && [ ! -L "$file" ] || fail 'Update payload is incomplete or contains symlinks'
done
[ ! -L "$PAYLOAD_DIR/etc" ] && [ ! -L "$PAYLOAD_DIR/etc/init.d" ] || fail 'Update service directory is a symlink'

# The trusted installer owns replacement, config preflight, startup and rollback.
# Its single invocation includes the restart, so this stage covers that interval.
# Let the accepted HTTP response reach the browser before stopping its server.
sleep 1
write_state stage restarting
if ! sh "$PAYLOAD_DIR/install.sh" --system "$SYSTEM" --binary "$PAYLOAD_DIR/tgwsproxy" \
    --service-dir "$PAYLOAD_DIR/etc/init.d" >> "$STATE_DIR/log" 2>&1; then
    fail 'Installer failed; its rollback details are above.'
fi
write_state stage complete
COMPLETE=1
