#!/bin/sh
# Self-contained release installer. POSIX sh / BusyBox ash; no Python or jq.
set -eu
umask 077
REPO=${TGWS_REPO:-Omn1z/tg-ws-keenetic}
VERSION=latest
SYSTEM=auto
ARCH=
LOCAL_BIN=
SERVICE_DIR=
NO_START=0
ROOT=
WORK=
LOCK=
CHANGED=0
HAD_BIN=0
HAD_INIT=0
NEW_CONFIG=0
OLD_RUNNING=0
say() { printf '[tgwsproxy] %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh install.sh [options]
  --version TAG           Install a specific release (default: latest)
  --system openwrt|entware Override automatic system detection
  --arch ARCH             mips, mipsel, arm, armv7, aarch64, x86_64
  --binary FILE           Install a local binary without downloading
  --service-dir DIR       Init templates for --binary (default: source tree)
  --no-start              Install without starting the service
  --root DIR              Stage files under DIR; requires --no-start
  --help                  Show this help
Existing config.json and shared packages are preserved.
EOF
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--system|--arch|--binary|--service-dir|--root)
            [ "$#" -ge 2 ] || die "Missing value for $1"
            case "$1" in
                --version) VERSION=$2 ;; --system) SYSTEM=$2 ;;
                --arch) ARCH=$2 ;; --binary) LOCAL_BIN=$2 ;;
                --service-dir) SERVICE_DIR=$2 ;; --root) ROOT=$2 ;;
            esac
            shift 2 ;;
        --no-start) NO_START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$REPO" in *[!A-Za-z0-9_./-]*|/*|*..*) die "Invalid repository" ;; esac
case "$VERSION" in *[!A-Za-z0-9_.-]*|'') die "Invalid release tag" ;; esac
if [ -n "$ROOT" ]; then
    [ "$NO_START" = 1 ] || die "--root requires --no-start"
    case "$ROOT" in /*) ;; *) die "--root must be an absolute directory" ;; esac
    [ "$ROOT" != / ] || die "Omit --root to install on the current system"
    mkdir -p "$ROOT"
    ROOT=$(cd "$ROOT" && pwd -P)
else
    [ "$(id -u)" = 0 ] || die "Run as root"
fi
if [ "$SYSTEM" = auto ]; then
    if [ -f /etc/openwrt_release ] && [ -x /sbin/procd ]; then SYSTEM=openwrt
    elif [ -x /opt/bin/opkg ]; then SYSTEM=entware
    else die "OpenWrt/Entware not detected; specify --system openwrt or --system entware"
    fi
fi
case "$SYSTEM" in
    openwrt) BIN_DIR=$ROOT/usr/bin; CONFIG_DIR=$ROOT/etc/tgwsproxy; INIT=$ROOT/etc/init.d/tgwsproxy; TEMPLATE=tgwsproxy; RUN_DIR=$ROOT/var/run ;;
    entware) BIN_DIR=$ROOT/opt/bin; CONFIG_DIR=$ROOT/opt/etc/tgwsproxy; INIT=$ROOT/opt/etc/init.d/S99tgwsproxy; TEMPLATE=S99tgwsproxy; RUN_DIR=$ROOT/opt/var/run ;;
    *) die "Unknown system: $SYSTEM" ;;
esac
BIN=$BIN_DIR/tgwsproxy
CONFIG=$CONFIG_DIR/config.json
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$(dirname "$INIT")" "$RUN_DIR"
LOCK=$RUN_DIR/tgwsproxy-install.lock
mkdir "$LOCK" 2>/dev/null || die "Another install/uninstall is active ($LOCK). Remove a stale lock only after checking its pid file."
printf '%s\n' "$$" > "$LOCK/pid"
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$CHANGED" = 1 ]; then
        say "Installation failed; restoring previous files."
        [ -n "$ROOT" ] || "$INIT" stop >/dev/null 2>&1 || :
        if [ "$HAD_BIN" = 1 ]; then mv -f "$BIN.previous.$$" "$BIN"; else rm -f "$BIN"; fi
        if [ "$HAD_INIT" = 1 ]; then mv -f "$INIT.previous.$$" "$INIT"; else rm -f "$INIT"; fi
        [ "$NEW_CONFIG" = 0 ] || rm -f "$CONFIG"
        if [ "$OLD_RUNNING" = 1 ] && [ -x "$INIT" ]; then
            "$INIT" start || say "Previous service could not restart; inspect its logs."
        fi
    fi
    rm -f "$BIN.new.$$" "$BIN.previous.$$" "$INIT.new.$$" "$INIT.previous.$$"
    [ -z "$WORK" ] || rm -rf "$WORK"
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || :
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
WORK=$(mktemp -d "$BIN_DIR/.tgwsproxy-install.XXXXXX") || die "Cannot create staging directory"
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --retry 2 --connect-timeout 20 --max-time 300 --proto '=https' --tlsv1.2 "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$2" "$1"
    else die "Install curl or wget with HTTPS support and ca-certificates first"
    fi
}
detect_arch() {
    machine=$(uname -m)
    # uname often says 'mips' even on little-endian routers. Read ELF EI_DATA.
    case "$machine" in
        mips*)
            elf=/bin/busybox
            [ -f "$elf" ] || elf=/bin/sh
            endian=$(od -An -tu1 -j5 -N1 "$elf" 2>/dev/null | tr -d ' \n')
            case "$endian" in 1) ARCH=mipsel ;; 2) ARCH=mips ;; *) die "Cannot detect MIPS byte order; use --arch mips or --arch mipsel" ;; esac
            ;;
        aarch64|arm64) ARCH=aarch64 ;;
        armv7*|armv8l) ARCH=armv7 ;;
        armv5*|armv6*|arm) ARCH=arm ;;
        x86_64|amd64) ARCH=x86_64 ;;
        *) die "Unsupported architecture: $machine" ;;
    esac
}
if [ -n "$LOCAL_BIN" ]; then
    [ -f "$LOCAL_BIN" ] || die "Local binary not found: $LOCAL_BIN"
    cp "$LOCAL_BIN" "$WORK/tgwsproxy"
    if [ -z "$SERVICE_DIR" ]; then
        SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
        if [ -d "$SCRIPT_DIR/../etc/init.d" ]; then SERVICE_DIR=$SCRIPT_DIR/../etc/init.d
        else SERVICE_DIR=$SCRIPT_DIR/etc/init.d
        fi
    fi
    cp "$SERVICE_DIR/$TEMPLATE" "$WORK/init" || die "Init template not found; use --service-dir"
else
    [ -n "$ARCH" ] || detect_arch
    case "$ARCH" in mips|mipsel|arm|armv7|aarch64|x86_64) ;; *) die "Unsupported --arch: $ARCH" ;; esac
    if [ "$VERSION" = latest ]; then
        fetch "https://api.github.com/repos/$REPO/releases/latest" "$WORK/release.json" || die "Cannot resolve latest release"
        VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/release.json" | head -n1)
        case "$VERSION" in *[!A-Za-z0-9_.-]*|'') die "Latest release response has no valid tag; try --version vX.Y.Z" ;; esac
    fi
    ASSET=tgwsproxy-$ARCH.tar.gz
    BASE=https://github.com/$REPO/releases/download/$VERSION
    say "Downloading $VERSION for $SYSTEM / $ARCH"
    fetch "$BASE/SHA256SUMS" "$WORK/SHA256SUMS" || die "Release $VERSION has no Rust SHA256SUMS; choose a Rust release"
    fetch "$BASE/$ASSET" "$WORK/$ASSET" || die "Asset $ASSET is unavailable in $VERSION; no files were replaced"
    expected=$(awk -v name="$ASSET" '{sub(/^\*/, "", $2)} $2 == name {print $1}' "$WORK/SHA256SUMS")
    [ "${#expected}" = 64 ] || die "Missing or duplicate SHA256 entry for $ASSET"
    case "$expected" in *[!0-9a-fA-F]*) die "Invalid checksum" ;; esac
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required (BusyBox or coreutils-sha256sum)"
    actual=$(sha256sum "$WORK/$ASSET" | awk '{print $1}')
    [ "$expected" = "$actual" ] || die "Checksum mismatch; refusing installation"
    # Extract only named files; never unpack arbitrary archive paths.
    tar -xzOf "$WORK/$ASSET" tgwsproxy > "$WORK/tgwsproxy" || die "Archive has no tgwsproxy binary"
    tar -xzOf "$WORK/$ASSET" "etc/init.d/$TEMPLATE" > "$WORK/init" || die "Archive has no init script"
fi
chmod 755 "$WORK/tgwsproxy" "$WORK/init"
"$WORK/tgwsproxy" --version || die "Binary cannot execute on this CPU/kernel"
if [ -f "$CONFIG" ]; then
    "$WORK/tgwsproxy" --config "$CONFIG" --check-config || die "Existing config is incompatible; it was left untouched"
else
    "$WORK/tgwsproxy" --config "$WORK/config.json" --init-config || die "Cannot generate config"
    "$WORK/tgwsproxy" --config "$WORK/config.json" --check-config || die "Generated config is invalid"
fi
cp "$WORK/tgwsproxy" "$BIN.new.$$"
cp "$WORK/init" "$INIT.new.$$"
chmod 755 "$BIN.new.$$" "$INIT.new.$$"
if [ -f "$BIN" ]; then cp -p "$BIN" "$BIN.previous.$$"; HAD_BIN=1; fi
if [ -f "$INIT" ]; then cp -p "$INIT" "$INIT.previous.$$"; HAD_INIT=1; fi
if [ -z "$ROOT" ] && [ -x "$INIT" ]; then
    if "$INIT" status >/dev/null 2>&1; then OLD_RUNNING=1; fi
    "$INIT" stop || die "Cannot stop previous service"
fi
CHANGED=1
mv -f "$BIN.new.$$" "$BIN"
mv -f "$INIT.new.$$" "$INIT"
if [ ! -f "$CONFIG" ]; then
    mv "$WORK/config.json" "$CONFIG"
    chmod 600 "$CONFIG"
    NEW_CONFIG=1
fi
if [ "$NO_START" = 0 ]; then
    "$INIT" start || die "Service did not start"
    sleep 3
    "$INIT" status || die "Service exited during startup"
fi
if [ "$SYSTEM" = openwrt ] && [ -z "$ROOT" ]; then
    "$INIT" enable || die "Cannot enable boot startup"
fi
CHANGED=0
say "Installed: $BIN"
say "Configuration preserved at: $CONFIG"
say "Service: $INIT {start|stop|restart|status}"
say "Default web panel: http://<router-ip>:1434/ (set its password in the panel)"
say "Telegram link: $BIN --config $CONFIG --print-link"
