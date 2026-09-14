#!/bin/sh
# Offline integration tests of real installer transitions; no root/network.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/release/etc/init.d"
cat > "$TEST_DIR/mock-proxy" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --version ]; then echo 'tgwsproxy 2.0.0'; exit 0; fi
[ "$1" = --config ] || exit 2
case "$3" in
    --init-config) printf '{"secret":"keep-me","port":1433}\n' > "$2" ;;
    --check-config) grep -q '"secret"' "$2" ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$TEST_DIR/mock-proxy"
install_local() {
    sh "$HERE/install.sh" --system "$1" --root "$TEST_DIR/$1" --no-start --binary "$TEST_DIR/mock-proxy" > "$TEST_DIR/output" 2>&1
}
for system in entware openwrt; do
    install_local "$system" || { cat "$TEST_DIR/output"; fail 'initial install'; }
    prefix=$TEST_DIR/$system
    if [ "$system" = entware ]; then prefix=$prefix/opt; binary=$prefix/bin/tgwsproxy
    else binary=$prefix/usr/bin/tgwsproxy
    fi
    config=$prefix/etc/tgwsproxy/config.json
    [ -f "$binary" ] && [ -f "$config" ] || fail 'missing installed files'
    printf '{"secret":"previous-python-secret","unknown_legacy_field":true}\n' > "$config"
    cp "$config" "$TEST_DIR/config-before"
    install_local "$system" || fail 'upgrade'
    cmp "$config" "$TEST_DIR/config-before" || fail 'upgrade changed config'
    cp "$binary" "$TEST_DIR/binary-before"
    printf 'INVALID\n' > "$config"
    if install_local "$system"; then fail 'accepted invalid existing config'; fi
    cmp "$binary" "$TEST_DIR/binary-before" || fail 'bad config replaced binary'
    printf '{"secret":"previous-python-secret"}\n' > "$config"
    if [ "$system" = entware ]; then run=$prefix/var/run; else run=$TEST_DIR/$system/var/run; fi
    mkdir "$run/tgwsproxy-install.lock"
    if install_local "$system"; then fail 'ignored lock'; fi
    rmdir "$run/tgwsproxy-install.lock"
    sh "$HERE/uninstall.sh" --system "$system" --root "$TEST_DIR/$system" >/dev/null
    [ ! -f "$binary" ] && [ -f "$config" ] || fail 'uninstall preservation'
    sh "$HERE/uninstall.sh" --system "$system" --root "$TEST_DIR/$system" --purge >/dev/null
    [ ! -e "$config" ] || fail 'purge'
done

# Force a failure between the binary rename and init-script rename. The old
# binary, init script, and secret must all survive a partially applied update.
install_local openwrt || fail 'rollback preparation'
cp "$TEST_DIR/openwrt/usr/bin/tgwsproxy" "$TEST_DIR/rollback-binary"
cp "$TEST_DIR/openwrt/etc/init.d/tgwsproxy" "$TEST_DIR/rollback-init"
cp "$TEST_DIR/openwrt/etc/tgwsproxy/config.json" "$TEST_DIR/rollback-config"
REAL_MV=$(command -v mv)
export REAL_MV
cat > "$TEST_DIR/bin/mv" <<'EOF'
#!/bin/sh
case "$*" in *'.new.'*'/etc/init.d/tgwsproxy') exit 1 ;; esac
exec "$REAL_MV" "$@"
EOF
chmod +x "$TEST_DIR/bin/mv"
printf '\n# New version\n' >> "$TEST_DIR/mock-proxy"
if PATH="$TEST_DIR/bin:$PATH" install_local openwrt; then fail 'ignored failed replacement'; fi
cmp "$TEST_DIR/openwrt/usr/bin/tgwsproxy" "$TEST_DIR/rollback-binary" || fail 'binary rollback'
cmp "$TEST_DIR/openwrt/etc/init.d/tgwsproxy" "$TEST_DIR/rollback-init" || fail 'init rollback'
cmp "$TEST_DIR/openwrt/etc/tgwsproxy/config.json" "$TEST_DIR/rollback-config" || fail 'config rollback'
rm "$TEST_DIR/bin/mv"

# Simulate the GitHub API and assets without weakening production HTTPS rules.
cp "$TEST_DIR/mock-proxy" "$TEST_DIR/release/tgwsproxy"
cp "$HERE/../etc/init.d/"* "$TEST_DIR/release/etc/init.d/"
(cd "$TEST_DIR/release" && tar -czf "$TEST_DIR/tgwsproxy-mips.tar.gz" tgwsproxy etc)
cp "$TEST_DIR/tgwsproxy-mips.tar.gz" "$TEST_DIR/tgwsproxy-mipsel.tar.gz"
(cd "$TEST_DIR" && sha256sum tgwsproxy-mips.tar.gz tgwsproxy-mipsel.tar.gz > SHA256SUMS)
cat > "$TEST_DIR/bin/wget" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
    case "$1" in https://*) url=$1; shift ;; -O) out=$2; shift 2 ;; *) exit 2 ;; esac
done
printf '%s\n' "$url" >> "$TGWS_TEST_DATA/requests"
case "$url" in
    */releases/latest) printf '{\n  "tag_name": "v2.0.0"\n}\n' > "$out" ;;
    */releases/download/v2.0.0/*) cp "$TGWS_TEST_DATA/${url##*/}" "$out" ;;
    *) exit 22 ;;
esac
EOF
cat > "$TEST_DIR/bin/uname" <<'EOF'
#!/bin/sh
echo mips
EOF
cat > "$TEST_DIR/bin/od" <<'EOF'
#!/bin/sh
echo "$TGWS_TEST_ENDIAN"
EOF
chmod +x "$TEST_DIR/bin/"*
export TGWS_TEST_DATA=$TEST_DIR
export PATH=$TEST_DIR/bin:$PATH
for TGWS_TEST_ENDIAN in 1 2; do
    export TGWS_TEST_ENDIAN
    sh "$HERE/install.sh" --root "$TEST_DIR/download" --system openwrt --no-start > "$TEST_DIR/output" 2>&1 || { cat "$TEST_DIR/output"; fail 'release install'; }
    if [ "$TGWS_TEST_ENDIAN" = 1 ]; then asset=mipsel; else asset=mips; fi
    tail -n1 "$TEST_DIR/requests" | grep -q "/v2.0.0/tgwsproxy-$asset.tar.gz$" || fail 'MIPS byte order or version pin'
done
before=$(sha256sum "$TEST_DIR/download/usr/bin/tgwsproxy")
# Staging Entware must also honor PATH, rather than use the host's /opt/bin.
sh "$HERE/install.sh" --root "$TEST_DIR/download-entware" --system entware --no-start > "$TEST_DIR/output" 2>&1 || { cat "$TEST_DIR/output"; fail 'Entware staged wget selection'; }
[ -f "$TEST_DIR/download-entware/opt/bin/tgwsproxy" ] || fail 'Entware release download'
printf 'tampered' >> "$TEST_DIR/tgwsproxy-mips.tar.gz"
if sh "$HERE/install.sh" --root "$TEST_DIR/download" --system openwrt --no-start > "$TEST_DIR/output" 2>&1; then fail 'accepted bad checksum'; fi
after=$(sha256sum "$TEST_DIR/download/usr/bin/tgwsproxy")
[ "$before" = "$after" ] || fail 'bad checksum changed installed binary'
grep -q 'Checksum mismatch' "$TEST_DIR/output" || fail 'wrong failure reason'
echo 'Installer integration tests passed (OpenWrt, Entware, config migration, locking, rollback, removal, pinned release, both MIPS byte orders, bad checksum).'
