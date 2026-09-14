#!/bin/sh
# Exercise worker lifecycle without writing to the host's /opt, /usr or /var.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

# Only installation roots are relocated in this test copy; lifecycle code is
# unchanged. Production has no environment override for its filesystem roots.
sed \
    -e "s@BIN_DIR=/opt/bin; EXPECTED_STATE=/opt/var/run/tgwsproxy-update;@BIN_DIR=$TEST_DIR/entware/opt/bin; EXPECTED_STATE=$TEST_DIR/entware/opt/var/run/tgwsproxy-update;@" \
    -e "s@BIN_DIR=/usr/bin; EXPECTED_STATE=/var/run/tgwsproxy-update;@BIN_DIR=$TEST_DIR/openwrt/usr/bin; EXPECTED_STATE=$TEST_DIR/openwrt/var/run/tgwsproxy-update;@" \
    "$HERE/update-worker.sh" > "$TEST_DIR/worker.sh"

for system in entware openwrt; do
    case "$system" in
        entware) bin=$TEST_DIR/entware/opt/bin; state=$TEST_DIR/entware/opt/var/run/tgwsproxy-update; template=S99tgwsproxy ;;
        openwrt) bin=$TEST_DIR/openwrt/usr/bin; state=$TEST_DIR/openwrt/var/run/tgwsproxy-update; template=tgwsproxy ;;
    esac
    mkdir -p "$bin" "$state"
    export TGWS_TEST_WORKER_STATE=$state
    export TGWS_TEST_WORKER_SYSTEM=$system
    make_payload() {
        payload=$(mktemp -d "$bin/.tgwsproxy-update.XXXXXX")
        mkdir -p "$payload/etc/init.d"
        printf 'binary fixture\n' > "$payload/tgwsproxy"
        printf 'service fixture\n' > "$payload/etc/init.d/$template"
        cat > "$payload/install.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$#" = 6 ] && [ "$1" = --system ] && [ "$2" = "$TGWS_TEST_WORKER_SYSTEM" ]
[ "$3" = --binary ] && [ -f "$4" ] && [ "$5" = --service-dir ] && [ -d "$6" ]
[ "$(cat "$TGWS_TEST_WORKER_STATE/stage")" = restarting ]
[ "$(cat "$TGWS_TEST_WORKER_STATE/target")" = v2.0.1 ]
case "$(cat "$TGWS_TEST_WORKER_STATE/pid")" in ''|*[!0-9]*) exit 2 ;; esac
echo 'Installer fixture ran'
exit "${TGWS_TEST_WORKER_FAILURE:-0}"
EOF
    }
    run_worker() { sh "$TEST_DIR/worker.sh" "$state" "$system" v2.0.1 "$payload"; }
    make_payload
    run_worker || fail "$system success"
    [ "$(cat "$state/stage")" = complete ] || fail 'missing complete stage'
    [ ! -e "$payload" ] && [ ! -e "$state/worker.lock" ] || fail 'success cleanup'
    grep -q 'Installer fixture ran' "$state/log" || fail 'installer log capture'

    make_payload
    if TGWS_TEST_WORKER_FAILURE=1 run_worker; then fail 'accepted failed installer'; fi
    [ "$(cat "$state/stage")" = error ] && [ -s "$state/error.txt" ] || fail 'missing failure state'
    [ ! -e "$payload" ] && [ ! -e "$state/worker.lock" ] || fail 'failure cleanup'

    make_payload
    mkdir "$state/worker.lock"
    printf 'other worker\n' > "$state/worker.lock/pid"
    printf 'downloading\n' > "$state/stage"
    printf '1234\n' > "$state/pid"
    if run_worker 2>/dev/null; then fail 'ignored worker lock'; fi
    [ -d "$payload" ] && [ "$(cat "$state/stage")" = downloading ] && [ "$(cat "$state/pid")" = 1234 ] || fail 'changed another worker state'
    [ "$(cat "$state/worker.lock/pid")" = 'other worker' ] || fail 'changed another worker lock'
    rm "$state/worker.lock/pid"
    rmdir "$state/worker.lock"
    run_worker || fail 'recovery after lock owner exits'
    [ ! -e "$state/error.txt" ] || fail 'old error survived successful retry'

    payload=$TEST_DIR/unrelated
    mkdir -p "$payload"
    printf 'preserve\n' > "$payload/marker"
    if run_worker; then fail 'accepted unrelated payload'; fi
    [ -f "$payload/marker" ] || fail 'removed unrelated directory'
    payload=$bin/.tgwsproxy-update.unsafe/nested
    mkdir -p "$payload"
    if run_worker; then fail 'accepted nested payload'; fi
    [ -d "$payload" ] || fail 'removed invalid nested payload'
done

# Run the actual installer core through the worker. Only the service-start side
# is disabled with its public staging option; binary/config/init replacement
# and rollback use the production implementation, including its cleanup trap.
export TGWS_TEST_REAL_INSTALLER=$HERE/install.sh
REAL_MV=$(command -v mv)
export REAL_MV
mkdir "$TEST_DIR/fault-bin"
cat > "$TEST_DIR/fault-bin/mv" <<'EOF'
#!/bin/sh
case "$*" in *'.new.'*"/etc/init.d/$TGWS_TEST_TEMPLATE") exit 1 ;; esac
exec "$REAL_MV" "$@"
EOF
chmod +x "$TEST_DIR/fault-bin/mv"
cat > "$TEST_DIR/proxy-fixture" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --version ]; then echo 'tgwsproxy 2.0.1'; exit 0; fi
[ "$1" = --config ] || exit 2
case "$3" in
    --init-config) printf '{"secret":"preserved-test-secret"}\n' > "$2" ;;
    --check-config) grep -q '"secret"' "$2" ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$TEST_DIR/proxy-fixture"
for system in entware openwrt; do
    export TGWS_TEST_INSTALL_ROOT=$TEST_DIR/$system
    case "$system" in
        entware) bin=$TEST_DIR/entware/opt/bin; state=$TEST_DIR/entware/opt/var/run/tgwsproxy-update; config=$TEST_DIR/entware/opt/etc/tgwsproxy/config.json; init=$TEST_DIR/entware/opt/etc/init.d/S99tgwsproxy; template=S99tgwsproxy ;;
        openwrt) bin=$TEST_DIR/openwrt/usr/bin; state=$TEST_DIR/openwrt/var/run/tgwsproxy-update; config=$TEST_DIR/openwrt/etc/tgwsproxy/config.json; init=$TEST_DIR/openwrt/etc/init.d/tgwsproxy; template=tgwsproxy ;;
    esac
    export TGWS_TEST_TEMPLATE=$template
    mkdir -p "${config%/*}" "${init%/*}"
    printf '{"secret":"preserved-test-secret","legacy":true}\n' > "$config"
    cp "$config" "$TEST_DIR/config.before"
    printf 'old binary\n' > "$bin/tgwsproxy"
    printf 'old init\n' > "$init"
    make_real_payload() {
        payload=$(mktemp -d "$bin/.tgwsproxy-update.XXXXXX")
        mkdir -p "$payload/etc/init.d"
        cp "$TEST_DIR/proxy-fixture" "$payload/tgwsproxy"
        cp "$HERE/../etc/init.d/$template" "$payload/etc/init.d/$template"
        cat > "$payload/install.sh" <<'EOF'
#!/bin/sh
exec sh "$TGWS_TEST_REAL_INSTALLER" --root "$TGWS_TEST_INSTALL_ROOT" --no-start "$@"
EOF
    }
    make_real_payload
    run_worker || fail 'real installer success'
    cmp "$TEST_DIR/proxy-fixture" "$bin/tgwsproxy" || fail 'real installer binary'
    cmp "$HERE/../etc/init.d/$template" "$init" || fail 'real installer service'
    cmp "$TEST_DIR/config.before" "$config" || fail 'real installer changed existing secret'

    cp "$bin/tgwsproxy" "$TEST_DIR/binary.before"
    cp "$init" "$TEST_DIR/init.before"
    make_real_payload
    printf '\n# candidate differs from installed version\n' >> "$payload/tgwsproxy"
    if PATH="$TEST_DIR/fault-bin:$PATH" run_worker; then fail 'real installer ignored replacement failure'; fi
    [ "$(cat "$state/stage")" = error ] || fail 'real installer failure stage'
    [ ! -e "$payload" ] && [ ! -e "$state/worker.lock" ] || fail 'real installer failure cleanup'
    cmp "$TEST_DIR/binary.before" "$bin/tgwsproxy" || fail 'real installer binary rollback'
    cmp "$TEST_DIR/init.before" "$init" || fail 'real installer init rollback'
    cmp "$TEST_DIR/config.before" "$config" || fail 'real installer config rollback'
    grep -q 'restoring previous files' "$state/log" || fail 'real installer rollback did not run'
done
echo 'Update-worker tests passed (both systems, stages, arguments, logs, cleanup, lock ownership, path boundary, real installer install and rollback).'
