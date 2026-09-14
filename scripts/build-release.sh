#!/usr/bin/env bash
# Native ARM64: Linux + musl-tools + Rust 1.97.0 + aarch64 musl target.
# Other targets: Linux + Docker + cross + nightly-2026-09-01/rust-src.
# Run from repo root; the optional second argument selects native or cross.
set -euo pipefail
arch=${1:?Usage: scripts/build-release.sh mips|mipsel|arm|armv7|aarch64|x86_64}
backend=${2:-cross}
toolchain=nightly-2026-09-01
case "$arch" in
    mips) target=mips-unknown-linux-musl ;;
    mipsel) target=mipsel-unknown-linux-musl ;;
    arm) target=armv5te-unknown-linux-musleabi ;;
    armv7) target=armv7-unknown-linux-musleabi ;;
    aarch64) target=aarch64-unknown-linux-musl ;;
    x86_64) target=x86_64-unknown-linux-musl ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac
export RUSTFLAGS='-C target-feature=+crt-static'
case "$arch" in
    aarch64)
        # Explicit RUSTFLAGS override .cargo/config.toml, so retain this opt-in.
        export RUSTFLAGS="$RUSTFLAGS --cfg aes_armv8"
        ;;
    mips|mipsel)
        # build-std does not install musl CRT objects. Let the cross GCC linker
        # locate those objects in its sysroot while still linking statically.
        export RUSTFLAGS="$RUSTFLAGS -C link-self-contained=no"
        ;;
esac
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
mkdir -p dist
case "$backend" in
    native)
        if [[ "$arch" != aarch64 || "$(uname -m)" != aarch64 ]]; then
            echo 'Native builds require an aarch64 Linux host and aarch64 target' >&2; exit 1
        fi
        toolchain=1.97.0
        export CC_aarch64_unknown_linux_musl=musl-gcc
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
        builder=(cargo)
        printf 'backend=native\nhost=%s\n' "$(uname -m)" > "dist/build-$arch.txt"
        musl-gcc --version | head -n1 >> "dist/build-$arch.txt"
        # Record libc/compiler versions alongside the locked Rust dependencies.
        dpkg-query -W musl musl-dev musl-tools gcc >> "dist/build-$arch.txt"
        ;;
    cross)
        image="ghcr.io/cross-rs/$target:main"
        docker pull "$image"
        docker inspect --format '{{index .RepoDigests 0}}' "$image" > "dist/build-$arch.txt"
        builder=(cross)
        cross --version >> "dist/build-$arch.txt"
        ;;
    *) echo "Unsupported build backend: $backend" >&2; exit 1 ;;
esac
rustc +"$toolchain" --version >> "dist/build-$arch.txt"
"${builder[@]}" +"$toolchain" build --locked --release --target "$target"
if [[ "$backend" = native ]]; then
    # Exercise the ARM hardware AES backend and Linux control plane before shipping.
    cargo +"$toolchain" test --locked --release --target "$target"
fi
binary="target/$target/release/tgwsproxy"
file "$binary" | tee -a "dist/build-$arch.txt"
readelf -h -A "$binary" >> "dist/build-$arch.txt"
# Reject silently dynamic executables (including a dynamic OpenSSL dependency).
program_headers=$(readelf -l "$binary")
dynamic_headers=$(readelf -d "$binary")
if grep -q 'INTERP' <<< "$program_headers"; then
    echo 'ERROR: release binary has an ELF interpreter' >&2; exit 1
fi
if grep -q 'NEEDED' <<< "$dynamic_headers"; then
    echo 'ERROR: release binary has dynamic library dependencies' >&2; exit 1
fi
# Native execution or QEMU via cross exercises actual target startup code.
"${builder[@]}" +"$toolchain" run --locked --release --target "$target" -- --version
config="target/smoke-$arch.json"
rm -f "$config"
"${builder[@]}" +"$toolchain" run --locked --release --target "$target" -- --config "$config" --init-config
"${builder[@]}" +"$toolchain" run --locked --release --target "$target" -- --config "$config" --check-config
rm -f "$config"
package=$(mktemp -d)
trap 'rm -rf "$package"' EXIT
mkdir -p "$package/etc/init.d"
cp "$binary" "$package/tgwsproxy"
cp etc/init.d/S99tgwsproxy etc/init.d/tgwsproxy "$package/etc/init.d/"
cp scripts/install.sh scripts/uninstall.sh LICENSE LICENSE.upstream THIRD_PARTY_NOTICES.md "$package/"
mkdir -p "$package/licenses"
# Cargo metadata points to the precise locked crate sources. Keep their actual
# license texts in the archive, including the statically linked OpenSSL source.
cargo +"$toolchain" metadata --locked --format-version 1 > "$package/dependencies.json"
jq -r '.packages[] | select(.source != null) | [.name + "-" + .version, .manifest_path] | @tsv' \
    "$package/dependencies.json" > "$package/dependency-paths.tsv"
jq -r '.packages[] | select(.source != null) | [.name, .version, .license] | @tsv' \
    "$package/dependencies.json" > "$package/licenses/DEPENDENCIES.tsv"
while IFS=$'\t' read -r name manifest; do
    directory=${manifest%/*}
    mkdir -p "$package/licenses/$name"
    for license in "$directory"/LICENSE* "$directory"/COPYING* "$directory"/NOTICE*; do
        [ ! -f "$license" ] || cp "$license" "$package/licenses/$name/"
    done
    if [[ "$name" = openssl-src-* ]]; then
        cp "$directory/openssl/LICENSE.txt" "$package/licenses/OpenSSL-LICENSE.txt"
    fi
done < "$package/dependency-paths.tsv"
test -s "$package/licenses/OpenSSL-LICENSE.txt"
case "$arch" in
    mips|mipsel)
        # The Tier-3 std build uses the cross image's GCC 9.2 static unwinder.
        # Ship the exact upstream license texts, checked against known hashes.
        gcc_source=https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-9.2.0
        wget -qO "$package/licenses/GCC-COPYING3" "$gcc_source/COPYING3"
        wget -qO "$package/licenses/GCC-COPYING.RUNTIME" "$gcc_source/COPYING.RUNTIME"
        (
            cd "$package/licenses"
            printf '%s\n' \
                '8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903  GCC-COPYING3' \
                '9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74  GCC-COPYING.RUNTIME' \
                | sha256sum -c -
        )
        ;;
esac
rm "$package/dependencies.json" "$package/dependency-paths.tsv"
chmod 755 "$package/tgwsproxy" "$package/"*.sh "$package/etc/init.d/"*
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C "$package" -czf "dist/tgwsproxy-$arch.tar.gz" \
    tgwsproxy etc install.sh uninstall.sh LICENSE LICENSE.upstream THIRD_PARTY_NOTICES.md licenses
printf 'binary_bytes=%s\n' "$(wc -c < "$binary")" >> "dist/build-$arch.txt"
printf 'archive_bytes=%s\n' "$(wc -c < "dist/tgwsproxy-$arch.tar.gz")" >> "dist/build-$arch.txt"
cat "dist/build-$arch.txt"
