#!/bin/sh
# Start the pinned Linux release as the current user. No system installation.
set -eu
umask 077

fail() {
    printf 'ai-edge-gateway: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail 'This launcher requires Linux.'
[ "$(uname -o 2>/dev/null || :)" != Android ] || fail 'For native Termux, use the source-build command in README.md.'
arch=$(uname -m)
case "$arch" in
    x86_64|aarch64) ;;
    *) fail "No prebuilt Linux release for $arch." ;;
esac

version=v0.2.0
package=ai-edge-gateway-$arch-unknown-linux-musl
asset=$package.tar.gz
base=https://github.com/jinmanji/ai-edge-gateway/releases/download/$version
home=${AIEG_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/ai-edge-gateway}
mkdir -p -- "$home"
home=$(cd -- "$home" && pwd -P)
release="$home/releases/$version/$package"
bin="$release/ai-edge-gateway"
sample="$release/config.example.toml"
config="$home/config.toml"

if [ ! -x "$bin" ] || [ ! -f "$sample" ]; then
    tmp=$(mktemp -d "$home/.download.XXXXXXXX")
    trap 'rm -rf -- "$tmp"' 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    download() {
        curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 \
            --max-time 120 --retry 2 -o "$tmp/$1" "$base/$1"
    }
    printf 'Downloading %s (%s)...\n' "$package" "$version" >&2
    download SHA256SUMS
    download "$asset"
    # Require exactly one well-formed digest for our chosen asset.
    awk -v asset="$asset" '$2 == asset {
        count++
        if (NF == 2 && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/) hash = $1
    } END {
        if (count != 1 || hash == "") exit 1
        print hash "  " asset
    }' "$tmp/SHA256SUMS" > "$tmp/checksum" || fail "No unique checksum for $asset."
    (cd -- "$tmp" && sha256sum -c checksum)
    tar -xzf "$tmp/$asset" -C "$tmp" "$package/ai-edge-gateway" "$package/config.example.toml"
    test -f "$tmp/$package/ai-edge-gateway" && test ! -L "$tmp/$package/ai-edge-gateway" || fail 'Invalid executable in archive.'
    test -f "$tmp/$package/config.example.toml" && test ! -L "$tmp/$package/config.example.toml" || fail 'Invalid configuration template in archive.'
    chmod 700 "$tmp/$package/ai-edge-gateway"
    chmod 600 "$tmp/$package/config.example.toml"
    mkdir -p -- "$release"
    mv -f -- "$tmp/$package/config.example.toml" "$sample"
    mv -f -- "$tmp/$package/ai-edge-gateway" "$bin"
    rm -rf -- "$tmp"
    trap - 0 HUP INT TERM
fi

# Never replace a user's config. Noclobber also covers simultaneous first runs.
if [ ! -e "$config" ] && [ ! -L "$config" ]; then
    (set -C; cat "$sample" > "$config") || [ -f "$config" ] || fail "Cannot initialize $config."
fi
[ -f "$config" ] && [ -r "$config" ] || fail "Cannot read $config."
"$bin" --config "$config" --check
printf 'Starting ai-edge-gateway with %s (Ctrl+C to stop).\n' "$config" >&2
exec "$bin" --config "$config"
