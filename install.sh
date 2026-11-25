#!/bin/sh
# Installs the brioly CLI from the latest GitHub release.
#
#   curl -sSL https://brioly.io/install.sh | sh
#
# Options, as environment variables:
#   BRIOLY_VERSION      a release tag such as v0.1.0 (default: the latest)
#   BRIOLY_INSTALL_DIR  where to put the binary (default: /usr/local/bin if
#                       you can write there, otherwise ~/.local/bin)
#
# The download is checked against the release's checksums before anything
# is installed. Nothing is run with sudo.
set -eu

repo="brioly/brioly"

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) fail "this script supports Linux and macOS. For Windows, download brioly_windows_amd64.zip from https://github.com/$repo/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="amd64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) fail "unsupported CPU: $(uname -m)" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is needed"
command -v tar >/dev/null 2>&1 || fail "tar is needed"
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "sha256sum or shasum is needed to check the download"
fi

version="${BRIOLY_VERSION:-}"
if [ -n "$version" ]; then
  base="https://github.com/$repo/releases/download/$version"
else
  base="https://github.com/$repo/releases/latest/download"
fi
asset="brioly_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $asset from ${version:-the latest release}..."
curl -fsSL "$base/$asset" -o "$tmp/$asset" || fail "could not download $base/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || fail "could not download the checksums"

want="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || fail "the release has no checksum for $asset"
got="$(sha256 "$tmp/$asset")"
[ "$want" = "$got" ] || fail "checksum mismatch for $asset: nothing was installed"

tar -xzf "$tmp/$asset" -C "$tmp" brioly 2>/dev/null || tar -xzf "$tmp/$asset" -C "$tmp" ./brioly

dir="${BRIOLY_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    dir="/usr/local/bin"
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/brioly" "$dir/brioly" 2>/dev/null || {
  cp "$tmp/brioly" "$dir/brioly"
  chmod 0755 "$dir/brioly"
}

echo "Installed $("$dir/brioly" version) to $dir/brioly"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run it as 'brioly':  export PATH=\"$dir:\$PATH\"" ;;
esac
