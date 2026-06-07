#!/usr/bin/env sh
# Keelix installer.
#   curl -fsSL https://raw.githubusercontent.com/jwlamon/keelix/main/install.sh | sh
#
# Env:
#   KEELIX_VERSION  release tag to install (default: latest)
#   KEELIX_BINDIR   install dir (default: /usr/local/bin, or ~/.local/bin if not writable)
set -eu

REPO="jwlamon/keelix"
BIN="keelix"
VERSION="${KEELIX_VERSION:-latest}"

err() { echo "keelix-install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
	linux|darwin) ;;
	*) err "unsupported OS: $os (build from source: go install github.com/$REPO/cmd/keelix@latest)" ;;
esac

arch="$(uname -m)"
case "$arch" in
	x86_64|amd64) arch="amd64" ;;
	arm64|aarch64) arch="arm64" ;;
	*) err "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
	VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
		| grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
	[ -n "$VERSION" ] || err "could not determine latest version; set KEELIX_VERSION"
fi

asset="${BIN}-${os}-${arch}"
url="https://github.com/$REPO/releases/download/$VERSION/$asset"

bindir="${KEELIX_BINDIR:-/usr/local/bin}"
if [ ! -d "$bindir" ] || [ ! -w "$bindir" ]; then
	bindir="$HOME/.local/bin"
	mkdir -p "$bindir"
fi

tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT INT TERM
tmp="$tmpd/$BIN"
echo "Downloading $BIN $VERSION ($os/$arch) ..."
curl -fSL "$url" -o "$tmp" || err "download failed: $url"

# Verify the SHA-256 checksum against the release's checksums.txt. Keelix is a
# security tool; a tampered or unverifiable binary defeats the point, so this
# FAILS CLOSED: any inability to verify aborts the install. Set KEELIX_SKIP_VERIFY=1
# to override at your own risk.
if [ "${KEELIX_SKIP_VERIFY:-0}" = "1" ]; then
	echo "WARNING: KEELIX_SKIP_VERIFY=1 — installing without checksum verification."
else
	sums="$tmpd/checksums.txt"
	curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/checksums.txt" -o "$sums" \
		|| err "could not download checksums.txt for $VERSION; refusing to install an unverified binary (set KEELIX_SKIP_VERIFY=1 to override)"
	expected="$(grep " ${asset}\$" "$sums" | awk '{print $1}')"
	[ -n "$expected" ] || err "no checksum entry for $asset in checksums.txt; refusing to install"
	if have sha256sum; then actual="$(sha256sum "$tmp" | awk '{print $1}')";
	elif have shasum; then actual="$(shasum -a 256 "$tmp" | awk '{print $1}')";
	else err "no sha256 utility found (install coreutils, or use a shell with shasum); refusing to install an unverified binary (set KEELIX_SKIP_VERIFY=1 to override)"; fi
	[ "$actual" = "$expected" ] || err "checksum mismatch for $asset (expected $expected, got $actual)"
	echo "Checksum verified."
fi

chmod +x "$tmp"
mv "$tmp" "$bindir/$BIN"

echo "Installed $bindir/$BIN"
case ":$PATH:" in
	*":$bindir:"*) ;;
	*) echo "NOTE: add $bindir to your PATH." ;;
esac
"$bindir/$BIN" version || true
