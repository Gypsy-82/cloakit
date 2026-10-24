#!/usr/bin/env sh
# cloakit installer — verifiable, user-local, no sudo.
#
# PHILOSOPHY (matches the tool itself):
#   * Default to a sane user-local dir on PATH (~/.local/bin), never a system
#     dir and NEVER /tmp (world-writable + auto-wiped — hostile to a binary you
#     depend on, and obscurity is not security anyway).
#   * Verify before trusting: download the binary AND its SHA-256, check it, and
#     only then place it. We never pipe a URL straight into a shell.
#   * The user is in control: CLOAKIT_INSTALL_DIR relocates freely.
#
# Usage (after a release exists):
#   1. Download and READ this script first (don't blind-pipe it):
#        curl -fsSLO https://github.com/Gypsy-82/cloakit/releases/latest/download/install.sh
#        less install.sh
#   2. Run it:
#        sh install.sh
#   Override the location:
#        CLOAKIT_INSTALL_DIR="$HOME/bin" sh install.sh
#   Pin a version (default: latest):
#        CLOAKIT_VERSION=v0.1.0 sh install.sh
#
# NOTE: inactive until the repo is published with release assets. The URL scheme
# below is the intended layout, not a live endpoint yet.

set -eu

REPO="Gypsy-82/cloakit"
VERSION="${CLOAKIT_VERSION:-latest}"
INSTALL_DIR="${CLOAKIT_INSTALL_DIR:-$HOME/.local/bin}"

die() { printf 'cloakit-install: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

need curl
need sha256sum
need uname
need mktemp

# --- Refuse hostile install locations ------------------------------------
case "$INSTALL_DIR" in
    /tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*)
        die "refusing to install into '$INSTALL_DIR': ephemeral and/or world-writable.
     Pick a persistent, owner-only dir (default: ~/.local/bin)."
        ;;
esac

# --- Detect target triple -------------------------------------------------
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64)  target="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
    *) die "unsupported architecture '$arch'. Build from source: see docs/INSTALL.md" ;;
esac

asset="cloakit-${target}"
if [ "$VERSION" = "latest" ]; then
    base="https://github.com/${REPO}/releases/latest/download"
else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# --- Download to a private temp dir, verify, THEN place -------------------
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cloakit-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
chmod 700 "$tmp"

printf 'cloakit-install: downloading %s (%s)\n' "$asset" "$VERSION"
curl -fsSL "$base/$asset"        -o "$tmp/$asset"        || die "download failed: $base/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256" || die "download failed: $base/$asset.sha256"

printf 'cloakit-install: verifying checksum...\n'
( cd "$tmp" && sha256sum -c "$asset.sha256" ) || die "CHECKSUM MISMATCH — refusing to install. Do not run the downloaded file."

# Optional GPG signature check, if a detached signature is published and you
# have imported the maintainer key. Checksum-from-same-host only proves transit
# integrity; a signature is what defends against a compromised release host.
if command -v gpg >/dev/null 2>&1 && curl -fsSL "$base/$asset.sig" -o "$tmp/$asset.sig" 2>/dev/null; then
    if gpg --verify "$tmp/$asset.sig" "$tmp/$asset" >/dev/null 2>&1; then
        printf 'cloakit-install: GPG signature OK\n'
    else
        die "GPG signature verification FAILED — refusing to install."
    fi
fi

# --- Place the binary -----------------------------------------------------
mkdir -p "$INSTALL_DIR"
chmod +x "$tmp/$asset"
install -m 0755 "$tmp/$asset" "$INSTALL_DIR/cloakit" 2>/dev/null \
    || { cp "$tmp/$asset" "$INSTALL_DIR/cloakit" && chmod 0755 "$INSTALL_DIR/cloakit"; }

printf 'cloakit-install: installed -> %s/cloakit\n' "$INSTALL_DIR"

# --- PATH advice ----------------------------------------------------------
case ":$PATH:" in
    *":$INSTALL_DIR:"*) : ;; # already on PATH
    *) printf '\ncloakit-install: NOTE — %s is not on your PATH.\n  Add this to your shell rc:\n    export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
esac

printf '\nDone. Try:  cloakit\n'
