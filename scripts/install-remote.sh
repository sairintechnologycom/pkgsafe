#!/usr/bin/env bash
# PkgSafe remote installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sairintechnologycom/pkgsafe/main/scripts/install-remote.sh | bash
#
# Environment overrides:
#   PKGSAFE_VERSION   pin a specific version, e.g. 1.6.0 (default: latest release)
#   PKGSAFE_BIN_DIR   install directory (default: /usr/local/bin)
#
# The installer downloads the signed release tarball for your OS/arch,
# verifies its SHA-256 against the release checksums.txt, and installs the
# binary. For full supply-chain verification (cosign signature + GitHub
# attestation), see: https://github.com/sairintechnologycom/pkgsafe#install
set -euo pipefail

REPO="sairintechnologycom/pkgsafe"
BIN_DIR="${PKGSAFE_BIN_DIR:-/usr/local/bin}"

err()  { echo "pkgsafe-install: error: $*" >&2; exit 1; }
info() { echo "pkgsafe-install: $*"; }
need() { command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"; }

need curl
need tar
need uname

# --- detect OS ---
os="$(uname -s)"
case "$os" in
  Linux)  goos=linux ;;
  Darwin) goos=darwin ;;
  *) err "unsupported OS '$os'. On Windows, download the .zip from https://github.com/${REPO}/releases" ;;
esac

# --- detect arch ---
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  goarch=amd64 ;;
  arm64|aarch64) goarch=arm64 ;;
  *) err "unsupported architecture '$arch'" ;;
esac

# --- resolve version ---
version="${PKGSAFE_VERSION:-}"
if [ -z "$version" ]; then
  info "resolving latest release ..."
  version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 \
    | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/')"
  [ -n "$version" ] || err "could not resolve latest version; set PKGSAFE_VERSION explicitly"
fi
version="${version#v}"

asset="pkgsafe_${version}_${goos}_${goarch}.tar.gz"
base="https://github.com/${REPO}/releases/download/v${version}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading ${asset} ..."
curl -fsSL "${base}/${asset}"       -o "${tmp}/${asset}"      || err "failed to download ${asset}"
curl -fsSL "${base}/checksums.txt"  -o "${tmp}/checksums.txt" || err "failed to download checksums.txt"

# --- verify checksum ---
info "verifying SHA-256 checksum ..."
expected="$(awk -v f="$asset" '$2==f {print $1}' "${tmp}/checksums.txt" | head -1)"
[ -n "$expected" ] || err "no checksum for ${asset} in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
else
  err "no sha256 tool (sha256sum or shasum) found to verify the download"
fi
[ "$expected" = "$actual" ] || err "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"

# --- extract & install ---
tar -xzf "${tmp}/${asset}" -C "${tmp}"
[ -f "${tmp}/pkgsafe" ] || err "binary 'pkgsafe' not found in ${asset}"
chmod +x "${tmp}/pkgsafe"

if [ -d "$BIN_DIR" ] && [ -w "$BIN_DIR" ]; then
  mv "${tmp}/pkgsafe" "${BIN_DIR}/pkgsafe"
else
  info "elevating with sudo to write ${BIN_DIR} ..."
  sudo mkdir -p "$BIN_DIR"
  sudo mv "${tmp}/pkgsafe" "${BIN_DIR}/pkgsafe"
fi

info "installed pkgsafe ${version} -> ${BIN_DIR}/pkgsafe"
if command -v pkgsafe >/dev/null 2>&1; then
  pkgsafe version || true
else
  info "note: ${BIN_DIR} is not on your PATH — add it or invoke ${BIN_DIR}/pkgsafe directly"
fi
info "next: 'pkgsafe doctor' to check your setup, or see MCP setup at https://github.com/${REPO}#mcp-tool"
