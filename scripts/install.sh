#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./dist/pkgsafe}"
DEST="${DEST:-/usr/local/bin/pkgsafe}"
if [[ ! -x "$BIN" ]]; then
  echo "Binary not found or not executable: $BIN" >&2
  exit 1
fi
install -m 0755 "$BIN" "$DEST"
echo "Installed pkgsafe to $DEST"
