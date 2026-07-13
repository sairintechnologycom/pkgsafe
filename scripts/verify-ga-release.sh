#!/usr/bin/env bash
# Verify a published PkgSafe release for PRODUCTION_GA_READY.
#
# Usage:
#   scripts/verify-ga-release.sh [VERSION]
#   scripts/verify-ga-release.sh v1.7.0-beta.9
#
# Requires: gh, cosign, go (for make build), network access to GitHub releases.
# Optional env:
#   PKGSAFE_GITHUB_REPO   default: sairintechnologycom/pkgsafe
#   PKGSAFE_ARTIFACT_DIR  default: dist/ga-verify
#   SKIP_BUILD=1          use existing ./dist/pkgsafe

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION_RAW="${1:-v1.7.0-beta.9}"
VERSION="${VERSION_RAW#v}"
TAG="v${VERSION}"
REPO="${PKGSAFE_GITHUB_REPO:-sairintechnologycom/pkgsafe}"
ART_DIR="${PKGSAFE_ARTIFACT_DIR:-$ROOT_DIR/dist/ga-verify}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required tool not found: $1" >&2
    exit 2
  }
}

need gh
need cosign
need shasum

echo "==> Download release $TAG into $ART_DIR"
rm -rf "$ART_DIR"
mkdir -p "$ART_DIR"
gh release download "$TAG" --repo "$REPO" -D "$ART_DIR"

echo "==> Verify checksums"
(
  cd "$ART_DIR"
  shasum -a 256 -c checksums.txt
)

echo "==> Verify cosign signature on checksums.txt"
cosign verify-blob \
  --certificate "$ART_DIR/checksums.txt.pem" \
  --signature "$ART_DIR/checksums.txt.sig" \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ART_DIR/checksums.txt"

ARCHIVE="$(ls "$ART_DIR"/pkgsafe_*_darwin_arm64.tar.gz 2>/dev/null | head -1 || true)"
if [ -z "$ARCHIVE" ]; then
  ARCHIVE="$(ls "$ART_DIR"/pkgsafe_*.tar.gz "$ART_DIR"/pkgsafe_*.zip 2>/dev/null | head -1 || true)"
fi
if [ -z "$ARCHIVE" ]; then
  echo "error: no release archive found in $ART_DIR" >&2
  exit 1
fi

echo "==> Verify GitHub attestation for $(basename "$ARCHIVE")"
gh attestation verify "$ARCHIVE" \
  --repo "$REPO" \
  --signer-workflow "github.com/${REPO}/.github/workflows/release.yml"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> Build local pkgsafe for readiness command"
  make build
fi
if [ ! -x ./dist/pkgsafe ]; then
  echo "error: ./dist/pkgsafe missing; run make build" >&2
  exit 1
fi

echo "==> Run production-readiness with verified artifact dir"
export PKGSAFE_RELEASE_ARTIFACT_DIR="$ART_DIR"
export PKGSAFE_GITHUB_REPO="$REPO"
OUT_JSON="${PKGSAFE_READINESS_JSON:-$ROOT_DIR/evidence/releases/${TAG}/production-readiness-ga.json}"
mkdir -p "$(dirname "$OUT_JSON")"

./dist/pkgsafe test production-readiness --json | tee "$OUT_JSON.tmp" >/dev/null
# Keep only JSON object (command may print nothing else)
python3 - "$OUT_JSON.tmp" "$OUT_JSON" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
i = raw.find("{")
if i < 0:
    raise SystemExit("no JSON object in production-readiness output")
data = json.loads(raw[i:])
open(sys.argv[2], "w").write(json.dumps(data, indent=2) + "\n")
status = data.get("final_status")
ga = data.get("ga_ready")
blockers = data.get("ga_blockers") or []
print(f"final_status={status}")
print(f"ga_ready={ga}")
print(f"production_ready={data.get('production_ready')}")
print(f"ga_blockers={blockers}")
print(f"signing_verified={data.get('signing_verified')}")
print(f"provenance_verified={data.get('provenance_verified')}")
print(f"real_repos={data.get('real_repo_validation_count')}/{data.get('required_real_repo_validation_count')}")
if status != "PRODUCTION_GA_READY" or not ga or blockers:
    raise SystemExit(1)
PY
rm -f "$OUT_JSON.tmp"

echo
echo "PRODUCTION_GA_READY verified for $TAG"
echo "Evidence JSON: $OUT_JSON"
echo "Artifact dir:  $ART_DIR"
