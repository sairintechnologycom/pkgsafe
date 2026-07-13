#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

PATTERN='\bhosted[[:space:]]+evidence\b|\bbilling\b|\blicense[[:space:]]+server\b|\bSAML\b|\bSSO\b|\bRBAC\b|\benterprise[[:space:]]+dashboard\b|\bcommercial[[:space:]]+intelligence\b|\bprivate[[:space:]]+feed\b|\bcustomer-specific\b|\bpolicy[[:space:]]+sync[[:space:]]+service\b|\bpaid[[:space:]]+feature\b|\bpremium[[:space:]]+implementation\b'
FORBIDDEN_PATHS='^(pkg/license|internal/enterprise|pkg/enterprise|private|customer|customers)/'
FORBIDDEN_SYMBOLS='\b(Entitlement|LicenseResolver|EnterpriseCommandFunc|LoadSignedPolicyFunc|CIEnterpriseMode|FeatureSignedBundles|FeatureSignedPolicy|FeatureSignedEvidence)\b'
DOC_PATHS='^(docs|README\.md|CONTRIBUTING\.md|SECURITY\.md|ROLLOUT-READINESS\.md|REMEDIATION\.md|CHANGELOG\.md|action\.yml|Makefile)'
ALLOWLIST='^(docs/architecture/open-core-boundary\.md|docs/architecture/feature-classification\.md|CONTRIBUTING\.md|scripts/check-public-boundary\.sh):'

# Prefer ripgrep; fall back to find+grep so CI/developer machines without rg still work.
HAVE_RG=0
if command -v rg >/dev/null 2>&1; then
  HAVE_RG=1
fi

search_content() {
  # $1 = regex, $2... = roots
  local regex="$1"
  shift
  if [ "$HAVE_RG" -eq 1 ]; then
    rg -n -i -P --glob '!dist/**' --glob '!evidence/e2e/**' --glob '!graphify-out/**' "$regex" "$@" 2>/dev/null || true
  else
    # Portable fallback: line numbers, case-insensitive where supported.
    find "$@" \( -path '*/dist/*' -o -path '*/evidence/e2e/*' -o -path '*/graphify-out/*' -o -path '*/.git/*' \) -prune -o -type f -print 2>/dev/null \
      | while IFS= read -r f; do
          grep -n -i -E "$regex" "$f" 2>/dev/null | sed "s|^|${f}:|"
        done || true
  fi
}

search_go_symbols() {
  local regex="$1"
  shift
  if [ "$HAVE_RG" -eq 1 ]; then
    rg -n -P --glob '*.go' "$regex" "$@" 2>/dev/null || true
  else
    find "$@" -type f -name '*.go' ! -path '*/.git/*' -print 2>/dev/null \
      | while IFS= read -r f; do
          grep -n -E "$regex" "$f" 2>/dev/null | sed "s|^|${f}:|"
        done || true
  fi
}

list_impl_files() {
  if [ "$HAVE_RG" -eq 1 ]; then
    rg --files cmd internal pkg scripts 2>/dev/null || true
  else
    find cmd internal pkg scripts -type f ! -path '*/.git/*' 2>/dev/null || true
  fi
}

failures="$(search_content "$PATTERN" cmd internal pkg scripts | grep -Ev "$ALLOWLIST" || true)"

path_failures="$(list_impl_files | grep -E "$FORBIDDEN_PATHS" || true)"
symbol_failures="$(search_go_symbols "$FORBIDDEN_SYMBOLS" cmd internal pkg)"

if [ -n "$path_failures" ] || [ -n "$symbol_failures" ]; then
  echo "Public-boundary check failed: forbidden premium path or entitlement/dispatch symbol found." >&2
  [ -n "$path_failures" ] && echo "$path_failures" >&2
  [ -n "$symbol_failures" ] && echo "$symbol_failures" >&2
  exit 1
fi

if [ -n "$failures" ]; then
  echo "Public-boundary check failed: possible premium implementation terms found in implementation paths." >&2
  echo >&2
  echo "$failures" >&2
  echo >&2
  echo "Move private implementation to pkgsafe-enterprise, or replace it with an implementation-free public interface." >&2
  exit 1
fi

if [ "$HAVE_RG" -eq 1 ]; then
  warnings="$(rg -n -i -P --glob '!dist/**' --glob '!evidence/e2e/**' --glob '!graphify-out/**' "$PATTERN" . 2>/dev/null | grep -E "$DOC_PATHS" | grep -Ev "$ALLOWLIST" || true)"
else
  warnings="$(search_content "$PATTERN" docs README.md CONTRIBUTING.md SECURITY.md ROLLOUT-READINESS.md REMEDIATION.md CHANGELOG.md action.yml Makefile 2>/dev/null | grep -E "$DOC_PATHS" | grep -Ev "$ALLOWLIST" || true)"
fi

if [ -n "$warnings" ]; then
  echo "Public-boundary warning: review these public documentation mentions for OSS-safe wording." >&2
  echo >&2
  echo "$warnings" >&2
  echo >&2
fi

if [ "$HAVE_RG" -eq 1 ]; then
  echo "Public-boundary check passed: no obvious premium implementation leakage found."
else
  echo "Public-boundary check passed (grep fallback; install ripgrep for faster checks)."
fi
