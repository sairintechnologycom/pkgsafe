#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

PATTERN='\bhosted[[:space:]]+evidence\b|\bbilling\b|\blicense[[:space:]]+server\b|\bSAML\b|\bSSO\b|\bRBAC\b|\benterprise[[:space:]]+dashboard\b|\bcommercial[[:space:]]+intelligence\b|\bprivate[[:space:]]+feed\b|\bcustomer-specific\b|\bpolicy[[:space:]]+sync[[:space:]]+service\b|\bpaid[[:space:]]+feature\b|\bpremium[[:space:]]+implementation\b'
FORBIDDEN_PATHS='^(pkg/license|internal/enterprise|pkg/enterprise|private|customer|customers)/'
FORBIDDEN_SYMBOLS='\b(Entitlement|LicenseResolver|EnterpriseCommandFunc|LoadSignedPolicyFunc|CIEnterpriseMode|FeatureSignedBundles|FeatureSignedPolicy|FeatureSignedEvidence)\b'
IMPL_PATHS='^(cmd|internal|pkg|scripts)/'
DOC_PATHS='^(docs|README\.md|CONTRIBUTING\.md|SECURITY\.md|ROLLOUT-READINESS\.md|REMEDIATION\.md|CHANGELOG\.md|action\.yml|Makefile)'
ALLOWLIST='^(docs/architecture/open-core-boundary\.md|docs/architecture/feature-classification\.md|CONTRIBUTING\.md|scripts/check-public-boundary\.sh):'

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required for public-boundary checks" >&2
  exit 2
fi

failures="$(rg -n -i -P --glob '!dist/**' --glob '!evidence/e2e/**' --glob '!graphify-out/**' "$PATTERN" cmd internal pkg scripts 2>/dev/null | grep -Ev "$ALLOWLIST" || true)"

path_failures="$(rg --files cmd internal pkg scripts 2>/dev/null | grep -E "$FORBIDDEN_PATHS" || true)"
symbol_failures="$(rg -n -P --glob '*.go' "$FORBIDDEN_SYMBOLS" cmd internal pkg 2>/dev/null || true)"

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

warnings="$(rg -n -i -P --glob '!dist/**' --glob '!evidence/e2e/**' --glob '!graphify-out/**' "$PATTERN" . 2>/dev/null | grep -E "$DOC_PATHS" | grep -Ev "$ALLOWLIST" || true)"

if [ -n "$warnings" ]; then
  echo "Public-boundary warning: review these public documentation mentions for OSS-safe wording." >&2
  echo >&2
  echo "$warnings" >&2
  echo >&2
fi

echo "Public-boundary check passed: no obvious premium implementation leakage found."
