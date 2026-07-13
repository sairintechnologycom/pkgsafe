# pkgsafe v1.7.0-beta.8 Release Verification

- Tag: `v1.7.0-beta.8` (merge commit `26a3ae2`, PR #39)
- Published: 2026-07-13 via GitHub Actions release workflow
- Workflow: https://github.com/sairintechnologycom/pkgsafe/actions/runs/29247993928
- Classification: **pre-release (private beta)**

## What shipped

- **Scan fail-closed:** package scan commands exit `1` under `--mode block` (default fail-on) or explicit `--fail-on block|warn`, so shell scripts cannot proceed after BLOCK/REVIEW_REQUIRED.
- **CI empty-diff clarity:** changed-only scans with zero packages print a NOTICE that ALLOW is not a full-project clean bill of health.
- **Public-boundary check:** `scripts/check-public-boundary.sh` falls back to `find`+`grep` when ripgrep is unavailable.

## Pre-release E2E (local)

| Check | Result |
|---|---|
| `go test ./...` | PASS |
| `go vet ./...` / `make fmt-check` | PASS |
| Corpus (30 fixtures) | PASS (0 fails, critical detection 100%, false block 0%) |
| `test rollout-readiness` | PASS → `PRIVATE_BETA_READY` |
| Install intercept axois block | PASS (exit 1, not installed) |
| Scan block mode exit codes | PASS (malicious=1, safe=0) |
| CI zero-package NOTICE | PASS |
| PR #39 CI (ubuntu/macos/windows/lint/e2e/self-scan) | PASS |
| Release workflow validate + GoReleaser + attest | PASS |

## Release verification ritual

| Check | Result |
|---|---|
| GitHub release assets published | PASS (see release page) |
| `shasum -a 256 -c checksums.txt` | Run against downloaded assets |
| Cosign verify-blob on checksums.txt | Run if cosign available |
| Binary `pkgsafe version` reports `1.7.0-beta.8` | PASS on smoke download |
| GA promotion | **Not claimed** — remains private beta |

## Install

```bash
# pin this beta
PKGSAFE_VERSION=v1.7.0-beta.8 curl -fsSL \
  https://github.com/sairintechnologycom/pkgsafe/releases/download/v1.7.0-beta.8/install.sh | bash
```

Or Homebrew (tap formula updated by GoReleaser when HOMEBREW_TAP_TOKEN is configured).
