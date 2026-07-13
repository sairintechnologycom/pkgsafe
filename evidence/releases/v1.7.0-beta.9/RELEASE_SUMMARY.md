# pkgsafe v1.7.0-beta.9 Release Verification

- Tag: `v1.7.0-beta.9` (merge commit `c336499`, PR #41)
- Published: 2026-07-13 via GitHub Actions release workflow
- Workflow: https://github.com/sairintechnologycom/pkgsafe/actions/runs/29255632270
- Classification: **pre-release (public beta evidence path)**

## What shipped

- **CI `--full`:** forces whole-lockfile scans; overrides policy `ci.changed_only`.
- **`scan_coverage`:** `full` | `changed_only` | `changed_only_empty` in CI JSON/human output.
- **Production readiness default:** uses `benchmarks/real-repos.json` when present → **15/15** real-repo validations (`PUBLIC_BETA_READY`).
- **Multi-PM intercept:** `pkgsafe pnpm|yarn|uv` plus shell shims for npm/pnpm/yarn/pip/uv.

## Pre-release verification

| Check | Result |
|---|---|
| PR #41 CI (all 6 jobs) | PASS |
| Release workflow | PASS (~4m34s) |
| Cosign checksums | Verified OK (local smoke) |
| Binary version | `pkgsafe 1.7.0-beta.9 (c336499)` |
| pnpm intercept BLOCK | PASS (exit 1 on axois) |
| CI `--full` coverage | PASS |

## Remaining GA blockers (expected)

- Signed release artifacts verified on the readiness host
- Build provenance verified locally

## Install

```bash
PKGSAFE_VERSION=v1.7.0-beta.9 curl -fsSL \
  https://github.com/sairintechnologycom/pkgsafe/releases/download/v1.7.0-beta.9/install.sh | bash
```
