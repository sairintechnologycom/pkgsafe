# pkgsafe v1.7.0 — Production GA

- **Tag:** `v1.7.0` (commit `6af3119`)
- **Published:** 2026-07-13
- **GitHub:** https://github.com/sairintechnologycom/pkgsafe/releases/tag/v1.7.0
- **Channel:** **Latest** (not a pre-release)
- **Release workflow:** https://github.com/sairintechnologycom/pkgsafe/actions/runs/29261919774  
  (core publish succeeded; Homebrew tap push failed with PAT 403 — see caveats)

## Classification

```text
final_status: PRODUCTION_GA_READY
ga_ready: true
production_ready: true
ga_blockers: []
```

Evidence: [production-readiness-ga.json](./production-readiness-ga.json) · [GA_VERIFICATION.md](./GA_VERIFICATION.md)

## What shipped (since v1.6.0)

- Scan fail-closed: `--mode block` / `--fail-on` exit 1 on BLOCK
- CI `--full` + `scan_coverage` (`full` / `changed_only` / `changed_only_empty`)
- production-readiness defaults to real-repo catalog (15/15)
- Install intercept: npm, **pnpm**, **yarn**, **uv**, pip, python -m pip
- Shell shims for npm/pnpm/yarn/pip/uv
- GA verify automation: `scripts/verify-ga-release.sh`

## Verification ritual

| Check | Result |
|---|---|
| Assets published (16) | PASS |
| Checksums 12/12 | PASS |
| Cosign verify-blob | PASS (Verified OK) |
| GitHub attestation | PASS |
| Binary `pkgsafe version` | `pkgsafe 1.7.0 (6af3119)` |
| `production-readiness` | **PRODUCTION_GA_READY** |
| Homebrew formula push | **FAIL** — tap token 403 |

## Install

```bash
# Latest stable
curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash

# Pin
VERSION=1.7.0
curl -fsSL "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/install.sh" | bash
```

Homebrew (once tap formula is updated manually):

```bash
brew install sairintechnologycom/pkgsafe/pkgsafe
brew upgrade pkgsafe
```

## Caveats

1. **Homebrew:** GoReleaser could not push `Formula/pkgsafe.rb` to
   `sairintechnologycom/homebrew-pkgsafe` (`403 Resource not accessible by
   personal access token`). Release binaries are on GitHub Releases; refresh
   `HOMEBREW_TAP_TOKEN` with `contents:write` on the tap and re-run formula
   publish, or push the formula manually.
2. Workflow job marked failed only because of the Homebrew step after assets
   and signatures were already published.
