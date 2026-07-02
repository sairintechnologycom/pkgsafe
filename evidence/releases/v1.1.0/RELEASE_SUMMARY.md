# PkgSafe v1.1.0 Release Summary

Date verified: 2026-07-02

## Release

- Repository: `github.com/sairintechnologycom/pkgsafe`
- Tag: `v1.1.0`
- Commit SHA: `a4f1f19` (`Merge pull request #30 from sairintechnologycom/feat/public-cli-entrypoint`)
- Contains: PR #30 — CLI dispatch moved from `cmd/pkgsafe` (package main) to
  the exported `pkg/cli` package (`cli.Run`, `cli.Execute`); `cmd/pkgsafe` is
  now a thin shim. New exported API, no command behavior changes (minor bump).
- Motivation: everything else in the module is under `internal/` and cannot be
  imported across module boundaries, so the private `pkgsafe-enterprise`
  superset binary had no way to consume the public core. `pkg/cli` is the
  minimal stable public surface for downstream distributions.
- Release workflow run: `https://github.com/sairintechnologycom/pkgsafe/actions/runs/28576370848`
- Release URL: `https://github.com/sairintechnologycom/pkgsafe/releases/tag/v1.1.0`
- Release published: 2026-07-02 (published from draft after verification)

## Results

| Check | Result |
| --- | --- |
| `go build ./...`, `go vet ./...`, `gofmt` | PASS |
| Full `go test ./...` | PASS |
| `go test -race` on moved `pkg/cli` package | PASS |
| `scripts/check-public-boundary.sh` | PASS |
| PR #30 CI (Build & Test, Package Gate Self-Scan) | PASS |
| Release asset checksum verification (12/12) | PASS |
| Cosign checksum signature verification | PASS |
| GitHub artifact attestation verification | PASS |
| Released binary version self-report (`pkgsafe 1.1.0 (a4f1f19)`) | PASS |
| Downstream consumption (`pkgsafe-enterprise` builds against `v1.1.0` via module proxy) | PASS |

## Boundary Review

`pkg/cli` exposes interface surface only (the existing CLI dispatch); no
premium implementation was added. The scripted public-boundary check passed.

## Final Classification

```text
v1.1.0_released: true
release_verification_passed: true
binary_version_self_report_correct: true
scripted_boundary_check_passed: true
premium_leakage_found_by_script: false
```
