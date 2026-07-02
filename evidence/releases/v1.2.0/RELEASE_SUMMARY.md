# PkgSafe v1.2.0 Release Summary

Date verified: 2026-07-02

## Release

- Repository: `github.com/sairintechnologycom/pkgsafe`
- Tag: `v1.2.0`
- Commit SHA: `8a378e8` (`test(cli): make CI enterprise-mode gate test hermetic`)
- Contains: PR #31 — `pkg/cli` `RunConfig` + `RunWith`/`ExecuteWith` seam;
  the `CIEnterpriseMode` knob wires into the pre-existing
  `internal/ci` `ScanOptions.EnterpriseMode` (per-finding
  policy/registry/trust/exception evidence, policy pack metadata,
  exceptions-used). Public binary keeps zero-value config; public `ci scan`
  output unchanged. Additive API → minor bump.
- Release workflow run: `https://github.com/sairintechnologycom/pkgsafe/actions/runs/28582578606`
- Release URL: `https://github.com/sairintechnologycom/pkgsafe/releases/tag/v1.2.0`
- Release published: 2026-07-02 (published from draft after verification)

## Release Note

The first v1.2.0 tag (at merge commit `b03c684`) was deleted before any draft
was produced: PR #31's new gate test passed locally (warm package cache) but
failed in cold CI, where offline scans yield unknown-stub findings without
policy evidence. The test was rewritten to be hermetic — `ci.RunScan` is now
stubbed behind a swappable `ciRunScanFunc` (same pattern as `apiServeFunc`)
asserting `ScanOptions.EnterpriseMode` for both config values — and v1.2.0
was re-cut at `8a378e8` with main CI green. Product code was identical in
both cuts; only test code changed.

## Results

| Check | Result |
| --- | --- |
| PR #31 CI | Build & Test failed on first cut (env-dependent test); green at `8a378e8` |
| Main CI at tagged commit | PASS |
| Full local gates (build/vet/fmt/test) | PASS |
| Release asset checksum verification (12/12) | PASS |
| Cosign checksum signature verification | PASS |
| GitHub artifact attestation verification | PASS |
| Released binary version self-report (`pkgsafe 1.2.0 (8a378e8)`) | PASS |
| Downstream consumption (`pkgsafe-enterprise` on `v1.2.0` via module proxy) | PASS |
| Enterprise-mode gate (public scan emits no per-finding policy evidence; enterprise scan does) | PASS (regression test + downstream E2E run) |

## Boundary Review

Interface surface only: the enrichment implementation already lived in the
public module (`internal/ci`); the public CLI still cannot enable it. The
scripted boundary check passes.

## Final Classification

```text
v1.2.0_released: true
release_verification_passed: true
binary_version_self_report_correct: true
public_ci_scan_output_unchanged: true
```
