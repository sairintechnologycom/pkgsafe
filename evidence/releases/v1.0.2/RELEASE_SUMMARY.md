# PkgSafe v1.0.2 Release Summary

Date verified: 2026-07-02

## Release

- Repository: `github.com/sairintechnologycom/pkgsafe`
- Tag: `v1.0.2`
- Commit SHA: `02c8f70` (`fix(release): repair version ldflags broken by module rename`)
- Contains: PR #29 (E2E release qualification + PyPI calibration fix, merged at `dd37202`), release prep (`7de6823`), ldflags repair (`02c8f70`)
- Release workflow run: `https://github.com/sairintechnologycom/pkgsafe/actions/runs/28575530632`
- Release URL: `https://github.com/sairintechnologycom/pkgsafe/releases/tag/v1.0.2`
- Release published: 2026-07-02 (published from draft after verification)

## Release Note

The first v1.0.2 tag (at `7de6823`) was cut, built, and then discarded before
publication: verification caught that released binaries misreported their
version as `v1.0.2-dev (none)`. Root cause: `.goreleaser.yaml` still injected
`version.Version`/`version.Commit` at the pre-rename module path
`github.com/niyam-ai/pkgsafe`, so `-X` silently targeted a nonexistent symbol.
This defect also affects the published v1.0.0/v1.0.1 binaries (they report
`v0.2.0-beta.1-dev (none)`). The draft release and tag were deleted, the
ldflags were fixed, and v1.0.2 was re-cut at `02c8f70`. The re-cut binary
correctly reports `pkgsafe 1.0.2 (02c8f70)`.

## Verification Commands

```bash
git checkout main
git pull --rebase
go test ./...
go test -race ./...
go vet ./...
make build
make package
scripts/check-public-boundary.sh
gh release download v1.0.2 --repo sairintechnologycom/pkgsafe --dir <assets-dir>
shasum -a 256 -c checksums.txt
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/sairintechnologycom/pkgsafe' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
gh attestation verify pkgsafe_1.0.2_darwin_arm64.tar.gz --repo sairintechnologycom/pkgsafe
tar -xzf pkgsafe_1.0.2_darwin_arm64.tar.gz && ./pkgsafe version
```

## Results

| Check | Result |
| --- | --- |
| `go test ./...` | PASS |
| `go test -race ./...` | PASS |
| `go vet ./...` | PASS |
| `make build` | PASS |
| `make package` | PASS |
| `scripts/check-public-boundary.sh` | PASS |
| Release asset checksum verification (12/12) | PASS |
| Cosign checksum signature verification | PASS |
| GitHub artifact attestation verification | PASS |
| Released binary version self-report (`pkgsafe 1.0.2 (02c8f70)`) | PASS |
| Local tag `v1.0.2` at `02c8f70` | PASS |
| Remote tag `v1.0.2` at `02c8f70` | PASS |

All-loop E2E qualification for this line is recorded in
`evidence/e2e/E2E_VALIDATION_SUMMARY.md` (`E2E_PASS: true`,
`release_candidate_ready: true`, `blockers: 0`).

## Boundary Review

The scripted public-boundary check passed:

```text
Public-boundary check passed: no obvious premium implementation leakage found.
```

This release completes the open-core cleanup: enterprise-only implementation
(signed policy pack create/install/verify, SIEM / ServiceNow / Azure DevOps
exporters, enterprise MCP report surfaces) has been removed from the public
repository. Public commands return explicit handoff errors pointing to
`github.com/sairintechnologycom/pkgsafe-enterprise`.

## Known Limitations

- PkgSafe v1.0.2 remains npm-first GA. PyPI stays preview: the calibration fix
  removes false blocks on known-good packages but does not claim
  npm-equivalent depth; GA needs lockfile/artifact coverage evidence.
- Published v1.0.0 and v1.0.1 binaries misreport their version
  (`v0.2.0-beta.1-dev (none)`) due to the pre-rename ldflags path; their
  checksums, signatures, and behavior are otherwise valid. v1.0.2 supersedes
  them.
- Behavior analysis remains disabled by default. Heuristic mode is not real
  isolation, and isolated behavior support must fail closed when unavailable.
- The boundary script is term-based; it does not prove semantic absence of
  premium implementation.

## Final Classification

```text
v1.0.2_released: true
release_verification_passed: true
binary_version_self_report_correct: true
scripted_boundary_check_passed: true
premium_leakage_found_by_script: false
```
