# Loop 6 — Evidence, SBOM, and Signing Hardening

Date: 2026-07-12

## Scope

- Added a dependency-level SPDX 2.3 export for evidence packs.
- Added evidence-pack integrity verification with checksum validation and an optional downstream signature-verification seam.
- Added a CLI verifier: `pkgsafe report verify-evidence-pack`.
- Corrected release-verification documentation to reflect current npm/PyPI posture and the new evidence-pack verifier.

## Implemented changes

- `internal/report/sbom.go`
  - emits `dependency-sbom.spdx.json`
  - includes package identity, version, PURL external refs, and decision-oriented comments
- `internal/report/evidence_verify.go`
  - verifies evidence-pack manifest hashes
  - rejects path traversal / unexpected files
  - validates the dependency SBOM structure
  - supports an injected signature verifier for downstream signed packs
- `pkg/cli/report.go`
  - adds `pkgsafe report verify-evidence-pack`
- `docs/release-verification.md`
  - corrects npm/PyPI wording to public beta
  - documents evidence-pack verification

## Validation

Commands executed:

- `go test ./internal/report ./pkg/cli`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go run ./cmd/pkgsafe report evidence-pack --repo . --output <tmp>/evidence.zip`
- `go run ./cmd/pkgsafe report verify-evidence-pack --input <tmp>/evidence.zip --json`

Results:

- `go test ./internal/report ./pkg/cli` — PASS
- `go test ./...` — PASS
- `go test -race ./...` — PASS
- `go vet ./...` — PASS
- `pkgsafe report evidence-pack` — PASS
- `pkgsafe report verify-evidence-pack` — PASS

## Evidence observed

- Evidence pack manifest includes `dependency-sbom.spdx.json`.
- Verification reports `checksum_ok: true`.
- Unsigned packs verify successfully.
- Tampered evidence-pack content is rejected by unit tests.

## Known limitations

- Signed evidence packs still require a downstream signature-verification implementation.
- Dependency SBOM package entries are derived from the repository risk report, so empty reports produce an empty dependency list.
