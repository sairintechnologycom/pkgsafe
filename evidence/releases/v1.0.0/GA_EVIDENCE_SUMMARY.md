# PkgSafe v1.0.0 GA Evidence

## Final Status

- final_status: PRODUCTION_GA_READY
- ga_ready: true
- production_ready: true
- real_repo_validation_count: 15
- false_block_count: 0
- scanner_crash_count: 0

## Release Integrity

- checksums_verified: true
- sbom_verified: true
- signing_verified: true
- provenance_verified: true

## Release Artifact Verification

- release workflow: passed
- checksums: passed
- cosign signature: passed
- GitHub artifact attestations: passed for all binary archives
- RC install smoke test: passed
- final install smoke test: passed

## Evidence Artifacts

- production-readiness-v1.0.0.json
- pkgsafe-v1.0.0-ga-evidence.zip

## Tag And Evidence Commits

The v1.0.0 release tag points to the commit used to build the verified binaries.
GA evidence commits were recorded after release verification and are intentionally
not part of the build input.

## Scope

PkgSafe v1.0.0 GA is npm-first.

PyPI, Go, and Cargo coverage remains preview/experimental unless separately promoted.
Behavior analysis is disabled by default. Heuristic behavior analysis is opt-in and is not a security sandbox.
