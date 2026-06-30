# PkgSafe v1.0.0-rc.1 GA Candidate Evidence

## Final Status

- final_status: PRODUCTION_GA_READY
- ga_ready: true
- production_ready: true
- real_repo_validation_count: 15
- repo_validation_pass_rate: 1.00
- false_block_count: 0
- scanner_crash_count: 0

## Release Integrity

- checksums_verified: true
- sbom_verified: true
- signing_verified: true
- provenance_verified: true

## Release Artifact Verification

- checksums: passed for all release archives and SBOMs
- cosign signature: passed for checksums.txt
- GitHub artifact attestations: passed for all binary archives

## RC Install Smoke Test

- archive: pkgsafe_1.0.0-rc.1_darwin_arm64.tar.gz
- `pkgsafe version`: pkgsafe 1.0.0-rc.1 (ec1d528)
- `pkgsafe doctor --skip-network`: PASS
- `pkgsafe test rollout-readiness`: PASS
- expected warnings/skips: network checks skipped; local `python` command not found in PATH

## Evidence Artifacts

- production-readiness-ga-candidate.json
- pkgsafe-ga-candidate-evidence.zip

## Scope

PkgSafe v1.0.0 GA is npm-first.

PyPI, Go, and Cargo coverage remains preview/experimental unless separately promoted.
Behavior analysis is disabled by default. Heuristic behavior analysis is opt-in and is not a security sandbox.
