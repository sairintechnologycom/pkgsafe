# PkgSafe v1.0.0

PkgSafe v1.0.0 is an npm-first supply-chain guardrail for package risk scoring, dependency inventory, OSV vulnerability intelligence, CI/SARIF output, policy enforcement, and release evidence generation.

PyPI, Go, and Cargo are included as preview/experimental ecosystem coverage. Behavior analysis is disabled by default; heuristic behavior analysis is opt-in and is not a security sandbox.

## Stage

- Readiness stage: PRODUCTION_GA_READY
- final_status: PRODUCTION_GA_READY
- ga_ready: true
- production_ready: true
- real_repo_validation_count: 15
- false_block_count: 0
- scanner_crash_count: 0

## Highlights

- npm-first package safety CLI for developer and AI-agent workflows.
- Package risk scoring with policy-based allow, warn, and block decisions.
- Dependency inventory and lockfile-aware scanning.
- OSV vulnerability intelligence with local cache support.
- CI outputs, including SARIF and machine-readable JSON.
- MCP-compatible JSON-RPC tools for AI-agent package validation.
- Signed release checksums, per-archive SBOMs, and GitHub build-provenance attestations.
- GA evidence generation for production release governance.

## Release Integrity

This release was verified from downloaded GitHub release assets.

- checksums: passed
- cosign signature: passed
- GitHub artifact attestations: passed for all binary archives
- production readiness: PRODUCTION_GA_READY
- final install smoke test: passed

Evidence is recorded in `evidence/releases/v1.0.0/`.

## Known Limitations

- GA v1 scope is npm-first.
- PyPI, Go, and Cargo coverage is preview/experimental and not npm-equivalent.
- Behavior analysis is disabled by default.
- Heuristic behavior analysis is opt-in host execution and is not a security sandbox.

## Verify Release Integrity

```sh
shasum -a 256 -c checksums.txt

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/sairintechnologycom/pkgsafe/.github/workflows/release.yml@refs/tags/v1\.0\.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

gh attestation verify <artifact> \
  --repo sairintechnologycom/pkgsafe \
  --signer-workflow github.com/sairintechnologycom/pkgsafe/.github/workflows/release.yml
```

## Changelog

- `ebd07e9`: Record v1.0.0-rc.1 GA evidence
