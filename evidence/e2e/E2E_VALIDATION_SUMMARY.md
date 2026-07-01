# PkgSafe E2E Release Qualification Summary

Date: 2026-07-01
Branch: e2e-release-qualification
Commit SHA: b09b204c3faaf561d9bd1d797487cc6c6d96b8b7
Version tested: v0.2.0-beta.1-3-gb09b204-dirty (b09b204)

## Final Classification

E2E_PASS: false
release_candidate_ready: false
regression_blockers: 1
security_blockers: 0

Recommended next action: fix the PyPI connected benchmark false blocks, then rerun the full E2E gate from a clean release commit with signed/provenance artifacts available.

## Summary

The build, unit/race/vet gates, package generation, team evidence, GA evidence, CI outputs, feedback workflow, policy validation, private registry routing, MCP stdio, offline bundle verify/import, isolated behavior fail-closed behavior, and secret leakage sweep passed.

The run does not qualify as release-candidate ready because production readiness reports `ga_ready=false` and `production_ready=false`. The connected online benchmark still fails for 9 PyPI known-good package expectation mismatches. Local signing/provenance verification is also unavailable in this dirty local build, which is a release-artifact caveat rather than a product security failure.

During E2E, policy pack verification exposed a blocking version-compatibility bug. The bug was fixed narrowly in:

- `internal/enterprise/metadata.go`
- `internal/policy/resolver.go`

The full build/test/package gate was rerun after the fix and passed.

## Commands Run

- `git checkout -b e2e-release-qualification`
- `gofmt -w .`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `make build`
- `make package`
- `./dist/pkgsafe test rollout-readiness`
- `./dist/pkgsafe test benchmark --repo-list benchmarks/real-repos.json --json`
- `./dist/pkgsafe test production-readiness --repo-list benchmarks/real-repos.json --json`
- `./dist/pkgsafe report team-evidence --repo-list benchmarks/real-repos.json --output e2e-team-evidence.zip`
- `./dist/pkgsafe report ga-evidence --repo-list benchmarks/real-repos.json --output e2e-ga-evidence.zip --json-output e2e-ga-evidence.json`
- `./dist/pkgsafe ci scan --fail-on block --json-output pkgsafe-results.json --sarif-output pkgsafe-results.sarif --summary-output pkgsafe-summary.md`
- `./dist/pkgsafe feedback create --input e2e-warning-result.json --reason "..."`
- `./dist/pkgsafe policy validate default-policy.yaml`
- `./dist/pkgsafe policy explain default-policy.yaml`
- `./dist/pkgsafe policy test default-policy.yaml`
- `./dist/pkgsafe policy test testdata/policy-fixtures`
- `./dist/pkgsafe policy pack create --name e2e-default-policy --output e2e-policy-pack.tar.gz`
- `./dist/pkgsafe policy pack verify e2e-policy-pack.tar.gz`
- `./dist/pkgsafe registry test --policy testdata/registry-governance-policy.yaml --ecosystem npm --package @company/pkg`
- `./dist/pkgsafe registry test --policy testdata/registry-governance-policy.yaml --ecosystem pypi --package company_internal_pkg`
- `go test ./internal/... -run 'Private|Registry|Confusion|Redact'`
- `go test ./internal/... -run MCP`
- MCP JSON-RPC `tools/list` stdio smoke test
- `go test ./internal/... -run 'PyPI|Poetry|UV|Pipfile|Wheel|Sdist'`
- `./dist/pkgsafe update-db --ecosystem all`
- `./dist/pkgsafe db export-bundle --output e2e-osv-bundle.tar.gz`
- `./dist/pkgsafe db verify-bundle e2e-osv-bundle.tar.gz`
- `./dist/pkgsafe db import-bundle --db /tmp/pkgsafe-e2e-offline-home/.pkgsafe/pkgsafe.db e2e-osv-bundle.tar.gz`
- `HOME=/tmp/pkgsafe-e2e-offline-home ./dist/pkgsafe scan-npm-package lodash --version 4.17.20 --offline --json`
- `./dist/pkgsafe scan-local-npm ./testdata/npm/postinstall-curl --behavior isolated --json`
- Fake-secret production readiness run and recursive leakage sweep

## Stage Results

| Stage | Status | Evidence |
| --- | --- | --- |
| Freeze branch | PASS | Branch `e2e-release-qualification`, clean before E2E |
| Build/test/package | PASS | `go test`, race, vet, build, package passed after fix |
| Readiness gates | FAIL for RC | `private_beta_ready=true`, `ga_ready=false`, `production_ready=false` |
| Team evidence | PASS | `e2e-team-evidence.zip` |
| GA evidence | PASS with caveat | `e2e-ga-evidence.zip`; readiness inside is not GA-ready |
| CI output | PASS | JSON, SARIF, Markdown generated for node-backend-api fixture |
| Feedback workflow | PASS | `e2e-feedback.json` includes fingerprint and rule IDs |
| Policy pack | PASS after fix | Pack verification initially failed, then passed after version parsing fix |
| Private registry | PASS | Private npm/PyPI routing and redaction checks passed |
| MCP guardrail | PASS | JSON-RPC stdout only; stderr separated; MCP tests passed |
| PyPI depth | FAIL for RC | PyPI tests pass, but connected benchmark has 9 known-good false blocks |
| Offline bundle | PASS with caveat | Bundle verifies/imports; fresh offline package scan requires cached package metadata |
| Isolated behavior | PASS | macOS backend unavailable, fails closed with `executed=false` |
| Secret sweep | PASS | No fake secret markers found in generated outputs or ZIP payloads |

## Key Metrics

- scanner_crash_count: 0
- false_block_count on real-repo validation: 0
- real_repo_validation_count: 15
- repo_validation_pass_rate: 1.0
- private_beta_ready: true
- ga_ready: false
- production_ready: false
- online_benchmark_status: fail
- PyPI connected expectation_mismatch_count: 9
- secret leakage findings: 0
- MCP stdout pollution: 0

## Artifacts Copied

- `evidence/e2e/e2e-production-readiness.json`
- `evidence/e2e/e2e-benchmark.json`
- `evidence/e2e/e2e-team-evidence.zip`
- `evidence/e2e/e2e-ga-evidence.zip`
- `evidence/e2e/e2e-feedback.json`
- `evidence/e2e/e2e-offline-scan.json`
- `evidence/e2e/e2e-isolated-behavior.json`

## Blockers

1. PyPI connected benchmark false-blocks 9 known-good packages:
   `requests`, `fastapi`, `flask`, `click`, `pydantic`, `pytest`, `urllib3`, `pandas`, and `idna`.

## Caveats

- Signed release artifacts and build provenance are configured but not verified locally for this dirty E2E build.
- The version under test is `v0.2.0-beta.1-3-gb09b204-dirty`, not a clean v1.0.x release artifact.
- `PKGSAFE_HOME` is not honored by DB import in this build; isolated DB import used the supported `--db` flag.
- Fresh-home offline package scan failed until `lodash@4.17.20` package metadata was seeded; after seeding, the offline scan succeeded against the imported DB.
- Isolated behavior backend is unavailable on this macOS host and correctly fails closed.
