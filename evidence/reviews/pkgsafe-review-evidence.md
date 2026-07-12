# PkgSafe Review Evidence Record

Date: 2026-07-11  
Commit: `df143fe6eec47d02632b757987c2babe14561981`  
Version description: `v1.6.0-51-gdf143fe`  
Host: macOS, Asia/Kolkata review session; Linux bubblewrap unavailable.  
Primary report: `docs/reviews/pkgsafe-full-product-review.md`

## Evidence rules

This record contains observed command results and inspected code paths. It does not treat documentation, file names, or skipped tests as proof. No secrets or registry credentials are reproduced. No product code or claims were changed.

## Command ledger

| Command | Exit | Observed result |
| --- | ---: | --- |
| `go run ./cmd/pkgsafe --help` | 1 | Printed usage, then `unknown command "--help"`. |
| `gofmt -l .` | 0 | Listed 12 unformatted Go files; `-w` was intentionally not used in a review-only task. |
| `go test ./...` | 0 | All tested packages passed. |
| `go test -race ./...` | 0 | All tested packages passed under race detector. |
| `go vet ./...` | 0 | No diagnostics. |
| `make build` | 0 | Built `dist/pkgsafe`. |
| `make package` | 0 | Built Linux/Darwin/Windows binaries, archives, checksums, minimal SPDX. |
| `make check-public-boundary` | 0 | Reported no obvious leakage. |
| `/tmp` boundary negative fixture | 1 | Correctly rejected a file containing `premium implementation`. |
| `./dist/pkgsafe test corpus --json` | 0 | 30/30 fixture results passed. |
| `./dist/pkgsafe test benchmark --json --offline` | 0 | Status `PRIVATE_BETA_ACCURACY_CANDIDATE`; 1 scanned/cache hit, 24 skipped/cache miss, 0 real repos. |
| `./dist/pkgsafe test rollout-readiness --json` | 0 | `PRIVATE_BETA_READY`; archive, redaction, MCP, registry routing, install, malformed-input gates passed. |
| `./dist/pkgsafe test production-readiness --json` | 1 | `BLOCKED`; zero real repos, timing absent, signatures/provenance not locally verified. |
| `./dist/pkgsafe db status --json` | 0 | 260,056 vulnerability records; DB stale; offline-ready true. |
| `./dist/pkgsafe policy validate default-policy.yaml` | 0 | Policy valid. |
| `./dist/pkgsafe inventory . --json` | 0 | Inventory generated; included repository fixtures and generated editor JS. |
| `./dist/pkgsafe scan . --offline --json` | 0 | Cached Go scans emitted; behavior mode disabled. |

Named passing Go test events observed: 389. Named skipped test events: 0. The authoritative `go test ./...` exit was 0. Connected package validation was environmentally unavailable: production-readiness reported 25 network-unavailable packages, zero attempted live validations.

## Formatting evidence

`gofmt -l .` listed:

- `internal/analyzer/cargo/analyzer.go`
- `internal/cli/doctor.go`
- `internal/cli/update_db.go`
- `internal/intercept/enforcement.go`
- `internal/mcp/get_agent_guidance_test.go`
- `internal/output/output.go`
- `internal/policy/policy.go`
- `internal/registry/pypi/pep440.go`
- `internal/scanner/cargo/scanner_test.go`
- `internal/typosquat/pypi_test.go`
- `internal/typosquat/typosquat.go`
- `pkg/cli/main.go`

## Code-path evidence for critical findings

### Exception can downgrade registry/source hard blocks

`internal/risk/policy_controls.go` adds registry findings and score, computes `hasMalware` only for `known_malware_indicator`, `credential_path_reference`, or enabled strict-mode rules in block mode, then applies an active exception to any `BLOCK` when `!hasMalware`. Default rules `dependency_confusion_candidate`, `private_scope_public_registry`, and `unapproved_registry_url` score 100 but are not declared `BlockInStrictMode`. Therefore an active exception can reduce these blocks to WARN. This is a code-confirmed precedence defect; the review did not alter policy fixtures to exploit it.

### Offline plus heuristic behavior is not network-offline

CLI/MCP paths independently set `Offline` and `BehaviorMode`. `internal/sandbox/runner.go` states that heuristic mode executes on the host and that `network_mode=disabled` is not enforced. There is no global rejection of offline plus heuristic. Registry/OSV offline behavior passed in the exercised disabled-behavior scan, but full offline semantics fail by construction when heuristic execution is requested.

### Public entitlement implementation bypasses keyword boundary check

`pkg/license/license.go` implements signed entitlement parsing/verification/status/feature access. `pkg/cli/main.go` carries `RunConfig.Entitlement`; public CLI enterprise dispatch/tests contain premium feature gates. `docs/architecture/open-core-boundary.md` prohibits licensing enforcement and hidden premium logic in public code. `scripts/check-public-boundary.sh` searches “license server” but not entitlement/license verifier symbols, so the real check passes. The isolated negative fixture proves only that recognized keywords fail.

## Readiness evidence

Production-readiness blockers reported verbatim as categories (not full output):

- real-repository validation count below threshold (0 of required 15);
- npm real-repository count below threshold;
- average and p95 scan duration not reported;
- signed release artifacts not verified locally;
- build provenance not verified locally;
- isolated backend unavailable;
- online benchmark `no_network` with all 25 packages unavailable.

The offline benchmark reported `packages_tested: 1`, `packages_passed: 1`, `offline_cache_hits: 1`, `offline_cache_misses: 24`, while skipped package records also carried `passed: true`. This is why the review does not accept its aggregate candidate label.

## Scope limitations

- Network restrictions prevented live npm/PyPI registry and OSV validation.
- macOS prevented runtime validation of the Linux bubblewrap isolated backend.
- No external real repositories were cloned or scanned; configured paths are local synthetic fixtures.
- No signed published release or GitHub build-provenance attestation was verified.
- Shell-manager binaries were not allowed to install packages during this review; enforcement was assessed through tests, readiness gates, and code inspection.
- The report does not claim exhaustive manual review of every rule or every serialization field.

## Artifact hygiene

Build/package outputs remained under ignored `dist/`. Review artifacts contain no generated binary, token, credential, customer configuration, or temporary archive. `git status --short` was clean immediately before report creation.
