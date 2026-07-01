# Loop 2 - Team Evidence Pack Evidence

## Tracking

- Branch: `loop-02-team-evidence`
- Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/19

## Files Changed

Loop 2 implementation:

- `cmd/pkgsafe/report.go`
- `cmd/pkgsafe/main.go`
- `cmd/pkgsafe/main_test.go`
- `evidence/loops/loop-02-team-evidence.md`

Loop 1 changes are also present in this working branch because Loop 2 was
started before Loop 1 was committed or merged:

- `action.yml`
- `docs/github-action.md`
- `docs/feedback.md`
- `.github/ISSUE_TEMPLATE/false_negative.yml`
- `docs/loop-engineering-roadmap.md`
- `evidence/loops/loop-01-v1.0.1-stabilization.md`

## Already Implemented And Reused

- Reused `validation.RunBenchmarkPackWithOptions` for repo-list validation,
  dependency counts, per-repo allow/warn/block counts, false-block counts,
  scanner crash counts, artifact status, OSV cache counts, and behavior mode.
- Reused `validation.RunProductionReadinessWithOptions` for OSV DB status and
  release verification status.
- Reused `policy.ResolvePolicy` for policy summary and policy evidence.
- Reused existing ZIP manifest shape from `internal/report.Manifest`.
- Reused existing secret redaction with `registry.RedactSecrets`.

## Newly Implemented

- Added `pkgsafe report team-evidence --repo-list <path> --output <zip>`.
- Added a team evidence ZIP with:
  - `manifest.json`
  - `summary/team-evidence-summary.json`
  - `summary/team-evidence-summary.md`
  - `per-repo/<repo>/summary.json`
  - `per-repo/<repo>/summary.md`
  - `policy/policy-summary.json`
  - `policy/policy-used.json`
  - `status/osv-db-status.md`
  - `status/release-verification-status.md`
  - `known-limitations.md`
- Added explicit empty repo-list validation with a clear error.
- Added deterministic ZIP file ordering and fixed ZIP entry timestamps.
- Added unit coverage for team evidence ZIP shape and empty repo-list failure.

## Validation Commands

```text
gofmt -w cmd/pkgsafe/report.go cmd/pkgsafe/main.go cmd/pkgsafe/main_test.go  PASS
go test ./cmd/pkgsafe                                                         PASS
go test ./...                                                                 PASS
go test -race ./...                                                           PASS
go vet ./...                                                                  PASS
make build                                                                    PASS
make package                                                                  PASS
./dist/pkgsafe report team-evidence --repo-list benchmarks/real-repos.json --output pkgsafe-team-evidence.zip  PASS
ZIP structure inspection                                                       PASS
Manifest inspection                                                            PASS
Targeted credential-value scan                                                 PASS
Missing repo path validation                                                   PASS
Empty repo-list validation                                                     PASS
```

## Command Output

```text
PkgSafe team evidence generated: pkgsafe-team-evidence.zip
Repositories: 15 passed / 0 failed
Summary: allow=12 warn=0 block=0 false_blocks=0 scanner_crashes=0
```

## Generated Evidence Pack

- File: `pkgsafe-team-evidence.zip`
- ZIP entries: 40
- Required artifacts present:
  - `pkgsafe-team-evidence/manifest.json`
  - `pkgsafe-team-evidence/summary/team-evidence-summary.json`
  - `pkgsafe-team-evidence/summary/team-evidence-summary.md`
  - `pkgsafe-team-evidence/per-repo/*/summary.json`
  - `pkgsafe-team-evidence/per-repo/*/summary.md`
  - `pkgsafe-team-evidence/policy/policy-summary.json`
  - `pkgsafe-team-evidence/status/osv-db-status.md`
  - `pkgsafe-team-evidence/status/release-verification-status.md`
  - `pkgsafe-team-evidence/known-limitations.md`

## Sample Summary

```text
Repositories: 15
Passed / failed: 15 / 0
Direct / transitive dependencies: 59 / 1
Allow / warn / block: 12 / 0 / 0
False blocks: 0
Scanner crashes: 0
OSV DB status: pass: OSV database is initialized
```

## Review Loop

- Useful to platform/AppSec teams: PASS. The bundle aggregates repository
  status, dependency counts, decisions, artifact availability, policy summary,
  OSV status, release verification status, and limitations in one ZIP.
- Shareable with auditors: PASS with caveat. It is local-first and redacted for
  secrets, but raw local paths can still appear in validation details when the
  underlying readiness report includes them.
- Avoids duplicating beta/GA evidence logic: PASS. It reuses existing benchmark,
  readiness, policy, manifest, and redaction paths.
- Remains local-first: PASS. No SaaS, hosted service, billing, or SSO was added.
- Avoids SaaS assumptions: PASS.

## Learning Loop

- Most useful team fields are repo name, ecosystem, dependency counts,
  allow/warn/block counts, false-block count, scanner-crash count, policy
  version, artifact status, scan timestamp, and PkgSafe version.
- Enterprise evidence will likely need better normalization of volatile runtime
  fields, local paths, and environment-specific release verification details.
- Paid candidates later: richer policy governance summaries, multi-team
  baselines, historical trend comparison, and hosted evidence review. None were
  added in this loop.
- This should remain local-only until a later loop explicitly introduces a
  hosted workflow.

## Known Limitations

- The ZIP layout and entry timestamps are deterministic, but generated evidence
  still includes scan timestamps and benchmark durations from the validation
  run.
- The local validation build reports a dirty version string because Loop 1 and
  Loop 2 changes are uncommitted in this branch.
- Production readiness in the sample bundle remains blocked by local signing and
  provenance verification status; this does not block the team-evidence command
  itself.
- PyPI remains preview coverage; no ecosystem promotion was introduced.
