# Loop 3 - GitHub Action Pro Foundation Evidence

## Tracking

- Branch: `loop-03-github-action-pro-foundation`
- Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/20

## Files Changed

Loop 3 implementation:

- `action.yml`
- `cmd/pkgsafe/main.go`
- `docs/github-action.md`
- `internal/ci/result.go`
- `internal/ci/scan.go`
- `internal/ci/scan_test.go`
- `internal/ci/summary.go`
- `evidence/loops/loop-03-github-action-pro-foundation.md`
- `evidence/loops/loop-03-results.json`
- `evidence/loops/loop-03-results.sarif`
- `evidence/loops/loop-03-summary.md`
- `evidence/loops/loop-03-results-pass.json`
- `evidence/loops/loop-03-results-pass.sarif`
- `evidence/loops/loop-03-summary-pass.md`

Earlier Loop 1 and Loop 2 changes are also present in this working branch
because those loops are not yet committed or merged.

## Already Implemented And Reused

- Reused existing `pkgsafe ci scan` JSON, SARIF, and Markdown output flags.
- Reused existing changed-only branch diff behavior.
- Reused existing action output variables for decision, risk score, counts, JSON,
  SARIF, Markdown, and evidence pack paths.
- Reused existing GitHub Action SARIF upload and PR comment behavior.
- Reused existing fail-on exit behavior.

## Newly Implemented

- `--baseline` now supports either a Git ref or an existing baseline
  `package-lock.json` file for changed-only scans.
- CI JSON results now include `baseline_type` (`file` or `git_ref`) when
  changed-only diffing succeeds.
- Markdown PR summaries now include workflow result, ecosystem, lockfile or
  dependency files, changed-only state, baseline source/type, a compact counts
  table, clearer findings sections, and fail-on-specific recommended action.
- GitHub Action docs now describe baseline file workflows, fail-on behavior, and
  SARIF permissions.
- Action docs now match both `action.yml` inputs and outputs.
- Added tests for baseline-file changed-only scans and Markdown summary context.

## Validation Commands

```text
gofmt -w cmd/pkgsafe/main.go internal/ci/result.go internal/ci/scan.go internal/ci/summary.go internal/ci/scan_test.go  PASS
go test ./internal/ci ./cmd/pkgsafe                                      PASS
go test ./...                                                            PASS
go test -race ./...                                                      PASS
go vet ./...                                                             PASS
make build                                                               PASS
make package                                                             PASS
./dist/pkgsafe ci scan --lockfile testdata/ci-scenarios/warn/package-lock.json --changed-only --baseline testdata/ci-scenarios/safe/package-lock.json --fail-on block --json-output evidence/loops/loop-03-results.json --sarif-output evidence/loops/loop-03-results.sarif --summary-output evidence/loops/loop-03-summary.md --offline  EXPECTED EXIT 1
./dist/pkgsafe ci scan --lockfile testdata/ci-scenarios/warn/package-lock.json --changed-only --baseline testdata/ci-scenarios/safe/package-lock.json --fail-on none --json-output evidence/loops/loop-03-results-pass.json --sarif-output evidence/loops/loop-03-results-pass.sarif --summary-output evidence/loops/loop-03-summary-pass.md --offline  PASS
JSON/SARIF parse checks                                                   PASS
SARIF structure check                                                     PASS
action.yml/docs input consistency check                                   PASS
action.yml/docs output consistency check                                  PASS
workflow YAML parse check                                                 PASS
Markdown link check                                                       PASS
wording guardrail check                                                   PASS
```

## Sample Output

`--fail-on block` correctly returned nonzero because the changed dependency
scan found a BLOCK:

```text
Changed dependency scan enabled.
Baseline: testdata/ci-scenarios/safe/package-lock.json
Baseline Type: file
Changed packages found: 1

- esbuild: added 0.19.0

Decision: BLOCK
Fail On: BLOCK
Packages Scanned: 1
```

The report-only variant with `--fail-on none` generated the same JSON, SARIF,
and Markdown evidence while exiting successfully.

## Evidence Generated

- Sample JSON: `evidence/loops/loop-03-results.json`
- Sample SARIF: `evidence/loops/loop-03-results.sarif`
- Sample PR summary: `evidence/loops/loop-03-summary.md`
- Passing report-only JSON: `evidence/loops/loop-03-results-pass.json`
- Passing report-only SARIF: `evidence/loops/loop-03-results-pass.sarif`
- Passing report-only PR summary:
  `evidence/loops/loop-03-summary-pass.md`

## Review Loop

- Easy to copy into GitHub: PASS. Docs include minimal, advanced, scheduled
  warmup, and baseline-file workflows.
- Noisy findings manageable: PASS. PR summary separates counts, warn/block
  findings, vulnerabilities, fixed versions, and action guidance.
- Fail-on behavior deterministic: PASS. `fail-on block` returned nonzero for a
  BLOCK sample; `fail-on none` reported without failing.
- Outputs useful in PR review: PASS. Summary includes baseline source/type,
  changed-only status, counts, top reason, and fixed-version recommendations.
- SARIF valid: PASS. Generated SARIF parses as version `2.1.0`.

## Learning Loop

- Baseline file support is valuable before hosted evidence because teams can
  manage approved snapshots directly in-repo.
- The most useful PR fields are decision, workflow result, fail-on threshold,
  changed-only state, baseline source, dependency counts, top reasons, and fixed
  versions.
- Future paid candidates remain hosted baselines, PR bots, organization policy
  drift, and multi-repo trend history. None were added in this loop.

## Known Limitations

- `--baseline` auto-detects a file only when the path exists locally; otherwise
  it continues to behave as a Git ref for compatibility.
- Baseline file support is currently npm lockfile based. PyPI, Go, and Cargo
  remain preview and were not promoted.
- Heuristic behavior analysis remains disabled by default and non-isolated when
  explicitly enabled.
- Local build/package validation used a dirty version string because prior loop
  changes are still uncommitted in the branch stack.
