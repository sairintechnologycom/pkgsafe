# Loop 14 — CLI aggregate `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in CLI summary reducers.
- Make CLI summary failures treat `REVIEW_REQUIRED` as a readiness gate.
- Keep history and scan summaries visually distinct from plain ALLOW/WARN output.

## Fix implemented

Updated `pkg/cli/main.go` so aggregate reducers and scan summaries preserve `REVIEW_REQUIRED` instead of flattening it into `WARN` or `ALLOW`.

Files changed:

- `pkg/cli/main.go`
- `pkg/cli/main_test.go`

Behavior after the change:

- Audit history aggregation recognizes:
  - `BLOCK`
  - `REVIEW_REQUIRED`
  - `WARN`
- Per-file scan summaries recognize:
  - `BLOCK`
  - `REVIEW_REQUIRED`
  - `WARN`
- Final scan failure now treats `REVIEW_REQUIRED` as a blocking readiness condition.
- CLI summary helpers now centralize the precedence logic.

## Validation commands

```bash
gofmt -w pkg/cli/main.go pkg/cli/main_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./pkg/cli -run '^(TestAggregateSummaryDecisionReviewRequired|TestSummaryDecisionHelpersReviewRequired|TestReorderFlagsAllowsTrailingCommandFlags)$'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused CLI summary tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- This loop only hardens the CLI aggregation/reporting layer.
- The CI scan JSON reducer still has its own decision-state gap and should be handled in a later loop if we continue the same pattern.
