# Loop 20 — CLI report summary `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in the CLI `report generate` summary output.
- Make the command-line report summary print the new decision state explicitly.

## Fix implemented

Updated `pkg/cli/report.go` so the repository-risk report summary output surfaces `REVIEW_REQUIRED` rather than flattening everything into ALLOW/WARN/BLOCK.

Files changed:

- `pkg/cli/report.go`
- `pkg/cli/main_test.go`

Behavior after the change:

- `report generate` now prints `REVIEW_REQUIRED` as the overall decision when present.
- The summary includes a `Review required` count.
- The decision helper is covered by a unit test.

## Validation commands

```bash
gofmt -w pkg/cli/report.go pkg/cli/main_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./pkg/cli -run '^(TestReportOverallDecisionReviewRequired|TestReportCommandCLI|TestReorderFlagsAllowsTrailingCommandFlags)$'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused CLI tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- This loop only hardened the repository-risk CLI summary output.
- The remaining report/export surfaces are already substantially aligned; additional loops would be incremental polish rather than a new contract class.
