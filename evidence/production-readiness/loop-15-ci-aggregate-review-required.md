# Loop 15 — CI aggregate `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in CI scan summaries.
- Update CI workflow-result text and human summary output.
- Keep the CI gate behavior aligned with the agent-facing contract.

## Fix implemented

Updated the CI summary model and markdown/text generation so `types.DecisionReviewRequired` is represented explicitly instead of collapsing into warn/block-only summaries.

Files changed:

- `internal/ci/result.go`
- `internal/ci/scan.go`
- `internal/ci/summary.go`
- `internal/ci/scan_test.go`

Behavior after the change:

- CI summary counts now include `review_required`.
- Overall CI decision now preserves `review_required` when present.
- Human summary output now shows:
  - `Review Required`
  - `Warn / Review / Block Findings`
- Workflow-result text now explicitly mentions `REVIEW_REQUIRED`.

## Validation commands

```bash
gofmt -w internal/ci/result.go internal/ci/scan.go internal/ci/summary.go internal/ci/scan_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/ci -run '^(TestWriteSummaryOutputIncludesActionContext|TestCI_VulnerabilitySummaryOutputs)$'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused CI tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- This loop only hardens the CI aggregation layer.
- The repository still contains additional non-agent summary/report surfaces that may need the same treatment if we continue the same one-fix-at-a-time pattern.
