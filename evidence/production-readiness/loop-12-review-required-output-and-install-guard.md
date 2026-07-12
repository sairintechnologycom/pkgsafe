# Loop 12 — `REVIEW_REQUIRED` output and install guard hardening

Date: 2026-07-12

Scope of this loop:

- Prevent `REVIEW_REQUIRED` from being treated as an install-safe default in user-facing output.
- Prevent `REVIEW_REQUIRED` from proceeding through the npm install path.

## Fix implemented

Updated the output and CLI install paths so `types.DecisionReviewRequired` is treated as a human-review gate, not as a safe install decision.

Files changed:

- `internal/output/output.go`
- `internal/output/output_test.go`
- `pkg/cli/main.go`

Behavior after the change:

- `RecommendedAction(...)` now returns:
  - `Request authorized human review before installing.`
- Lockfile report rendering now colors `REVIEW_REQUIRED` as a warning-class decision instead of a safe decision.
- `pkg/cli` install flow now rejects `REVIEW_REQUIRED` with an explicit human-review error.

## Validation commands

```bash
gofmt -w internal/output/output.go internal/output/output_test.go pkg/cli/main.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/output ./pkg/cli -run 'TestRecommendedActionReviewRequired|TestReorderFlagsAllowsTrailingCommandFlags'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused output/CLI tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- This loop hardens the user-facing contract even though the current scan path rarely emits `REVIEW_REQUIRED` directly.
- The change ensures future emission of that state will not slip through as a safe install recommendation.
