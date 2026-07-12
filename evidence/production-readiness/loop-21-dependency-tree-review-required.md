# Loop 21 — Dependency Tree REVIEW_REQUIRED Semantics

## Feature spec

The dependency-tree output must preserve `REVIEW_REQUIRED` as a distinct gated decision. Risk-only pruning must retain dependencies that require authorized review, and the human-readable tree must not render them as unlabeled or neutral.

## Build loop

- Added an explicit `REVIEW_REQUIRED` dependency-tree label using warning-class color.
- Included `review_required` nodes in `--only-risky` pruning.
- Updated the `--only-risky` help text to name review-required decisions.
- Extracted the decision presentation mapping so the output contract can be tested without intercepting process stdout.

## Validation loop

The focused test verifies that:

- `review_required` maps to the visible `REVIEW_REQUIRED` label;
- it uses warning-class presentation rather than ALLOW presentation;
- it remains present when risk-only pruning is enabled.

Validation commands and final results:

```text
gofmt -w pkg/cli/main.go pkg/cli/main_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./pkg/cli -run '^TestDependencyTreeReviewRequiredPresentation$'  PASS
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...                                                     PASS
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...                                                      PASS
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...                                               PASS
```

## Review loop

CSV exporters were inspected first. They already preserve decision values directly and required no implementation change. The concrete gap was limited to the dependency-tree human-readable and pruning paths.

The default user-level Go build cache was unavailable in the restricted validation environment, so tests used an isolated cache under `/private/tmp`. This changes only build-cache placement, not test coverage or product behavior.

## Evidence loop

- `pkg/cli/main.go`
- `pkg/cli/main_test.go`

## Completion gate

```text
REVIEW_REQUIRED visible in dependency tree: PASS
REVIEW_REQUIRED retained by --only-risky: PASS
CLI help matches behavior: PASS
repository test suite: PASS
race detector: PASS
```
