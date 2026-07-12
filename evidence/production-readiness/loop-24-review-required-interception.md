# Loop 24 — REVIEW_REQUIRED Install Interception

Date: 2026-07-12

## Feature spec

A `REVIEW_REQUIRED` package must not be installed by generic npm/pip/python
interception. Local confirmation and risk-acceptance flags are not substitutes
for an authorized approval record.

## Build loop

- Added explicit `REVIEW_REQUIRED` handling to `CanProceed`.
- Rejected installation with the blocked exit class even when `--yes`,
  `--force-risk-accept`, and a local reason are present.
- Added decision aggregation precedence:
  `BLOCK > REVIEW_REQUIRED > WARN > ALLOW`.
- Added JSON remediation: request authorized human review before installation.
- Rendered `REVIEW_REQUIRED` with warning-class human output rather than ALLOW
  styling.
- Added the invariant to rollout and alpha readiness self-tests.

## Validation loop

Focused tests cover:

- REVIEW_REQUIRED dominates ALLOW and WARN;
- BLOCK dominates REVIEW_REQUIRED;
- no flags can locally override REVIEW_REQUIRED;
- the blocked exit class and authorized-review reason are stable.

Commands and results:

```text
go test ./internal/intercept ./internal/validation   PASS
make fmt-check                                      PASS
go test ./...                                       PASS
go vet ./...                                        PASS
golangci-lint v1.64.8 run --timeout 5m              PASS
go test -count=1 -race ./...                        PASS
```

## Review loop

Before this loop, `Validate` ignored `DecisionReviewRequired` during aggregate
reduction, so a review-required result could become aggregate ALLOW. Even if an
upstream caller supplied REVIEW_REQUIRED directly, `CanProceed` handled only
BLOCK and WARN and therefore returned true. Human output also used its default
green styling.

The corrected contract fails closed. A future approval workflow must introduce
an explicit, validated, auditable approval object before this decision can
proceed; generic local override flags remain insufficient.

## Completion gate

```text
REVIEW_REQUIRED aggregate preservation: PASS
REVIEW_REQUIRED install attempts: 0
--yes bypass: rejected
force-risk-accept bypass: rejected
JSON remediation: authorized review required
readiness invariant: PASS
repository tests/vet/lint/race: PASS
```
