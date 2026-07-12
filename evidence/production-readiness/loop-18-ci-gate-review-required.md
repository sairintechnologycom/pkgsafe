# Loop 18 — CI gate report `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in the CI gate evidence exporter.
- Render review-required CI decisions and actions explicitly.

## Fix implemented

Updated the CI gate Markdown exporter so `review_required` decisions are rendered explicitly in exported evidence.

Files changed:

- `internal/report/markdown.go`
- `internal/report/exporters_test.go`

Behavior after the change:

- The CI gate evidence exporter now understands `review_required` in the serialized CI result summary.
- CI gate output now states that authorized human review is required when the decision is `review_required`.
- The findings table includes `REVIEW_REQUIRED` findings.
- The required-action section explicitly asks for authorized human review.

## Validation commands

```bash
gofmt -w internal/report/markdown.go internal/report/exporters_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/report -run '^(TestExportCIGateReportReviewRequired|TestExportMarkdownReviewRequired|TestExportHTMLReviewRequired|TestExportCSVAllTypes|TestExportCSVContentAndUnsupported|TestExportCSVRedactsSecrets|TestSeverityToSarifLevel|TestExportDependencyConfusionReport|TestExportAIAgentActivityReport|TestExportCIGateReportBlock|TestExportCIGateReportPass|TestExportCIGateReportErrors)$'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused report tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- This loop only hardened the CI gate evidence exporter.
- Other smaller export surfaces can still be evaluated in the same one-surface-at-a-time way if needed.
