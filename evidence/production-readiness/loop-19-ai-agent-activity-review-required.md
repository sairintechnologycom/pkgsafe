# Loop 19 — AI-agent activity report `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in the AI-agent activity report.
- Render review-required agent requests explicitly in the exported report.

## Fix implemented

Updated the AI-agent package safety report so review-required requests are counted and rendered explicitly instead of being hidden in warn/block-only metrics.

Files changed:

- `internal/report/markdown.go`
- `internal/report/exporters_test.go`

Behavior after the change:

- `ExportAIAgentActivityReport(...)` now counts `review_required` requests separately.
- The report now includes a `Review Required` metric.
- Review-required requests appear in a dedicated `Top Review Required Requests` section.

## Validation commands

```bash
gofmt -w internal/report/markdown.go internal/report/exporters_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/report -run '^(TestExportAIAgentActivityReportReviewRequired|TestExportAIAgentActivityReport|TestExportMarkdownReviewRequired|TestExportHTMLReviewRequired|TestExportCIGateReportReviewRequired)$'
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

- This loop only hardened the AI-agent activity report.
- The remaining smaller exporter/report surfaces can still be reviewed individually if needed.
