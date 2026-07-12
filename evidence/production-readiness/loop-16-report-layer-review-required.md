# Loop 16 — Report layer `REVIEW_REQUIRED` preservation

Date: 2026-07-12

Scope of this loop:

- Preserve `REVIEW_REQUIRED` in the repository-risk report model.
- Render review-required findings explicitly in Markdown output.
- Keep recommendations and overall decision text aligned with the new state.

## Fix implemented

Updated the repository report model, generator, and Markdown exporter so `review_required` is represented as a first-class state in the repo-risk report.

Files changed:

- `internal/report/model.go`
- `internal/report/generator.go`
- `internal/report/markdown.go`
- `internal/report/exporters_test.go`

Behavior after the change:

- `RiskSummary` now tracks `ReviewRequired`.
- `GenerateReport(...)` counts `review_required` findings and emits review-required recommendations.
- `ExportMarkdown(...)`:
  - renders overall decision as `REVIEW_REQUIRED` when appropriate
  - shows a `Review Required` count in the summary table
  - includes `review_required` findings in the top findings table
  - keeps recommendation text explicit about authorized human review

## Validation commands

```bash
gofmt -w internal/report/model.go internal/report/generator.go internal/report/markdown.go internal/report/exporters_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/report -run '^(TestExportMarkdownReviewRequired|TestExportCSVAllTypes|TestExportCSVContentAndUnsupported|TestExportCSVRedactsSecrets|TestSeverityToSarifLevel|TestExportDependencyConfusionReport|TestExportAIAgentActivityReport|TestExportCIGateReportBlock|TestExportCIGateReportPass|TestExportCIGateReportErrors)$'
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

- This loop only fixed the repository-risk report layer.
- Other export surfaces may still need explicit `review_required` rendering if we continue hardening every summary path one at a time.
