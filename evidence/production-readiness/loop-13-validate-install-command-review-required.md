# Loop 13 — `validate_install_command` REVIEW_REQUIRED hardening

Date: 2026-07-12

Scope of this loop:

- Fix the install-command reducer so `REVIEW_REQUIRED` is not flattened into `allow`.
- Make install gating explicit for the new decision state.

## Fix implemented

Updated `internal/mcp/validate_install_command.go` so package reductions that yield `types.DecisionReviewRequired` are preserved and treated as a hard review gate.

Files changed:

- `internal/mcp/validate_install_command.go`
- `internal/mcp/validate_install_command_test.go`

Behavior after the change:

- `REVIEW_REQUIRED` is now selected by the reducer when any scanned package returns that decision.
- `REVIEW_REQUIRED` disallows install.
- `REVIEW_REQUIRED` returns the explicit recommendation:
  - `Request authorized human review before installing.`

## Validation commands

```bash
gofmt -w internal/mcp/validate_install_command.go internal/mcp/validate_install_command_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/mcp -run '^(TestResolveValidateInstallDecisionReviewRequired|TestValidateInstallAllowedReviewRequired|TestValidateInstallRecommendedActionReviewRequired|TestGetAgentGuidance_Unit|TestDecisionString_ReviewRequired|TestAgentInstruction_ReviewRequired|TestRemediationForDecision_ReviewRequired|TestGetAgentGuidanceTool_ToolList|TestGetAgentGuidanceTool_ToolError_MissingName|TestGetAgentGuidanceTool_ToolError_InvalidJSON|TestGetAgentGuidanceTool_ToolError_BadPolicyPath|TestGetAgentGuidanceTool_WithPolicy)$'
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...
```

## Results

- Focused MCP tests: passed
- Repository tests: passed
- `go vet ./...`: passed
- `go test -race ./...`: passed

## Notes

- The reducer now behaves consistently with the already-hardened `REVIEW_REQUIRED` guidance, remediation, and CLI install gating.
