# Loop 11 — Agent explain/remediation contract hardening

Date: 2026-07-12

Scope of this loop:

- Fix the `explain_policy_decision` agent path so `REVIEW_REQUIRED` gets explicit remediation guidance.
- Keep the agent-facing review contract consistent with the internal decision model.

## Fix implemented

Updated the policy explanation path so `types.DecisionReviewRequired` no longer falls through to the default remediation bucket.

Files changed:

- `internal/mcp/explain_policy_decision.go`
- `internal/mcp/get_agent_guidance_test.go`

Behavior after the change:

- `explain_policy_decision` now returns explicit remediation for `REVIEW_REQUIRED`:
  - request authorized human review
  - do not install automatically
  - use a safer alternative if available
- A regression test now covers the helper used by the explain path.

## Validation commands

```bash
gofmt -w internal/mcp/explain_policy_decision.go internal/mcp/get_agent_guidance_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/mcp -run '^(TestGetAgentGuidance_Unit|TestDecisionString_ReviewRequired|TestAgentInstruction_ReviewRequired|TestRemediationForDecision_ReviewRequired|TestGetAgentGuidanceTool_ToolList|TestGetAgentGuidanceTool_ToolError_MissingName|TestGetAgentGuidanceTool_ToolError_InvalidJSON|TestGetAgentGuidanceTool_ToolError_BadPolicyPath|TestGetAgentGuidanceTool_WithPolicy)$'
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

- This loop only fixed the explanation/remediation contract. It did not attempt to widen the `REVIEW_REQUIRED` state into other decision reducers.
