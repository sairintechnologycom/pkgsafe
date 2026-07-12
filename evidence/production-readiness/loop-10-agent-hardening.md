# Loop 10 — Agent / vibe-coding hardening

Date: 2026-07-12

Scope of this loop:

- Close the `REVIEW_REQUIRED` contract gap in the MCP agent guidance path.
- Keep agent-facing decision strings consistent with the internal decision model.
- Verify the change with focused and repository-wide validation.

## Fix implemented

Updated the MCP guidance path so `types.DecisionReviewRequired` is preserved as `REVIEW_REQUIRED` instead of collapsing to `BLOCK`.

Files changed:

- `internal/mcp/agent_guidance.go`
- `internal/mcp/get_agent_guidance.go`
- `internal/mcp/check_package.go`
- `internal/mcp/get_agent_guidance_test.go`

Behavior after the change:

- `GetAgentGuidance(...)` returns `REVIEW_REQUIRED` when the internal decision is `types.DecisionReviewRequired`.
- `check_package` now serializes `REVIEW_REQUIRED` correctly through `decisionString(...)`.
- `get_agent_guidance` now documents `REVIEW_REQUIRED` as a supported decision value and its integration test accepts it.
- `validate_package_install` now produces an explicit human-review instruction for `REVIEW_REQUIRED` instead of falling back to a generic deny message.
- The agent guidance contract now exposes:
  - allowed next actions: `ask_user`, `request_review`, `suggest_alternative`, `remove_dependency`
  - prohibited actions: `run_install`, `execute_lifecycle_script`

## Validation commands

```bash
gofmt -w internal/mcp/agent_guidance.go internal/mcp/check_package.go internal/mcp/get_agent_guidance_test.go
env GOCACHE=/private/tmp/pkgsafe-gocache go test ./internal/mcp -run '^(TestGetAgentGuidance_Unit|TestDecisionString_ReviewRequired|TestGetAgentGuidanceTool_ToolList|TestGetAgentGuidanceTool_ToolError_MissingName|TestGetAgentGuidanceTool_ToolError_InvalidJSON|TestGetAgentGuidanceTool_ToolError_BadPolicyPath|TestGetAgentGuidanceTool_WithPolicy)$'
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

- No sandbox-specific failure was encountered in the final repo-wide validation run.
- This loop only addressed the `REVIEW_REQUIRED` agent-contract drift. It did not expand the scope to other MCP decision paths.
