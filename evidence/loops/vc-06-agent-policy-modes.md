# Loop VC-6 - Agent Policy Modes Evidence

Date: 2026-07-09
Branch: feat/agent-package-guardrail

## Feature Spec

Introduce first-class configuration parameters for AI agent dependency policies in `policy.yaml`.

Configuration Schema:
```yaml
agent_policy:
  mode: block                            # observe, warn, block
  warn_requires_human: true              # agents must request human review for WARN decisions
  block_install_commands: true           # agents cannot execute install commands autonomously
  allow_agent_exceptions: false          # agents cannot bypass policy rules/exceptions
  require_pkg_safe_check_before_install: true # agents are strictly required to check package first
```

## Files Created/Modified

- `internal/policy/policy.go` (modified): Defined `AgentPolicy` type and added it to `Policy` struct. Configured fallback default values and updated parser logic.
- `internal/policy/resolver.go` (modified): Merged override `AgentPolicy` settings into default policy object.
- `internal/policy/policy_test.go` (modified): Added `TestLoadAgentPolicy` test.
- `internal/risk/policy_controls.go` (modified): Suppressed active policy exceptions if `AllowAgentExceptions` is disabled for AI agents.
- `internal/mcp/check_package.go` (modified): Implemented `ApplyAgentPolicyOverrides` helper and processed overrides inside `CheckPackage`.
- `internal/mcp/check_install_command.go` (modified): Processed `ApplyAgentPolicyOverrides` overrides in `CheckInstallCommand`.
- `internal/mcp/review_dependency_diff.go` (modified): Processed `ApplyAgentPolicyOverrides` overrides in `ReviewDependencyDiff`.
- `internal/mcp/server_test.go` (modified): Added `TestMCPAgentPolicy` test suite.

## Validation Results

Run full unit tests for policy and MCP server:
```bash
go test ./internal/policy/...
go test ./internal/mcp/...
go test ./...
```

All tests pass:
```text
ok  	github.com/sairintechnologycom/pkgsafe/internal/policy	2.248s
ok  	github.com/sairintechnologycom/pkgsafe/internal/mcp	10.712s
```

## Sample Policy Config Override Validation

When the policy has the following override configured:
```yaml
agent_policy:
  mode: block
  require_pkg_safe_check_before_install: true
```

Executing `check_package` for `fixture@2.0.0` (which normally returns `WARN` with score `35` under standard thresholds):

**Response**
```json
{
  "decision": "BLOCK",
  "risk_score": 35,
  "confidence": "high",
  "top_reasons": [
    "Package has custom postinstall scripts"
  ],
  "policy_result": "mode: warn, scan_decision: warn",
  "evidence_id": "pkg-20260709-668",
  "agent_instruction": "Do not install this package. The policy decision is BLOCK. A pre-install check is strictly required before proceeding.",
  "allowed_next_actions": [
    "suggest_alternative",
    "remove_dependency"
  ],
  "prohibited_actions": [
    "run_install",
    "execute_lifecycle_script"
  ]
}
```

The warning decision is successfully overridden to a hard **BLOCK**, the allowed actions are constrained to prevent installation, and the agent instruction is appended with check requirements!
