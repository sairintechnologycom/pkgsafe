# Loop 07 - MCP / AI Agent Guardrail Pro Foundation

Date: 2026-07-01
Branch: loop-07-mcp-ai-agent-guardrail
Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/24

## Feature Spec

Strengthen MCP guardrails for AI coding agents. This loop kept PkgSafe local-first, npm-first GA, and did not add SaaS, billing, SSO, hosted services, or behavior-analysis execution by default.

## Files Changed

Loop 7 changes:

- `internal/mcp/agent_guidance.go`
- `internal/mcp/protocol.go`
- `internal/mcp/server_test.go`
- `internal/mcp/validate_install_command.go`
- `internal/mcp/validate_package_install.go`
- `evidence/loops/loop-07-mcp-ai-agent-guardrail.md`

The branch is stacked on uncommitted Loop 1-6 work, which was preserved and reused.

## Already Implemented And Reused

- Existing MCP stdio server and JSON-RPC routing.
- Existing MCP tools:
  - `validate_package_install`
  - `validate_install_command`
  - `explain_package_risk`
  - `suggest_safe_alternative`
  - `score_lockfile`
- Existing npm and PyPI scanners.
- Existing install-command parser for npm and pip commands.
- Existing policy controls where AI-agent WARN does not install by default.
- Existing local audit logger from install interception.
- Existing behavior-analysis response field named `behavior_analysis`.

## Newly Implemented

- Added `agent_instruction` to `validate_package_install` responses.
- Added `agent_instruction` to `validate_install_command` responses.
- Agent instruction actions:
  - `proceed`
  - `ask_human`
  - `never_install`
- Made MCP tool descriptions explicit: BLOCK means never install, WARN means ask a human for AI agents.
- Added `requested_by` input to `validate_install_command`, defaulting to `ai_agent`.
- Added local audit events for MCP package validation decisions.
- Added local audit events for MCP install-command validation decisions.
- Updated `explain_package_risk` schema to include PyPI, matching existing implementation support.
- Added MCP tests for:
  - BLOCK response maps to `never_install`
  - WARN AI-agent response maps to non-installable instruction
  - human WARN response still advises review
  - command validation includes agent instruction
  - MCP audit log entries are written
  - malformed stdio request returns JSON-RPC parse error only on stdout

## Validation Commands Run

```bash
gofmt -w internal/mcp/agent_guidance.go internal/mcp/validate_package_install.go internal/mcp/validate_install_command.go internal/mcp/protocol.go internal/mcp/server_test.go
go test ./internal/mcp
go test ./...
go test -race ./...
go vet ./...
make build
make package
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | ./dist/pkgsafe mcp serve --offline
printf '%s\n' '{bad json}' | ./dist/pkgsafe mcp serve --offline
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_package_install","arguments":{"ecosystem":"npm","offline":true}}}' | ./dist/pkgsafe mcp serve --offline
! rg -n "secure sandbox|secure containment|full PyPI|full Go|full Cargo|SaaS|billing|SSO|hosted service|npm_secret|user:pass" internal/mcp docs/mcp-* docs/ai-agent-install-safety.md
```

## Test Results

- `gofmt`: pass
- `go test ./internal/mcp`: pass
- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `make build`: pass
- `make package`: pass
- MCP stdio tools/list sample: pass
- MCP stdio malformed request sample: pass
- MCP structured tool error sample: pass
- Wording/secrets audit: pass

## Sample MCP Evidence

Tool schema advertises agent guardrail semantics:

```json
{
  "name": "validate_package_install",
  "description": "Validate whether a package should be installed. For AI agents, BLOCK means never install and WARN means ask a human before installing."
}
```

Malformed request returns JSON-RPC only on stdout:

```json
{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: invalid character 'b' looking for beginning of object key string"}}
```

Structured tool error:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"error\": {\n    \"code\": \"MISSING_PACKAGE_NAME\",\n    \"message\": \"Package name is required\"\n  }\n}"
      }
    ],
    "isError": true
  }
}
```

Tested agent response behavior:

- BLOCK package: `agent_instruction.action == "never_install"` and `install_allowed == false`
- WARN package for AI agent: `install_allowed == false` and instruction tells the agent not to install automatically
- WARN package for human: `agent_instruction.action == "ask_human"`
- Install command validation: response includes `agent_instruction` and writes an MCP audit event

## Wording Audit

- No Loop 7 code or docs claim secure sandboxing or secure containment.
- Existing legacy `sandbox` MCP input remains only as a deprecated compatibility alias for `behavior_mode=heuristic`.
- Tool schema explicitly says heuristic behavior runs on the host without isolation and is not a security sandbox.
- No Loop 7 work claims full PyPI, Go, or Cargo GA.
- No SaaS, billing, SSO, hosted-service, or behavior-analysis default enablement was introduced.

## Review Loop

- AI agents now receive explicit, deterministic next-step instructions.
- BLOCK remains non-installable.
- WARN remains non-installable by default for AI agents and maps to human review.
- MCP stdio emits JSON-RPC responses only on stdout.
- Local audit events provide traceability for MCP package and command decisions without implying hosted telemetry.

## Learning Loop

- Existing MCP guardrails were already strong on decisions and stdio behavior.
- The missing layer was agent-readable instruction shape and local audit evidence.
- Future agent docs should include concrete Codex/Cursor/Claude examples that inspect `agent_instruction.action`.
- Safe alternatives are currently strongest for npm and should remain npm-first until another ecosystem is explicitly promoted.

## Known Limitations

- MCP audit logging uses the existing local install-interception audit log format.
- `validate_install_command` validates parsed packages but does not execute installs.
- Safe alternative suggestions remain npm-focused.
- PyPI is supported in MCP validation/explain paths but remains preview, not GA.
- The branch remains stacked on uncommitted Loop 1-6 changes.

## Completion Criteria

- MCP guardrail response semantics strengthened: complete.
- WARN means ask-human for AI agents: complete.
- BLOCK means never install: complete.
- Agent audit events written locally: complete.
- MCP stdio tests pass: complete.
- All required validation commands pass: complete.
