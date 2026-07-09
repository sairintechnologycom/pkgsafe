# Loop VC-1 - Agent-Safe MCP Contract Evidence

Date: 2026-07-09
Branch: loop-vc-01-agent-safe-mcp-contract

## Feature Spec

Define and harden PkgSafe MCP tools for package install decisions.

Required tools:
* `check_package`
* `check_install_command`
* `review_dependency_diff`
* `explain_policy_decision`
* `record_agent_decision`

Each tool returns a structured response matching the agent decision contract:
* `decision` (ALLOW, WARN, BLOCK, REVIEW_REQUIRED)
* `risk_score` (int)
* `confidence` (string)
* `top_reasons` ([]string)
* `policy_result` (string)
* `evidence_id` (string)
* `agent_instruction` (string)
* `allowed_next_actions` ([]string)
* `prohibited_actions` ([]string)

## Files Created/Modified

- `internal/mcp/check_package.go` (new)
- `internal/mcp/check_install_command.go` (new)
- `internal/mcp/review_dependency_diff.go` (new)
- `internal/mcp/explain_policy_decision.go` (new)
- `internal/mcp/record_agent_decision.go` (new)
- `internal/mcp/protocol.go` (modified)
- `internal/mcp/server.go` (modified)
- `internal/mcp/server_test.go` (modified)
- `internal/agent/install_command_parser.go` (modified)
- `internal/agent/agent_test.go` (modified)

## Validation Commands Run

```bash
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
make build
make package
```

## Test Results

- `gofmt`: pass
- `go test ./internal/mcp`: pass
- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `make build`: pass
- `make package`: pass

## Sample MCP Evidence

### 1. `check_package` (Safe Package)

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "check_package",
    "arguments": {
      "ecosystem": "npm",
      "name": "fixture",
      "version": "1.0.0"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"ALLOW\",\n  \"risk_score\": 0,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"No critical vulnerabilities found\",\n    \"No lifecycle scripts detected\",\n    \"Package age and project health acceptable\"\n  ],\n  \"policy_result\": \"mode: warn, scan_decision: allow\",\n  \"evidence_id\": \"pkg-20260709-001\",\n  \"agent_instruction\": \"Package may be installed.\",\n  \"allowed_next_actions\": [\n    \"proceed\"\n  ],\n  \"prohibited_actions\": []\n}"
      }
    ],
    "isError": false
  }
}
```

### 2. `check_package` (Warn Package)

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "check_package",
    "arguments": {
      "ecosystem": "npm",
      "name": "fixture",
      "version": "2.0.0"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"WARN\",\n  \"risk_score\": 35,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"Package has custom postinstall scripts\"\n  ],\n  \"policy_result\": \"mode: warn, scan_decision: warn\",\n  \"evidence_id\": \"pkg-20260709-002\",\n  \"agent_instruction\": \"Do not install automatically. Ask the user for approval or choose an existing dependency.\",\n  \"allowed_next_actions\": [\n    \"ask_user\",\n    \"suggest_alternative\",\n    \"remove_dependency\"\n  ],\n  \"prohibited_actions\": [\n    \"run_install\",\n    \"execute_lifecycle_script\"\n  ]\n}"
      }
    ],
    "isError": false
  }
}
```

### 3. `check_package` (Block Package)

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "check_package",
    "arguments": {
      "ecosystem": "npm",
      "name": "fixture",
      "version": "3.0.0"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"BLOCK\",\n  \"risk_score\": 100,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"Package version has a high severity advisory\",\n    \"Score clamped to 100\"\n  ],\n  \"policy_result\": \"mode: warn, scan_decision: block\",\n  \"evidence_id\": \"pkg-20260709-003\",\n  \"agent_instruction\": \"Do not install this package. The policy decision is BLOCK.\",\n  \"allowed_next_actions\": [\n    \"suggest_alternative\",\n    \"remove_dependency\"\n  ],\n  \"prohibited_actions\": [\n    \"run_install\",\n    \"execute_lifecycle_script\"\n  ]\n}"
      }
    ],
    "isError": false
  }
}
```

### 4. `check_install_command`

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "check_install_command",
    "arguments": {
      "command": "npm install fixture@3.0.0"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"BLOCK\",\n  \"risk_score\": 100,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"[fixture] Package version has a high severity advisory\",\n    \"[fixture] Score clamped to 100\"\n  ],\n  \"policy_result\": \"mode: warn\",\n  \"evidence_id\": \"pkg-20260709-004\",\n  \"agent_instruction\": \"Do not install this package. The policy decision is BLOCK.\",\n  \"allowed_next_actions\": [\n    \"suggest_alternative\",\n    \"remove_dependency\"\n  ],\n  \"prohibited_actions\": [\n    \"run_install\",\n    \"execute_lifecycle_script\"\n  ],\n  \"packages_detected\": [\n    {\n      \"ecosystem\": \"npm\",\n      \"name\": \"fixture\",\n      \"version\": \"3.0.0\",\n      \"decision\": \"BLOCK\",\n      \"risk_score\": 100\n    }\n  ],\n  \"safe_command\": null\n}"
      }
    ],
    "isError": false
  }
}
```

### 5. `explain_policy_decision`

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "explain_policy_decision",
    "arguments": {
      "package": "npm:fixture@3.0.0"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"BLOCK\",\n  \"risk_score\": 100,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"Package version has a high severity advisory\",\n    \"Score clamped to 100\"\n  ],\n  \"policy_result\": \"mode: warn, scan_decision: block\",\n  \"evidence_id\": \"pkg-20260709-005\",\n  \"agent_instruction\": \"Do not install this package. The policy decision is BLOCK.\",\n  \"allowed_next_actions\": [\n    \"suggest_alternative\",\n    \"remove_dependency\"\n  ],\n  \"prohibited_actions\": [\n    \"run_install\",\n    \"execute_lifecycle_script\"\n  ],\n  \"rule_ids\": [\n    \"known_vulnerability_high\",\n    \"score_clamped\"\n  ],\n  \"remediation\": [\n    \"Remove dependency\",\n    \"Use approved internal package\",\n    \"Request security exception\"\n  ]\n}"
      }
    ],
    "isError": false
  }
}
```

### 6. `record_agent_decision`

**Request**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "record_agent_decision",
    "arguments": {
      "ecosystem": "npm",
      "name": "fixture",
      "version": "1.0.0",
      "decision": "ALLOW",
      "action_taken": "installed",
      "agent": "codex"
    }
  }
}
```

**Response**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"decision\": \"ALLOW\",\n  \"risk_score\": 0,\n  \"confidence\": \"high\",\n  \"top_reasons\": [\n    \"Decision recorded successfully\"\n  ],\n  \"policy_result\": \"PASS\",\n  \"evidence_id\": \"\",\n  \"agent_instruction\": \"Decision has been logged.\",\n  \"allowed_next_actions\": [\n    \"proceed\"\n  ],\n  \"prohibited_actions\": []\n}"
      }
    ],
    "isError": false
  }
}
```

### 7. Malformed Stdio JSON-RPC Request

**Request**
```
{bad json}
```

**Response**
```json
{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: invalid character 'b' looking for beginning of value"}}
```
