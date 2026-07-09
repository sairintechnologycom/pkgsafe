# Loop VC-5 - Agent Audit Log Evidence

Date: 2026-07-09
Branch: loop-vc-05-agent-audit-log

## Feature Spec

Record auditable AI-agent package decisions in a local audit log.

Event properties captured:
* `event_id`
* `timestamp`
* `agent_name`
* `agent_tool`
* `repo_path`
* `repo_sha`
* `package`
* `ecosystem`
* `version`
* `command_requested`
* `decision`
* `risk_score`
* `policy_version`
* `evidence_id`
* `human_approval_required`
* `human_approval_recorded`
* `redaction_status`

## Files Created/Modified

- `internal/mcp/record_agent_decision.go` (created in Loop VC-1)

## Local Event Logging Format

Decisions recorded via `record_agent_decision` are appended to the local agent audit log file at `~/.pkgsafe/agent_audit.log` as JSONL.

### Sample Event Entry

```json
{
  "event_id": "evt-20260709-123",
  "timestamp": "2026-07-09T10:24:25Z",
  "agent_name": "codex",
  "agent_tool": "record_agent_decision",
  "repo_path": ".",
  "repo_sha": "77f3e477610be5349f4c3a5043bf7dbd20d75f28",
  "package": "fixture",
  "ecosystem": "npm",
  "version": "1.0.0",
  "command_requested": "record_agent_decision npm fixture 1.0.0",
  "decision": "ALLOW",
  "risk_score": 0,
  "policy_version": "1.0",
  "evidence_id": "pkg-20260709-001",
  "human_approval_required": false,
  "human_approval_recorded": false,
  "redaction_status": "clean"
}
```

## Security & Redaction Control

Credentials, security tokens, or secrets matching standard regex rules are automatically redacted from all entry fields before write, maintaining a clean and audit-safe logs file.
