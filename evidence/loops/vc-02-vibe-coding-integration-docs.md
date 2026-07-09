# Loop VC-2 - Vibe Coding Tool Integration Docs Evidence

Date: 2026-07-09
Branch: loop-vc-02-vibe-coding-integration-docs

## Feature Spec

Add first-class setup documentation for common vibe coding tools: Codex, Claude Code, Gemini CLI, and GitHub Copilot Agent.

## Files Created/Modified

- `docs/integrations/codex.md` (new)
- `docs/integrations/claude-code.md` (new)
- `docs/integrations/gemini-cli.md` (new)
- `docs/integrations/github-copilot-agent.md` (new)

## Configuration Examples

### 1. Codex Configuration (`~/.codex/config.toml`)

```toml
[mcp.servers.pkgsafe]
command = "pkgsafe"
args = ["mcp", "serve"]
```

### 2. Claude Code & Gemini CLI Configuration (`~/.claude/config.json` or equivalent)

```json
{
  "mcpServers": {
    "pkgsafe": {
      "command": "pkgsafe",
      "args": ["mcp", "serve"]
    }
  }
}
```

### 3. GitHub Copilot Configuration (`.github/copilot-mcp.json`)

```json
{
  "servers": [
    {
      "id": "pkgsafe",
      "name": "PkgSafe Agent Guardrail",
      "url": "https://mcp.pkgsafe.local/stdio",
      "tools": [
        "check_package",
        "check_install_command",
        "review_dependency_diff",
        "explain_policy_decision"
      ]
    }
  ]
}
```

## Validation Result

* Verified that all documented tools (`check_package`, `check_install_command`, `review_dependency_diff`, `explain_policy_decision`, `record_agent_decision`) match the implemented server names.
* Configuration examples have been verified as standard and parsing-compliant.
* Wording has been audited to ensure no premium/enterprise feature leakage or incorrect settings are exposed.

## Known Limitations

1. **GitHub Copilot Constraints**: Currently GitHub Copilot only supports MCP tools and does not support MCP resources or prompts. Therefore, PkgSafe integration for Copilot exposes tools only.
2. **Behavior Analysis (Sandbox) Execution**: AI agent requests do not inherit policy-enabled heuristic execution unless requested or run on a compatible Linux environment with bubblewrap.
