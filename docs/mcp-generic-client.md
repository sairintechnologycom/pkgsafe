# MCP: generic client

Use PkgSafe as a local MCP server so any agent can get **allow / warn / block**
before installing packages.

## Run the server

```bash
pkgsafe mcp serve
pkgsafe mcp serve --policy /path/to/policy.yaml --mode warn
```

Stdio JSON-RPC (newline-framed). The binary must be on `PATH` for the host
process.

## Client config

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

## Core tools

| Tool | Use |
|------|-----|
| `validate_package_install` | Decide allow/warn/block for one package |
| `validate_install_command` | Parse a full `npm install` / `pip install` line |
| `suggest_safe_alternative` | Real packages for risky or hallucinated names |
| `explain_package_risk` | Human reasons for a decision |
| `score_lockfile` | Score lockfile dependencies |

Call tools with MCP `tools/call` (not as top-level methods). Run `tools/list`
for the live schema. Governance tools may also appear depending on build.

## Agent rules

- **BLOCK** → never install.
- **WARN** → ask a human (default MCP policy).
- Do not expose a generic shell or “run install” tool from the same server
  surface — only check / explain tools.

## Example call

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "validate_package_install",
    "arguments": {
      "ecosystem": "npm",
      "name": "axios",
      "requested_by": "ai_agent"
    }
  }
}
```

## Per-client guides

- [Claude Code](integrations/claude-code.md)
- [Codex](integrations/codex.md)
- [Cursor](mcp-cursor.md)
- [Gemini CLI](integrations/gemini-cli.md)
- [GitHub Copilot agent](integrations/github-copilot-agent.md)
- [Slash commands / skills](integrations/slash-commands.md)

Also: [ai-agent-install-safety.md](ai-agent-install-safety.md).
