# Claude Code + PkgSafe

Block risky, typosquatted, or hallucinated packages before Claude Code installs
them.

## MCP setup

Add PkgSafe to your Claude Code MCP config (for example `~/.claude.json` or the
path your Claude Code build uses for MCP servers):

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

Confirm `pkgsafe` is on `PATH` for the Claude Code process, then restart the
client if needed.

## Tools to use

Prefer the live tool list from `tools/list`. Typical safety tools:

| Tool | Purpose |
|------|---------|
| `validate_package_install` / `check_package` | allow / warn / block one package |
| `validate_install_command` / `check_install_command` | guard a full install command line |
| `review_dependency_diff` | review manifest/lockfile changes between refs |
| `explain_package_risk` / `explain_policy_decision` | why a decision was made |
| `suggest_safe_alternative` | fix hallucinated or risky names |
| `score_lockfile` | review project dependencies |
| `get_agent_guidance` | policy-aware guidance for the current agent context |
| `record_agent_decision` | append install decision to local audit log |

Do **not** wire a broad shell or unrestricted install tool through this server.
Only check, review, and explain.

## Agent behavior

1. Before any `npm install` / `pip install`, call `validate_package_install` (or
   `validate_install_command`).
2. On **BLOCK** — do not install.
3. On **WARN** — ask the user; do not auto-install.
4. On **ALLOW** — install is fine under current policy.

Optional: project skills / slash commands — see
[slash-commands.md](slash-commands.md).

## Related

- [Generic MCP client](../mcp-generic-client.md)
- [AI agent install safety](../ai-agent-install-safety.md)
- [Policy guide](../policy-guide.md)
- [Slash commands](slash-commands.md)
