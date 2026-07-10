# Gemini CLI + PkgSafe

Use PkgSafe as an MCP tool server so Gemini CLI checks packages before install.

## MCP setup

In Gemini CLI settings (`mcpServers` block):

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

Ensure `pkgsafe` is on `PATH` for the Gemini process.

## Tools

Prefer tools from `tools/list`. Typical set:

| Tool | Purpose |
|------|---------|
| `validate_package_install` / `check_package` | Package decision |
| `validate_install_command` / `check_install_command` | Install command guard |
| `review_dependency_diff` | Manifest change review |
| `explain_package_risk` / `explain_policy_decision` | Remediation text |
| `suggest_safe_alternative` | Safer names |

Allowlist check/review/explain only — not unrestricted shell.

## Agent rules

- **BLOCK** — do not install  
- **WARN** — ask the user  
- **ALLOW** — install is OK under policy  

## Related

- [Generic MCP](../mcp-generic-client.md)
- [AI agent install safety](../ai-agent-install-safety.md)
- [Slash commands](slash-commands.md)
