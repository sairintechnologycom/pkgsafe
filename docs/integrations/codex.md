# Codex CLI + PkgSafe

Guard Codex coding agents so they do not install risky or hallucinated packages.

## MCP setup

In `~/.codex/config.toml`:

```toml
[mcp.servers.pkgsafe]
command = "pkgsafe"
args = ["mcp", "serve"]
```

Or via CLI (syntax may vary by Codex version):

```bash
codex mcp add pkgsafe --command "pkgsafe" --args "mcp" --args "serve"
```

`pkgsafe` must be on `PATH`.

## Tools

Use the live `tools/list` schema. Common safety tools:

| Tool | Purpose |
|------|---------|
| `validate_package_install` / `check_package` | Package allow/warn/block |
| `validate_install_command` / `check_install_command` | Guard install command lines |
| `review_dependency_diff` | Review manifest/lockfile changes |
| `explain_package_risk` / `explain_policy_decision` | Explain decisions |
| `suggest_safe_alternative` | Fix bad or invented names |

Do not expose broad shell or unrestricted install tools to the agent.

## Agent rules

1. Validate before install.
2. **BLOCK** → never install.
3. **WARN** → ask a human.
4. **ALLOW** → proceed under policy.

## Related

- [Generic MCP](../mcp-generic-client.md)
- [AI agent install safety](../ai-agent-install-safety.md)
- [Slash commands](slash-commands.md)
