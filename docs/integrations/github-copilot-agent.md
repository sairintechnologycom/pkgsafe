# GitHub Copilot agent + PkgSafe

Use PkgSafe MCP tools with GitHub Copilot cloud agent / code review so
dependency changes are checked before install.

## Constraints

- Copilot MCP support focuses on **tools** (not resources/prompts in all modes).
- Expose **check / review / explain** tools only — never a broad shell or
  unrestricted install tool.
- Prefer **local stdio** (`pkgsafe mcp serve`) when the agent host can run a
  binary. Remote URL endpoints are environment-specific; do not invent public
  SaaS URLs.

## Local stdio configuration (recommended)

Where the host can spawn a process:

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

Repository admins may also configure MCP in GitHub settings or
`.github/` config files — follow current GitHub Copilot MCP docs for the exact
file shape (it changes by product surface).

## Tools to allowlist

| Tool | Purpose |
|------|---------|
| `check_package` / `validate_package_install` | Package safety |
| `check_install_command` / `validate_install_command` | Install command guard |
| `review_dependency_diff` | Manifest/lockfile review |
| `explain_policy_decision` / `explain_package_risk` | Explain findings |

Confirm names with `tools/list` on your PkgSafe version.

## Agent rules

1. Call a check tool before recommending or applying dependency installs.
2. **BLOCK** → do not install or merge blindly.
3. **WARN** → require human review.
4. Pair with the [GitHub Action](../github-action.md) for PR gates in CI.

## Related

- [Generic MCP](../mcp-generic-client.md)
- [CI/CD](../ci-cd.md)
- [AI agent install safety](../ai-agent-install-safety.md)
