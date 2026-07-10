# AI agent install safety

AI coding agents should not install dependencies without a safety check.
PkgSafe is that check — via MCP tools or the CLI.

## Rules for agents

1. **WARN blocks by default** for AI-requested installs unless a human confirms
   or a logged override is used.
2. **BLOCK always blocks.** Agents must not install blocked packages.
3. Prefer MCP tools (`validate_package_install`, `validate_install_command`) over
   raw shell installs.

## Mark the request as agent-driven

```bash
export PKGSAFE_REQUESTED_BY=ai_agent
```

With this set, interactive prompts are skipped and WARN is treated strictly so
automation fails closed.

## Good agent workflow

```bash
# 1) Validate first
pkgsafe scan-npm-package some-pkg --json
# or MCP: validate_package_install

# 2) Only then install (if ALLOW, or WARN after human approval)
pkgsafe npm-install some-pkg
```

Tips:

- Use `--dry-run` when available to validate without installing.
- Parse `--json` for structured decisions and rule IDs.
- On hallucinated names, use `suggest_safe_alternative` (MCP) before inventing installs.

## Setup by client

See [docs/integrations/](integrations/) and [mcp-generic-client.md](mcp-generic-client.md).

## Related

- [Install interception](install-interception.md)
- [Policy guide](policy-guide.md) (`mcp` section)
- [Troubleshooting](troubleshooting.md)
