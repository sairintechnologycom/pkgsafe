# AI Agent Install Safety

AI coding agents and background processes should not install dependencies blindly. PkgSafe enforces strict guardrails for automated agents.

## Stricter AI Agent Enforcement Rules

When PkgSafe is run by an AI agent (e.g. MCP call or tool use):
1. **Warn decisions block by default**: If a package receives a WARN decision, the installation is automatically blocked unless an explicit override flag (`--force-risk-accept` with `--reason`) is passed.
2. **Block decisions always block**: AI agents cannot install blocked dependencies.

## Environment Variable Integration

AI coding tools and agents should set the following environment variable during session executions:

```bash
export PKGSAFE_REQUESTED_BY=ai_agent
```

When this flag is active:
- Warnings are treated strictly as block thresholds.
- Interactive prompts are skipped, and execution fails with exit code 1 or 2 to ensure safety.

## Best Practices for Agent Workflows

- Run installation validation with the `--dry-run` flag first to parse the installation request and check warnings.
- Integrate PkgSafe commands directly into agent command validation pipelines before running the actual installations.
- Use `--json` output formats for structured parser checks.
