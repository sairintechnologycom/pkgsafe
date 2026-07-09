# PkgSafe Codex CLI Integration Guide

PkgSafe acts as the package safety guardrail layer for Codex coding agents, preventing the autonomous installation of risky, typosquatted, or malicious dependencies during coding loops.

## Purpose

Codex CLI allows configuring Model Context Protocol (MCP) servers. By exposing only narrow check/review/explain tools to Codex, PkgSafe intercepts dependency additions before Codex runs shell commands or modifies package manifests.

## MCP Configuration

To register the PkgSafe MCP server in Codex, add the following configuration to your `~/.codex/config.toml` file:

```toml
[mcp.servers.pkgsafe]
command = "pkgsafe"
args = ["mcp", "serve"]
```

Alternatively, you can add it via the Codex CLI:

```bash
codex mcp add pkgsafe --command "pkgsafe" --args "mcp serve"
```

## Allowlisted PkgSafe Tools

Configure Codex to only access the following safe read/check tools:

* `check_package`: Validates a package before recommending or installing it.
* `check_install_command`: Intercepts and parses shell install commands.
* `review_dependency_diff`: Reviews manifest/lockfile changes on branches.
* `explain_policy_decision`: Provides remediation recommendations for failed rules.

> [!CAUTION]
> Never expose broad command execution or installation tools to AI coding agents. Only allowlist PkgSafe check, review, and explain tools.

## Example Package Check

An agent running inside Codex checks a package:

```json
{
  "name": "check_package",
  "arguments": {
    "ecosystem": "npm",
    "name": "lodash",
    "version": "1.0.0"
  }
}
```

### Expected Output

```json
{
  "decision": "BLOCK",
  "risk_score": 100,
  "confidence": "high",
  "top_reasons": [
    "Package version has a high severity advisory"
  ],
  "agent_instruction": "Do not install this package. The policy decision is BLOCK.",
  "allowed_next_actions": [
    "suggest_alternative",
    "remove_dependency"
  ],
  "prohibited_actions": [
    "run_install",
    "execute_lifecycle_script"
  ]
}
```

## Codex-Specific Guardrail

* **Hard BLOCK**: Codex agents must never override a `BLOCK` decision. If a package check returns `BLOCK`, the agent must skip the package and suggest safe alternatives.
* **Human Approval on WARN**: If check returns `WARN`, the agent must pause execution and request human confirmation.

## Troubleshooting

1. **Codex CLI does not discover tools**: Make sure the `pkgsafe` binary is on your system `PATH`. Run `which pkgsafe` to verify.
2. **Registry timeout errors**: Ensure you have a valid network connection or run PkgSafe in offline mode by adding the `--offline` flag to your MCP config:
   ```toml
   args = ["mcp", "serve", "--offline"]
   ```
