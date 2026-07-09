# PkgSafe GitHub Copilot Agent Integration Guide

PkgSafe acts as the package safety guardrail layer for GitHub Copilot cloud agent and code review, preventing the autonomous installation of risky, typosquatted, or malicious dependencies.

## Purpose

GitHub allows repository administrators to configure MCP servers for Copilot cloud agent and code review. Because Copilot can use configured MCP tools autonomously, PkgSafe provides strict, narrow, safe MCP tools to guard the dependency path.

## Important Constraints

* **Tools Only**: GitHub Copilot currently supports MCP tools, not MCP resources or prompts. Expose tools only.
* **No Broad Shell Execution**: Ensure the Copilot MCP configurations do not expose broad shell execution or install execution. Allowlist read/check tools only.

## MCP Configuration

Repository administrators can configure the PkgSafe MCP server in the repository's `.github/copilot-mcp.json` or through the GitHub repository settings page:

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

## Allowlisted PkgSafe Tools

Expose only the following safe read/check tools:

* `check_package`: Checks package safety against configured repo security policies.
* `check_install_command`: Checks install command syntax and package contents.
* `review_dependency_diff`: Performs a dependency diff review in PR workflows.
* `explain_policy_decision`: Provides remediation recommendations for failed rules.

## Example Dependency Diff Review

When Copilot review parses modifications in `package.json`:

```json
{
  "name": "review_dependency_diff",
  "arguments": {
    "repo_path": ".",
    "base_ref": "main",
    "head_ref": "agent-branch"
  }
}
```

### Expected Output

```json
{
  "decision": "REVIEW_REQUIRED",
  "risk_score": 75,
  "confidence": "high",
  "top_reasons": [
    "[risky-dep:npm] Warning: 75 risk score"
  ],
  "agent_instruction": "Do not open PR as ready. Mark PR as requiring security review.",
  "allowed_next_actions": [
    "mark_review",
    "proceed_coding"
  ],
  "prohibited_actions": [
    "run_install",
    "execute_lifecycle_script"
  ],
  "new_dependencies": 1,
  "blocked_dependencies": 0,
  "warn_dependencies": 1
}
```

## Copilot-Specific Guardrail

* **Hard BLOCK**: If `check_package` or `review_dependency_diff` returns `BLOCK` or `REVIEW_REQUIRED`, Copilot must mark the PR as requiring security review and must not execute the install.
* **PR Readiness Check**: The `review_dependency_diff` tool is run automatically on PR branch commits to prevent insecure dependencies from merging.
