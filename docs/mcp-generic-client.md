# PkgSafe MCP Generic Client Integration

This document describes how to configure any generic MCP-compatible client to use **PkgSafe** as a local package safety guardrail.

## 1. Overview
PkgSafe acts as a local package safety oracle. Before an AI coding assistant suggests or runs `npm install <package>`, it should call PkgSafe and receive a clear decision (`allow`, `warn`, or `block`) with explainable reasons.

## 2. Running PkgSafe MCP Serve
To run PkgSafe as an MCP server, use:
```bash
pkgsafe mcp serve
```
Optional flags can be passed to configure policy and mode:
```bash
pkgsafe mcp serve --policy /path/to/policy.yaml --mode warn
```

## 3. Generic Client Configuration
MCP servers running over stdio communicate using JSON-RPC 2.0 messages framed by newline (`\n`) characters. 

Add the following definition to your client's MCP server configuration (e.g. VS Code Extension settings, custom Python agent script, etc.):

```json
{
  "mcpServers": {
    "pkgsafe": {
      "command": "pkgsafe",
      "args": ["mcp", "serve"],
      "enabled": true
    }
  }
}
```

## 4. Example Request
```json
{
  "name": "validate_package_install",
  "arguments": {
    "ecosystem": "npm",
    "name": "react-markdown-renderer-plus",
    "version": "latest",
    "requested_by": "ai_agent"
  }
}
```

## 5. Expected Response
```json
{
  "ecosystem": "npm",
  "package": "react-markdown-renderer-plus",
  "version": "1.0.1",
  "requested_by": "ai_agent",
  "decision": "warn",
  "risk_score": 68,
  "install_allowed": false,
  "mode": "warn",
  "reasons": [
    {
      "rule_id": "new_package",
      "severity": "medium",
      "score": 15,
      "message": "Package was recently published"
    },
    {
      "rule_id": "missing_repository",
      "severity": "low",
      "score": 10,
      "message": "Package metadata does not include a source repository"
    },
    {
      "rule_id": "ai_package_squatting_candidate",
      "severity": "high",
      "score": 25,
      "message": "Package name resembles an AI-generated package name with low ecosystem reputation"
    }
  ],
  "vulnerabilities": [],
  "safe_alternatives": [
    "react-markdown",
    "markdown-it"
  ],
  "recommended_action": "Review package before installing. Prefer established alternatives if functionality matches."
}
```

## 6. Recommended Agent Instruction
Add the following instruction to your agent's system prompt or context instructions:

```text
Before installing, suggesting, or adding any npm package, call the PkgSafe MCP tool `validate_package_install`.

If PkgSafe returns `block` or if `install_allowed` is false, do not install or suggest the package. Suggest safe alternatives instead.

If PkgSafe returns `warn`, explain the warning to the user and ask for explicit confirmation before suggesting or installing.

If PkgSafe returns `allow`, proceed normally.
```
