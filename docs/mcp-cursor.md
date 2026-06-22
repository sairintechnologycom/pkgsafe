# Cursor MCP Integration with PkgSafe

This document describes how to configure the **Cursor** AI editor to use **PkgSafe** as an MCP server, ensuring package installation requests are checked for safety before suggestions or executions.

## 1. Overview
PkgSafe acts as a local package safety oracle. Before Cursor suggests or executes dependency installation (e.g. `npm install <package>`), it calls PkgSafe and receives a clear decision (`allow`, `warn`, or `block`) with explainable reasons.

## 2. Running PkgSafe MCP Serve
To run PkgSafe as an MCP server, use:
```bash
pkgsafe mcp serve
```
Optional flags can be passed to configure policy and mode:
```bash
pkgsafe mcp serve --policy /path/to/policy.yaml --mode warn
```

## 3. Configuration in Cursor
To configure Cursor, open your Cursor settings and navigate to **Features > MCP**. Click **+ Add New MCP Server** and fill out the details:

* **Name**: `PkgSafe`
* **Type**: `stdio`
* **Command**: `/path/to/pkgsafe mcp serve` (Ensure you use the absolute path to your installed `pkgsafe` binary, e.g. `/usr/local/bin/pkgsafe` or similar)

Alternatively, add it directly to your Cursor MCP settings configuration file:
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
Add the following instruction to your Cursor System Prompts or `.cursorrules`:

```text
Before installing, suggesting, or adding any npm package, call the PkgSafe MCP tool `validate_package_install`.

If PkgSafe returns `block` or if `install_allowed` is false, do not install or suggest the package. Suggest safe alternatives instead.

If PkgSafe returns `warn`, explain the warning to the user and ask for explicit confirmation before suggesting or installing.

If PkgSafe returns `allow`, proceed normally.
```
