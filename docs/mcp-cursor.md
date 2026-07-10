# Cursor + PkgSafe (MCP)

Have Cursor call PkgSafe before suggesting or running package installs.

## Run the server

```bash
pkgsafe mcp serve
pkgsafe mcp serve --policy /path/to/policy.yaml --mode warn
```

## Configure Cursor

**UI:** Features → MCP → Add server

- Name: `PkgSafe`
- Type: `stdio`
- Command: absolute path to binary, e.g. `/usr/local/bin/pkgsafe`
- Args: `mcp` `serve`

**Config file:**

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

## Tools

Use `tools/list` for the live schema. Core tools:

| Tool | Purpose |
|------|---------|
| `validate_package_install` | allow / warn / block |
| `validate_install_command` | full install line |
| `suggest_safe_alternative` | fix bad names |
| `explain_package_risk` | why |
| `score_lockfile` | project score |

Also available under agent-oriented aliases such as `check_package` and
`check_install_command`.

## Agent rules

- **BLOCK** → do not install  
- **WARN** → ask the user  
- **ALLOW** → OK under policy  

## Related

- [Generic MCP](mcp-generic-client.md)
- [AI agent install safety](ai-agent-install-safety.md)
- [Integrations index](README.md) via [docs/README.md](README.md)
