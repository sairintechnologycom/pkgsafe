# Install interception

PkgSafe can sit in front of `npm` and `pip` so packages are checked **before**
the real package manager runs.

Non-install commands (for example `npm run build`, `npm test`) pass through to
the real binary with no scan.

## How it works

1. Parse the package manager and arguments.
2. If the command installs packages, extract names and versions.
3. Scan against policy, OSV, typosquat rules, and static analysis.
4. Apply the decision:
   - **ALLOW** → run the real install
   - **WARN** → prompt (interactive) or block (non-interactive / AI by default)
   - **BLOCK** → stop install, audit log, non-zero exit

## Commands

```bash
# Prefer these
pkgsafe npm install axios
pkgsafe npm add lodash
pkgsafe pip install requests
pkgsafe python -m pip install Django

# Or the dedicated helpers
pkgsafe npm-install axios
pkgsafe pip install requests

# Generic gate
pkgsafe run -- npm install lodash
pkgsafe run -- pip install requests
```

Shell aliases / shims can point `npm` and `pip` at PkgSafe. See
[shell-shims.md](shell-shims.md) and ecosystem notes:
[npm-interception.md](npm-interception.md), [pip-interception.md](pip-interception.md).

## Useful flags

| Flag | Purpose |
|------|---------|
| `--mode audit\|warn\|block` | Override enforcement mode |
| `--policy <path>` | Custom policy |
| `--behavior disabled\|heuristic\|isolated` | Optional script execution (default: disabled) |
| `--offline` | Local cache / DB only |
| `--dry-run` | Scan only; do not install |
| `--yes` | Auto-confirm WARN in non-interactive use (use carefully) |
| `--json` | Structured output |
| `--force-risk-accept --reason "…"` | Override under policy rules; always logged |

`--sandbox` is deprecated; it means `--behavior heuristic` (host execution).

## Policy defaults that matter

From the default policy:

- AI agents should not install on WARN without confirmation.
- Non-interactive WARN often **blocks** by default.
- Force accept requires a reason and is audited.
- Known malware and credential-access findings always block.

Tune only with care: [policy-guide.md](policy-guide.md).

## Related

- [Getting started](getting-started.md)
- [Commands](commands.md)
- [AI agent install safety](ai-agent-install-safety.md)
- [Troubleshooting](troubleshooting.md)
