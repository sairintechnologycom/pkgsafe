# CI/CD integration

Use PkgSafe as a dependency gate in any CI system. Preferred options:

1. **GitHub Action** — [github-action.md](github-action.md) (PR comments, SARIF upload).
2. **CLI** — `pkgsafe ci scan` on GitHub, GitLab, Azure Pipelines, Jenkins, etc.

## Command

```bash
pkgsafe ci scan [flags]
```

### Useful flags

| Flag | Purpose |
|------|---------|
| `--lockfile <path>` | Lockfile to scan (default often `package-lock.json`) |
| `--policy <path>` | Policy file (defaults to `.pkgsafe/policy.yaml` if present) |
| `--mode audit\|warn\|block` | Decision mode |
| `--fail-on none\|warn\|block` | Minimum decision that fails the job (default: `block`) |
| `--changed-only` | Only packages changed vs baseline |
| `--baseline <branch>` | Baseline branch (default: `main`) |
| `--ecosystem npm\|pypi\|…` | When the project is not npm-default |
| `--behavior disabled\|heuristic\|isolated` | Default `disabled` |
| `--offline` | Local DB / cache only |
| `--json-output <path>` | Write JSON report |
| `--sarif-output <path>` | Write SARIF 2.1.0 |
| `--summary-output <path>` | Write Markdown summary |

`--sandbox` is deprecated; it means `--behavior heuristic` (host execution, not a sandbox).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK — fail-on threshold not reached |
| 1 | Findings at fail-on threshold |
| 2 | Usage or config error |
| 3 | Scanner runtime error |
| 4 | Policy validation error |
| 5 | Lockfile / manifest parse error |

## Examples

**PR-style gate (changed deps only, fail on BLOCK):**

```bash
pkgsafe ci scan --changed-only --baseline main --fail-on block
```

**Offline + SARIF for code scanning upload:**

```bash
pkgsafe ci scan --offline --sarif-output pkgsafe-results.sarif
```

**PyPI project:**

```bash
pkgsafe ci scan --ecosystem pypi --lockfile poetry.lock --fail-on block
```

## Minimal GitHub workflow (without the Action)

```yaml
- uses: actions/checkout@v4
- name: Install PkgSafe
  run: curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash
- name: Scan
  run: pkgsafe ci scan --changed-only --fail-on block --sarif-output results.sarif
```

For the packaged Action (comments + Code Scanning wiring), use
[github-action.md](github-action.md).

## Related

- [Policy guide](policy-guide.md)
- [Commands](commands.md)
- [Troubleshooting](troubleshooting.md)
- [Known limitations](known-limitations.md)
