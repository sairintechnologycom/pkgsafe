# Getting started

This page is the shortest path from zero to a useful PkgSafe workflow.

## 1. Install

```bash
curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash
pkgsafe doctor
```

Pin a version or change the install directory with `PKGSAFE_VERSION` and
`PKGSAFE_BIN_DIR`. Full options: [install.md](install.md).

## 2. Check one package (before you install it)

```bash
# npm
pkgsafe scan-npm-package axios

# PyPI
pkgsafe scan-pypi-package requests
```

You get a decision and the reasons:

- **ALLOW** — looks fine under current policy.
- **WARN** — review first (default mode still lets interactive installs proceed after confirm).
- **BLOCK** — do not install.

Machine-readable output:

```bash
pkgsafe scan-npm-package axios --json
```

## 3. Check a whole project

```bash
# npm lockfile
pkgsafe scan-lockfile ./package-lock.json

# Python (requirements, pyproject, poetry, uv, Pipfile)
pkgsafe scan-python-deps ./requirements.txt

# Preview ecosystems
pkgsafe scan-go-deps ./go.mod
pkgsafe scan-cargo-deps ./Cargo.lock
```

Explain a decision in plain language:

```bash
pkgsafe explain axios
pkgsafe explain-pypi requests
```

## 4. Install only if allowed

```bash
pkgsafe npm-install lodash
pkgsafe pip install requests
```

PkgSafe scans first, then runs the real package manager only when policy allows.

You can also put PkgSafe in front of normal commands (shell shims / interceptors).
See [install-interception.md](install-interception.md).

## 5. Modes (how strict)

Add `--mode` to any scan:

| Mode | Behavior |
|------|----------|
| `audit` | Report only. Never blocks. |
| `warn` | **Default.** Warn on risk; block critical findings. |
| `block` | Block at or above the block score threshold. |

## 6. Local policy (optional)

Without a file, PkgSafe uses a built-in default policy.

```bash
# Create / edit a project policy
mkdir -p .pkgsafe
cp default-policy.yaml .pkgsafe/policy.yaml   # or start from policy edit
pkgsafe policy validate .pkgsafe/policy.yaml

# Use it
pkgsafe scan-lockfile ./package-lock.json --policy .pkgsafe/policy.yaml
```

Details: [policy-guide.md](policy-guide.md).

## 7. CI on pull requests

```yaml
- uses: sairintechnologycom/pkgsafe@v1.6.0
  with:
    mode: warn
    fail-on: block
    changed-only: true
```

Full Action docs: [github-action.md](github-action.md).  
Any CI runner: [ci-cd.md](ci-cd.md).

## 8. AI coding agents (MCP)

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

The agent should call `validate_package_install` (or related tools) before
installing. **BLOCK** means never install. **WARN** means ask a human.

Per-client guides: [docs/integrations/](integrations/).

## 9. Offline use

```bash
# Once, while online
pkgsafe update-db --ecosystem all

# Later, no network
pkgsafe scan-npm-package axios --offline
```

Air-gapped machines: [offline-intelligence-bundle.md](offline-intelligence-bundle.md).

## What to remember

1. Default scans **do not run** package install scripts.
2. Optional `--behavior heuristic` runs scripts **on the host** (not a sandbox).
3. Optional `--behavior isolated` is **Linux-only** (bubblewrap). See
   [behavior-analysis.md](behavior-analysis.md).
4. npm and PyPI are GA. Go and Cargo are preview.
5. If something looks wrong, see [troubleshooting.md](troubleshooting.md) and
   [feedback.md](feedback.md).

## Next steps

- [Commands](commands.md) — full reference  
- [Known limitations](known-limitations.md) — honest scope  
- [Docs index](README.md) — everything else  
