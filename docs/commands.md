# Commands

Common PkgSafe commands. For flags on a specific command, run
`pkgsafe <command> --help` when available, or pass `-h` on subcommands that
support the standard flag set.

Global patterns used widely:

| Flag | Meaning |
|------|---------|
| `--json` | Machine-readable JSON (same shape MCP tools use) |
| `--mode audit\|warn\|block` | Enforcement mode |
| `--fail-on none\|warn\|block` | Process exit threshold for scan commands (see below) |
| `--policy <path>` | Custom policy file |
| `--offline` | Use local cache / DB only (no registry fetch when required data is missing, fail closed) |
| `--behavior disabled\|heuristic\|isolated` | Optional lifecycle execution (default: disabled) |

**Scan exit codes:** package scan commands print a decision and, by default, exit
`0` in `warn`/`audit` mode so interactive review stays usable. With
`--mode block` (or explicit `--fail-on block`), a `block` or `review_required`
decision exits `1` so scripts fail closed:

```bash
pkgsafe scan-npm-package axois --mode block && npm install axois   # blocked install never runs
pkgsafe scan-local-npm ./pkg --fail-on warn                        # exit 1 on warn or worse
```

`pkgsafe scan` (workspace) defaults to failing on block even in warn mode so it
stays a project gate. Use `--fail-on none` to override.

---

## Health and version

```bash
pkgsafe version
pkgsafe doctor
pkgsafe history
```

| Command | Purpose |
|---------|---------|
| `version` | Print version and commit |
| `doctor` | Check binary, DB, registry reachability, package managers |
| `history` | Local audit / decision history |

---

## Scan packages

```bash
pkgsafe scan-npm-package <name[@version]>
pkgsafe scan-pypi-package <name[@version]>
pkgsafe scan-local-npm [path]
```

| Command | Purpose |
|---------|---------|
| `scan-npm-package` | Single npm package from the registry |
| `scan-pypi-package` | Single PyPI package from the registry |
| `scan-local-npm` | Scan a local package / project path |
| `explain <name>` | Plain-language npm decision |
| `explain-pypi <name>` | Plain-language PyPI decision |

---

## Scan projects and lockfiles

```bash
pkgsafe scan-lockfile ./package-lock.json
pkgsafe scan-python-deps ./requirements.txt
pkgsafe scan-go-deps ./go.mod          # preview
pkgsafe scan-cargo-deps ./Cargo.lock   # preview
pkgsafe tree package-lock.json [--only-risky]
pkgsafe verify package-lock.json
```

| Command | Purpose |
|---------|---------|
| `scan-lockfile` | npm lockfile (including pnpm/yarn where supported) |
| `scan-python-deps` | requirements, pyproject, poetry.lock, uv.lock, Pipfile |
| `scan-go-deps` | Go modules (preview) |
| `scan-cargo-deps` | Cargo (preview) |
| `tree` | Dependency tree with risk highlighting |
| `verify` | Lockfile integrity / hash audit |
| `inventory` / `inventory diff` | Inventory listing and change diff |

---

## Safe install

```bash
pkgsafe npm-install <packages...>
pkgsafe npm <args...>          # intercept; non-install commands pass through
pkgsafe pnpm <args...>         # install/add/i/ci
pkgsafe yarn <args...>         # install/add (bare yarn = project install)
pkgsafe uv <args...>           # uv pip install / uv add / uv sync
pkgsafe pip <args...>
pkgsafe python -m pip <args...>
```

Install paths scan first, then call the real package manager only if allowed.
Shell shims (`pkgsafe init shell`) alias npm, pnpm, yarn, pip, and uv.

---

## Policy

```bash
pkgsafe policy edit
pkgsafe policy validate [path]
pkgsafe policy explain [path]
pkgsafe policy test <fixture-dir>
```

See [policy-guide.md](policy-guide.md).

---

## CI

```bash
pkgsafe ci scan [flags]
```

Important flags: `--lockfile`, `--policy`, `--mode`, `--fail-on`,
`--changed-only`, `--baseline`, `--offline`, `--json-output`, `--sarif-output`,
`--summary-output`.

Exit codes and examples: [ci-cd.md](ci-cd.md).  
GitHub Action: [github-action.md](github-action.md).

---

## MCP (AI agents)

```bash
pkgsafe mcp serve
```

Core tools include `validate_package_install`, `validate_install_command`,
`suggest_safe_alternative`, `explain_package_risk`, `score_lockfile`.

---

## Local API (developer only)

```bash
pkgsafe serve-api
```

Binds to **localhost** by default. Unauthenticated without extra setup. Do not
expose to the public internet.

---

## Database and offline intel

```bash
pkgsafe update-db --ecosystem all
pkgsafe db status
pkgsafe db export-bundle ...
pkgsafe db verify-bundle ...
pkgsafe db import-bundle ...
```

See [offline-intelligence-bundle.md](offline-intelligence-bundle.md).

---

## Reports and feedback

```bash
pkgsafe report ...
pkgsafe feedback create ...
```

Feedback workflow: [feedback.md](feedback.md).

---

## Sandbox / behavior (opt-in)

```bash
pkgsafe sandbox profile ...
# Or pass on scan commands:
pkgsafe scan-npm-package foo --behavior isolated   # Linux + bubblewrap
```

Read [behavior-analysis.md](behavior-analysis.md) before enabling. Default
scans never execute package code.

---

## Readiness / validation (maintainers)

```bash
pkgsafe test corpus
pkgsafe test benchmark
pkgsafe test production-readiness
pkgsafe test rollout-readiness
```

These gate release quality. End users normally do not need them.

---

## Other

```bash
pkgsafe init
pkgsafe registry ...
pkgsafe run ...
```

`init` helps scaffold local config. `registry` configures private registry
routing (see [private-registry.md](private-registry.md)).
