# PkgSafe Private Beta Guide

PkgSafe private beta is strongest for npm dependency scanning, OSV vulnerability checks, dependency inventory, policy gates, CI outputs, and evidence generation.

## Positioning

- npm has the deepest artifact, lifecycle-script, inventory, and policy coverage.
- PyPI, Go, and Cargo support are available for early validation, but they are not npm-equivalent yet.
- Behavior analysis defaults to `disabled`.
- `heuristic` behavior mode runs lifecycle scripts on the host and is not sandboxing.
- `isolated` behavior mode reports unavailable until a real isolation backend lands.

## Real Repo Validation

Create a repo list from `benchmarks/real-repos.example.json`, then run:

```bash
pkgsafe test benchmark --repo-list benchmarks/real-repos.json --json
pkgsafe test production-readiness --repo-list benchmarks/real-repos.json --json
pkgsafe report beta-evidence --repo-list benchmarks/real-repos.json --output beta-evidence.md --json-output beta-evidence.json
```

Private beta evidence should include real repositories, but GA requires a larger threshold. Current GA blockers are surfaced directly in `production-readiness --json`.

## Private Beta Defaults

Use:

```yaml
sandbox:
  behavior_mode: disabled
```

Only use `--behavior heuristic` in disposable environments. Do not enable heuristic behavior analysis automatically for CI or AI-agent workflows.
