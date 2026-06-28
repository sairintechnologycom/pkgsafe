# Behavior Analysis

PkgSafe behavior analysis has three explicit modes:

| Mode | Status | Notes |
| --- | --- | --- |
| `disabled` | Default | Static, registry, policy, inventory, and OSV checks only. |
| `heuristic` | Opt-in | Runs lifecycle scripts on the host with fake HOME, cleaned environment, and timeout. This is not sandboxing. |
| `isolated` | Planned | Reserved for a real isolation backend. Until implemented, it reports unavailable and does not execute scripts. |

## Required Wording

Use "heuristic behavior analysis" for host execution.

Do not describe heuristic mode as containment, isolation, or a protected execution environment.

## Execution Rules

- Behavior analysis is disabled by default.
- Static `BLOCK` packages are never executed.
- PyPI behavior analysis is disabled unless an isolated backend is available.
- AI-agent and CI workflows should not automatically use heuristic mode.
- `--sandbox` is a deprecated compatibility alias for `--behavior heuristic`.
