# Behavior Analysis

PkgSafe behavior analysis has three explicit modes:

| Mode | Status | Notes |
| --- | --- | --- |
| `disabled` | Default | Static, registry, policy, inventory, and OSV checks only. |
| `heuristic` | Opt-in | Runs lifecycle scripts on the host with fake HOME, cleaned environment, and timeout. This is not sandboxing. |
| `isolated` | Experimental, opt-in | Uses the Linux bubblewrap backend when available. It reports unavailable and does not execute scripts on unsupported hosts or when isolation setup fails. |

## Required Wording

Use "heuristic behavior analysis" for host execution.

Do not describe heuristic mode as containment, isolation, or a protected execution environment.

## Execution Rules

- Behavior analysis is disabled by default.
- Static `BLOCK` packages are never executed.
- PyPI behavior analysis is disabled unless an isolated backend is available and explicitly supported for that package flow.
- AI-agent and CI workflows should not automatically use heuristic mode.
- `--sandbox` is a deprecated compatibility alias for `--behavior heuristic`.

## Isolated Backend

The first isolated backend is Linux-only and requires `bwrap` from bubblewrap.
It is experimental and opt-in through `--behavior isolated` or policy
configuration. The backend uses private user, mount, pid, ipc, uts, and network
namespaces, a disposable workspace, a fake HOME, cleaned environment variables,
timeout enforcement, and a low file-descriptor limit. Network is disabled by
default; `network_mode=host` explicitly shares host networking.

When the backend is unavailable, PkgSafe reports `not_performed` and does not
fall back to heuristic host execution.
