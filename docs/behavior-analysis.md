# Behavior Analysis

PkgSafe behavior analysis has three explicit modes:

| Mode | Status | Notes |
| --- | --- | --- |
| `disabled` | Default | Static, registry, policy, inventory, and OSV checks only. |
| `heuristic` | Opt-in | Runs lifecycle scripts on the host with fake HOME, cleaned environment, and timeout. This is not sandboxing. |
| `isolated` | Supported on Linux, opt-in | Uses the Linux bubblewrap backend when available. It reports unavailable and does not execute scripts on unsupported hosts or when isolation setup fails. |

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

The isolated backend is Linux-only and requires `bwrap` from bubblewrap plus
unprivileged user namespaces (on Ubuntu 23.10+ the AppArmor restriction
`kernel.apparmor_restrict_unprivileged_userns` must permit them). It is opt-in
through `--behavior isolated` or policy configuration and is validated
end-to-end in CI on Linux.

The backend executes each lifecycle script as uid 65534 inside private user,
mount, pid, ipc, uts, cgroup, and network namespaces with:

- a disposable workspace and a private HOME seeded with credential canaries;
  the host HOME and credential directories are never mounted
- a fully cleared environment (`--clearenv`) with a fixed `PATH`; host
  environment values are never forwarded
- system directories (`/usr`, `/bin`, `/lib`, ...) mounted read-only, and
  synthetic `/etc/passwd` / `/etc/group` files so the host account database is
  not exposed
- **network disabled by default** via an unshared network namespace — this is
  enforced, not merely declared. `network_mode=host` explicitly opts in to host
  networking (and mounts `/etc/resolv.conf` and CA certificates read-only so
  DNS/TLS work); any other value fails closed to disabled
- wall-clock timeout enforcement with process-group kill, plus in-sandbox
  `ulimit` caps on file descriptors, process count, and file size
- clean teardown: the temporary workspace is force-removed even if the script
  strips permissions from files it created

A non-zero script exit or a timeout is an observed behavior and is recorded in
the result; only an isolation-infrastructure failure is an error, and such
failures are recorded per script (`error` field) rather than silently skipped.

Isolation reduces host exposure but shares the host kernel; it is not a
hypervisor boundary. When the backend is unavailable, PkgSafe reports
`not_performed` and does not fall back to heuristic host execution.
