# Behavior analysis

By default PkgSafe **does not run** package install scripts. It only inspects
metadata, lockfiles, and package artifacts statically.

Optional behavior modes execute lifecycle scripts to watch what they do. Use
them only when you understand the risk.

## Modes

| Mode | Default? | What it does |
|------|----------|--------------|
| `disabled` | Yes | Static + registry + policy + OSV only. **Recommended.** |
| `heuristic` | Opt-in | Runs scripts **on the host** with a fake HOME, cleaned env, and timeout. **Not a sandbox.** |
| `isolated` | Opt-in, Linux | Runs scripts inside bubblewrap namespaces when available. |

## How to enable

```bash
# Host execution — disposable machine only
pkgsafe scan-npm-package some-pkg --behavior heuristic

# Linux isolation (bubblewrap + unprivileged user namespaces)
pkgsafe scan-npm-package some-pkg --behavior isolated
```

Policy default (usually leave alone):

```yaml
sandbox:
  enabled: false
  behavior_mode: disabled
```

`--sandbox` is a **deprecated** alias for `--behavior heuristic`.

## Rules

- Behavior analysis is **off** by default.
- Packages that already **BLOCK** on static analysis are **not** executed.
- AI agents and CI should **not** turn on `heuristic` automatically.
- Unsupported hosts report isolation as unavailable and **do not** fall back to
  host execution.

## Isolated backend (Linux)

Requires `bwrap` (bubblewrap) and unprivileged user namespaces. Each script runs
as a low-privilege user in private namespaces with:

- disposable workspace and private HOME (credential canaries; host HOME not mounted)
- cleared environment and fixed `PATH`
- read-only system mounts
- **network off by default** (unshared net namespace)
- wall-clock timeout and resource caps
- force-remove of the temp workspace after the run

`network_mode=host` is an explicit opt-in. Isolation still **shares the host
kernel** — it is not a VM.

Inspect profiles when available:

```bash
pkgsafe sandbox profile ...
```

## Honest wording

| Say this | Do not say this |
|----------|-----------------|
| Heuristic behavior analysis | Sandbox, containment, protected environment |
| Isolated namespace backend (Linux) | Hypervisor isolation, full VM security |

## Related

- [Known limitations](known-limitations.md)
- [Policy guide](policy-guide.md)
- [Troubleshooting](troubleshooting.md)
