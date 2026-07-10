# Troubleshooting

Fix common setup and scan problems. If you still need help, open a
[Discussion](https://github.com/sairintechnologycom/pkgsafe/discussions) or a
GitHub issue with sanitized output (see [feedback.md](feedback.md)).

## First step: doctor

```bash
pkgsafe doctor
pkgsafe doctor --json   # if available / for support bundles
```

Fix what doctor reports before chasing scan results.

---

## Install and PATH

| Symptom | What to try |
|---------|-------------|
| `command not found: pkgsafe` | Confirm the binary is on `PATH`. Install script uses `/usr/local/bin` or `PKGSAFE_BIN_DIR`. |
| Wrong version | `pkgsafe version`. Reinstall from the release you want. |
| Signature / checksum fail | Re-download `checksums.txt` + archive from the same release. Follow [release-verification.md](release-verification.md). |
| Windows: not on PATH | Move `pkgsafe.exe` into a directory listed in your user PATH. |

---

## Registry and network

| Symptom | What to try |
|---------|-------------|
| Timeouts talking to npm/PyPI | Check network / proxy. Retry. Use offline only after a successful DB sync. |
| Private registry packages fail | Configure registries in policy. See [private-registry.md](private-registry.md). Do not put tokens in public reports. |
| Offline scan fails closed | Expected when advisory or metadata cache is missing. Run `pkgsafe update-db --ecosystem all` online, or import a verified bundle. |

```bash
pkgsafe update-db --ecosystem all
pkgsafe db status
pkgsafe scan-npm-package axios --offline
```

---

## Decisions you did not expect

### Package is BLOCK but you trust it

1. Read the **rule IDs** in the output (or `--json`).
2. Confirm name and version (typosquats are intentional blocks).
3. If it is a real false positive: do **not** disable hard-block rules for malware/credentials.
4. Prefer a time-boxed **exception** with reason and approver (see [policy-guide.md](policy-guide.md)).
5. File feedback with rule IDs and sanitized JSON: [feedback.md](feedback.md).

### Package is ALLOW but you expected a block

1. Confirm ecosystem and version.
2. Confirm you scanned the same artifact CI will install (lockfile vs floating range).
3. Report as `false_negative` with package, version, and why it is malicious.

### WARN in CI fails the job

CI uses `--fail-on` separately from scan mode:

- `fail-on: block` — fail only on BLOCK (common).
- `fail-on: warn` — fail on WARN and BLOCK.

See [ci-cd.md](ci-cd.md) and [github-action.md](github-action.md).

### WARN in non-interactive install is blocked

By default, non-interactive **WARN** can block so automation does not install
risky packages without a human. Interactive shells may prompt. Tune
`install_interception` in policy carefully.

---

## Behavior analysis

| Symptom | Cause |
|---------|--------|
| Scripts never run | Default is correct: behavior is **disabled**. |
| `isolated` unavailable | Linux + bubblewrap + unprivileged user namespaces required. Unsupported hosts report unavailable and **do not** fall back to host execution. |
| `heuristic` feels dangerous | It **is** host execution, not a sandbox. Use only on throwaway machines. |

Details: [behavior-analysis.md](behavior-analysis.md).

---

## Lockfiles and ecosystems

| Symptom | What to try |
|---------|-------------|
| Python scan misses deps | Point at the real lockfile (`poetry.lock`, `uv.lock`, `Pipfile.lock`) not only `requirements.txt` if that is what you install. |
| Go/Cargo feels shallow | Preview scope: metadata + OSV, not full GA artifact analysis. |
| Large PyPI wheels fail | Over extraction budget packages fail closed (unscannable). See [known-limitations.md](known-limitations.md). |
| Monorepo / workspaces | Scan the lockfile your install actually uses (root workspace lock). |

---

## MCP / AI agents

| Symptom | What to try |
|---------|-------------|
| Agent never calls PkgSafe | Confirm MCP config points at `pkgsafe mcp serve` and the binary is on PATH for that process. |
| Agent installs anyway after BLOCK | Client must honor tool results. Tighten agent instructions / skills. See [integrations/](integrations/). |
| Hallucinated package names | Use `suggest_safe_alternative` / `validate_package_install` before install. |

---

## Performance

| Symptom | What to try |
|---------|-------------|
| Slow full lockfile scan | Use `--changed-only` in CI. Ensure local DB is warm (`update-db`). |
| Huge artifact downloads | Expected for large scientific wheels; budgets apply. |

---

## Exit codes (CI)

| Code | Meaning |
|------|---------|
| 0 | Success; fail-on threshold not hit |
| 1 | Findings at fail-on threshold |
| 2 | Usage / config error |
| 3 | Runtime / scanner error |
| 4 | Policy validation error |
| 5 | Lockfile / manifest parse error |

---

## Still stuck?

1. `pkgsafe doctor`
2. Re-run with `--json` and keep **rule IDs**, decision, and score
3. Redact secrets
4. Open feedback with the taxonomy in [feedback.md](feedback.md)
