# Known Limitations

## Beta stage (v0.2.0-beta.1)

PkgSafe is in **private beta**. Core scanning, CI gating, MCP tooling, and
policy packs are functional and gated by `pkgsafe test production-readiness`,
which currently returns `PRIVATE_BETA_READY`. The following are explicitly *not*
claimed at this stage:

- Production GA hardening is incomplete: signed-release, provenance, and
  online-benchmark gates are reported but treated as non-blocking follow-ups.
- Accuracy is validated against deterministic fixtures plus optional online and
  real-repo checks; it has not been validated at production scale.
- Connected-environment behavior (npm/PyPI/OSV reachability) is checked by
  `pkgsafe doctor` but may vary by network and registry availability.

## General limitations

- Behavior analysis is disabled by default. `heuristic` mode is best-effort: it
  redirects home, temp, and XDG paths and drops secret-like environment variables,
  but still runs scripts on the host and is not a container, namespace, or VM
  sandbox. `isolated` mode must not be claimed unless a real isolation backend is
  active.
- npm has the deepest artifact and lifecycle analysis coverage. PyPI, Go, and
  Cargo support is useful but not equivalent across every package format.
- GA requires real repository validation. `production-readiness --json` reports
  `ga_ready=false` and explicit `ga_blockers` while repo counts, ecosystem depth,
  isolated behavior backend, or release verification are below threshold.
- Offline scans require advisory and registry metadata to be synced or cached
  first. Missing advisory data fails closed rather than silently allowing a
  package.
- The local REST API is designed for loopback developer tooling and should not
  be exposed as a public service.
- Generated release artifacts must be produced by the release pipeline or
  `make package` before packaging readiness can pass.
