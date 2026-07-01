# Known Limitations

## GA candidate scope

PkgSafe GA v1 is scoped as **npm-first**. Core npm scanning, CI gating, MCP
tooling, policy packs, OSV intelligence, and evidence reporting are gated by
`pkgsafe test production-readiness`. The following are explicitly *not* claimed
until their GA gates are verified:

- Production GA hardening is incomplete while signed-release, provenance,
  checksum, SBOM, online-benchmark, and real-repo evidence gates remain
  unverified.
- Accuracy is validated against deterministic fixtures plus optional online and
  real-repo checks; GA requires 15 executable real-repo validations.
- Connected-environment behavior (npm/PyPI/OSV reachability) is checked by
  `pkgsafe doctor` but may vary by network and registry availability.

## General limitations

- Behavior analysis is disabled by default. `heuristic` mode is best-effort: it
  redirects home, temp, and XDG paths and drops secret-like environment variables,
  but still runs scripts on the host and is not a container, namespace, or VM
  sandbox. `isolated` mode is experimental, Linux-only, and requires bubblewrap;
  unsupported hosts report unavailable and do not fall back to heuristic host
  execution.
- npm has the deepest artifact and lifecycle analysis coverage and is the GA v1
  production scope. PyPI, Go, and Cargo are preview coverage and are not
  npm-equivalent across every package format.
- GA requires real repository validation. `production-readiness --json` reports
  `ga_ready=false` and explicit `ga_blockers` while repo counts, npm validation,
  scan duration, signing, provenance, checksum, SBOM, or release verification
  are below threshold.
- Offline scans require advisory and registry metadata to be synced or cached
  first. Missing advisory data fails closed rather than silently allowing a
  package.
- PyPI remains preview. Dependency inventory now covers `requirements.txt`,
  `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile`, and `Pipfile.lock`,
  and artifact static analysis covers common setup/build, network, credential,
  environment-secret, cloud-metadata, encoded-exec, and native-extension
  signals. Remaining PyPI caveats include incomplete ecosystem benchmark depth,
  no default behavior execution, no PyPI GA claim, and no guarantee that every
  Python packaging edge case is parsed.
- The local REST API is designed for loopback developer tooling and should not
  be exposed as a public service.
- Generated release artifacts must be produced by the release pipeline or
  `make package` before packaging readiness can pass.
