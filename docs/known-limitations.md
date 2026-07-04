# Known Limitations

## GA candidate scope

PkgSafe GA v1 is scoped as **npm-first**. Core npm scanning, CI gating, MCP
tooling, local policy, OSV intelligence, and evidence reporting are gated by
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
  sandbox. `isolated` mode is Linux-only and requires bubblewrap with
  unprivileged user namespaces; it enforces namespace isolation with network
  disabled by default, but shares the host kernel and is not a hypervisor
  boundary. Unsupported hosts report unavailable and do not fall back to
  heuristic host execution.
- npm has the deepest artifact and lifecycle analysis coverage. npm and PyPI
  are the GA production scope; Go and Cargo are preview coverage and are not
  GA-equivalent across every package format.
- GA requires real repository validation. `production-readiness --json` reports
  `ga_ready=false` and explicit `ga_blockers` while repo counts, npm validation,
  scan duration, signing, provenance, checksum, SBOM, or release verification
  are below threshold.
- Offline scans require advisory and registry metadata to be synced or cached
  first. Missing advisory data fails closed rather than silently allowing a
  package.
- PyPI is GA (gates closed 2026-07-04, see
  `evidence/pypi/pypi-ga-gates-closed.md`). Dependency inventory covers
  `requirements.txt` (including `--hash` digests and line continuations),
  `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile`, and `Pipfile.lock`
  with per-`name@version` dedup; lockfile-recorded hashes, registries, and
  git/url sources are captured, and direct URL/VCS dependencies surface as
  UNKNOWN rather than being scanned under a same-named index package.
  Version resolution is pip-parity (PEP 440 ordering; pre-releases are
  selected only when pinned explicitly or when no stable release exists).
  Artifact static analysis covers setup/build, network, credential,
  environment-secret, cloud-metadata, encoded-exec, native-extension,
  orphaned-bytecode, wheel RECORD, and build-backend (in-tree
  `backend-path`, direct-URL build requires) signals. Remaining PyPI
  limitations: artifacts above the extraction budgets (40,000 files / 2 GiB
  uncompressed per artifact, sized ~2-3x above the top of PyPI by
  downloads) still fail closed as unscannable rather than being partially
  analyzed, conda `environment.yml` is unimplemented, no behavior execution
  exists for Python packages (static analysis only), and `ci scan` requires
  `--ecosystem pypi`.
- The local REST API is designed for loopback developer tooling and should not
  be exposed as a public service.
- Generated release artifacts must be produced by the release pipeline or
  `make package` before packaging readiness can pass.
