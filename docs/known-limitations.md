# Known limitations

Honest scope for PkgSafe GA. Read this before treating results as complete
security coverage.

## GA scope

**In scope (GA):** npm and PyPI package and lockfile scanning, local policy,
OSV intelligence, CI gating, MCP tools, evidence-style reports.

**Preview (not GA-depth):** Go modules and Cargo — metadata and OSV, not full
artifact analysis equivalent to npm/PyPI.

**Not a full SCA platform:** PkgSafe is a **pre-install firewall**. It
complements post-commit SCA, SBOM, and enterprise dashboards; it does not
replace them.

## Behavior analysis

- Off by default. Static scans never execute package code.
- `heuristic` runs scripts **on the host**. It is not a container, namespace, or
  VM sandbox.
- `isolated` is **Linux-only** (bubblewrap + unprivileged user namespaces). It
  shares the host kernel. Network is off by default. Unsupported hosts report
  unavailable and do **not** fall back to heuristic execution.
- See [behavior-analysis.md](behavior-analysis.md).

## Accuracy and evidence

- Fixture and real-repo benchmarks guide quality; no scanner is zero false
  positive / false negative.
- Report false results with rule IDs via [feedback.md](feedback.md).
- Connected behavior depends on registry and OSV reachability (`pkgsafe doctor`).

## Offline mode

- Needs a prior advisory sync or a verified offline bundle.
- Missing intelligence **fails closed** — packages are not silently allowed.
- See [offline-intelligence-bundle.md](offline-intelligence-bundle.md).

## PyPI specifics

Supported inventory includes `requirements.txt` (with hashes where present),
`pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile` / `Pipfile.lock`.

Still limited or out of scope:

- Artifacts over extraction budgets fail closed as unscannable (not partial
  scan).
- No conda `environment.yml` yet.
- No full Python behavior execution path equivalent to npm lifecycle isolation
  in all environments.
- Direct URL / VCS deps may surface as unknown rather than scanned as a registry
  package of the same name.

## Other surfaces

- Local REST API is for **loopback** developer use, not a public service.
- Windows is supported for the binary; some isolation features remain Linux-only.
- Generated release artifacts and signing proofs must come from the official
  release pipeline when you verify production installs.

## Related

- [Getting started](getting-started.md)
- [Policy guide](policy-guide.md)
- [Troubleshooting](troubleshooting.md)
- [Architecture](architecture.md)
