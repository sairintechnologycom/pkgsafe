# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- PyPI production depth (Loop 8). Lockfile parsing is now table-aware for
  `poetry.lock` and `uv.lock` (sub-tables no longer clobber entries; artifact
  hashes, explicit registries, and git/url sources are recorded; the
  project's own virtual/editable lock entry is never scanned against PyPI).
  `requirements.txt` handles backslash continuations, `--hash` digests, and
  PEP 508 `name @ url` direct references. `Pipfile.lock` records hashes and
  resolves index names to URLs. Names are PEP 503-canonicalized and
  validated. `ci scan --ecosystem pypi` discovers `Pipfile`/`Pipfile.lock`,
  dedups the inventory to one scan target per `name@version`, marks
  lockfile-only dependencies as transitive, and surfaces direct URL/VCS
  dependencies as UNKNOWN (fail closed) instead of scanning a same-named
  index package.
- New PyPI artifact findings: orphaned compiled bytecode
  (`pypi_compiled_bytecode_payload`), wheel RECORD anomalies
  (`pypi_wheel_record_missing`, `pypi_wheel_record_unlisted_files`), in-tree
  build backends (`pypi_in_tree_build_backend`), and direct URL/VCS build
  requirements (`pypi_build_requires_direct_reference`). Wheel
  `{name}.data/scripts/` files are analyzed as install execution surfaces.

### Fixed
- PyPI false block: nested example/test `setup.py` and `pyproject.toml`
  files inside a source distribution no longer score as install surfaces
  (click 8.1.7 previously blocked at score 100 from 11 inert example
  `setup.py` files; it now allows at 20).

## [1.2.0] - 2026-07-02

### Added
- `pkg/cli` gains `RunConfig`, `RunWith`, and `ExecuteWith` so downstream
  distributions can customize dispatch. The only current knob,
  `CIEnterpriseMode`, enables the enterprise evidence enrichment already
  implemented in the CI scan engine (per-finding policy/registry/trust/
  exception evidence, policy pack metadata, exceptions-used tracking). The
  public `pkgsafe` binary keeps the zero-value config; public `ci scan`
  output is unchanged.

## [1.1.0] - 2026-07-02

### Added
- Importable CLI entry point: command dispatch moved from `cmd/pkgsafe`
  (package main) to the exported `pkg/cli` package (`cli.Run`,
  `cli.Execute`). The `pkgsafe` binary is now a thin shim over `pkg/cli`,
  and downstream distributions (such as the private enterprise superset
  binary) can embed the identical command surface via the Go module. No
  command behavior changes.

## [1.0.2] - 2026-07-02

Post-GA calibration release: fixes PyPI false blocks on known-good packages
and completes the open-core public/private boundary cleanup. All-loop E2E
qualification for this line is recorded in
`evidence/e2e/E2E_VALIDATION_SUMMARY.md` (`E2E_PASS: true`, `blockers: 0`).

### Fixed
- PyPI analyzer no longer false-blocks known-good packages (`requests`,
  `fastapi`, `flask`, `click`, `pydantic`, `pytest`, `urllib3`, `pandas`,
  `idna`). Static Python behavior patterns now score only install-like
  execution surfaces (`scripts/`, `bin/`, `__main__.py`) instead of every
  `.py` file; `setup.py` keeps its dedicated risk analysis path.
- Native-extension presence is recorded once per artifact instead of once per
  native file, reducing finding noise on wheels with compiled extensions.

### Removed
- Enterprise-only implementation moved to the private downstream repository
  per the open-core model: signed policy pack create/install/verify, SIEM /
  ServiceNow / Azure DevOps exporters, and enterprise MCP report surfaces.
  Public commands return explicit handoff errors pointing to
  `pkgsafe-enterprise`. The public repo remains OSS core, interfaces/stubs,
  and public docs.

## [0.2.0-beta.1] - 2026-06-27

First private beta release candidate. Local-first scanning, CI gating, MCP
tooling, and local policy workflows are functional; lifecycle behavior analysis remains
best-effort and is labelled as such.

### Added
- Release candidate metadata: `pkgsafe version` reports the `v0.2.0-beta.1`
  line, a release notes template (`docs/release-notes-template.md`), and beta
  known-limitations updates.
- Connected-environment validation: `pkgsafe doctor` (without `--skip-network`)
  now probes npm, PyPI, and OSV registry reachability instead of OSV only.
- Online benchmark checks recorded separately from deterministic fixtures, so
  connected-mode accuracy is reported without weakening the offline-only gate.
- Stage-aware production readiness: `INTERNAL_ALPHA_READY`, `PRIVATE_BETA_READY`,
  `PUBLIC_BETA_READY`, `PRODUCTION_GA_READY`, and `BLOCKED` stages, plus explicit
  status fields (`online_benchmark_status`, `github_action_status`,
  `signed_release_status`, `sbom_status`, `provenance_status`, `docs_status`,
  `real_repo_validation_count`, `private_beta_recommendation`).
- Real-repository validation: `pkgsafe test benchmark --repo ./path` collects
  scan duration and dependency counts, and grades against an optional
  expectation file for false warn/block annotations.
- Beta feedback workflows: GitHub issue forms for bug / false-positive /
  false-negative / security reports, plus `docs/beta-feedback.md`.
- Release integrity documentation: checksum, cosign keyless signature, build
  provenance attestation, SBOM, and reproducible-build notes
  (`docs/release-integrity.md`).

### Added (foundational, first tagged release)
- Created policy-driven risk engine allowing users to customize security checks via a YAML configuration file.
- Added comprehensive documentation including:
  - Product Requirement Document (PRD) (`docs/prd.md`)
  - Architectural overview (`docs/architecture.md`)
  - Project Roadmap (`docs/roadmap.md`)
- Added validation for policy rules, custom thresholds, and package list filtering.
- Implemented **Local Threat Intelligence + OSV Vulnerability DB** milestone:
  - Set up OSV vulnerability querying for npm packages using OSV API.
  - Added a local SQLite database cache (`~/.pkgsafe/pkgsafe.db`) storing vulnerability records, package vulnerability index, and metadata.
  - Implemented `pkgsafe update-db` to update local vulnerability data.
  - Implemented `pkgsafe db status` to print threat database health and record statistics.
  - Added support for `--offline` scans in `scan-npm-package`, `scan-lockfile`, and `explain`.
  - Added policy-driven risk engine scoring rules for critical/high/medium/low severity vulnerabilities and malware indicators.
  - Updated scan output to report vulnerabilities in both human-readable and structured JSON formats, with remediation guidance.

### Fixed
- Fixed blocked-package policy enforcement to correctly analyze all transitive and direct dependencies extracted from lockfiles (such as npm `package-lock.json`), preventing blocked dependencies from being accepted.
- Fixed a bug where custom `protected_paths` configurations did not clear or update the internal default `BlockPatterns` list. Dynamic block pattern derivation now correctly regenerates patterns whenever `protected_paths` is customized.

### Security
- Strengthened supply-chain risk mitigation by ensuring custom blocked npm packages are strictly checked during lockfile scans.
- Added offline-capable local vulnerability lookup to scan third-party packages for known CVEs/GHSAs without requiring active network connectivity.
