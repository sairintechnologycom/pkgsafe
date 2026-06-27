# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-beta.1] - 2026-06-27

First private beta release candidate. Local-first scanning, CI gating, MCP
tooling, and policy packs are functional; lifecycle behavior analysis remains
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
