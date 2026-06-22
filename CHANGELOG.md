# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
