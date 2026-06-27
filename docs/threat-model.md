# Threat Model

PkgSafe is a local-first supply-chain security tool for dependency installation, repository scans, CI gates, and AI-agent guardrails.

## Assets

- Developer machines and CI runners
- Package manifests and lockfiles
- Private registry credentials
- Policy packs and exception records
- Vulnerability cache and scan evidence

## Primary Threats

- Malicious package install scripts
- Typosquatting and dependency confusion
- Known vulnerable package versions
- Credential and environment secret access
- Registry fallback from private to public
- AI coding agents installing risky packages without review
- Secret leakage through reports, SARIF, logs, or evidence packs

## Controls

- Static manifest and source-import inventory
- npm tarball and PyPI artifact scanning with safe extraction controls
- OSV vulnerability lookup and local SQLite cache
- Fail-closed CI and MCP guardrails
- Private registry routing and public fallback controls
- Secret redaction in generated evidence
- Release checksums, SBOM, and signing/provenance-ready workflow

## Non-Goals

- PkgSafe is not a hosted registry proxy.
- PkgSafe is not a malware ML classifier.
- Behavior analysis is best-effort and currently labelled as such.
