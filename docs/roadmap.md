# PkgSafe / Niyam Guard Roadmap

**Version:** 0.1
**Status:** Draft for MVP Execution

## 1. Roadmap

## Phase 0: Starter Baseline

**Status:** Complete / In Progress

Objective:

Create the first working CLI package structure.

Capabilities:

* Go CLI project
* Local npm package scanner
* Lockfile scanner
* Risk engine
* Basic MCP stub
* Test fixtures
* Build scripts
* Release packages

Exit criteria:

* CLI builds successfully.
* Tests pass.
* Local fixtures scan correctly.
* Release binaries are generated.

## Phase 1: Real npm Registry Scanner

**Timeline:** Sprint 1
**Priority:** Critical

Objective:

Enable PkgSafe to scan real npm packages from the public registry.

Features:

* `pkgsafe scan-npm-package <name>`
* `--version`
* `--json`
* npm metadata fetcher
* latest version resolver
* tarball downloader
* safe extractor
* package.json analyzer
* risk scoring
* result cache

Acceptance criteria:

* Scans real npm packages.
* Detects lifecycle scripts.
* Detects suspicious script patterns.
* Handles missing packages gracefully.
* Supports human and JSON output.
* Tests cover registry metadata and tarball fixture scanning.

## Phase 2: Risk Engine Hardening

**Timeline:** Sprint 2
**Priority:** High

Objective:

Improve risk quality and reduce false positives.

Features:

* Policy-driven scoring
* Configurable thresholds
* Trusted package allowlist
* Denylist
* Package age checks
* Repository metadata checks
* Maintainer metadata checks
* Typosquat similarity scoring
* Better reason generation
* Debug mode

Acceptance criteria:

* Users can configure allow/warn/block thresholds.
* High-trust packages are not over-warned.
* Suspicious unknown packages are clearly flagged.
* Output explains scoring clearly.
* Policy file loads successfully.

## Phase 3: OSV and Advisory Data

**Timeline:** Sprint 3
**Priority:** High

Objective:

Add known vulnerability intelligence.

Features:

* OSV query support
* GitHub Advisory DB support later
* Local vulnerability cache
* `pkgsafe update-db`
* Vulnerability-based scoring
* CVE/GHSA reporting in output
* Offline vulnerability check from cache

Acceptance criteria:

* Known vulnerable package versions are detected.
* Scan results include vulnerability IDs.
* Offline mode can use cached advisory data.
* JSON output includes vulnerability details.

## Phase 4: MCP Guardrail for AI Agents

**Timeline:** Sprint 4
**Priority:** Critical Strategic Differentiator

Objective:

Allow AI coding agents to call PkgSafe before package installation.

Features:

* `pkgsafe mcp serve`
* MCP tool: `validate_package_install`
* MCP tool: `explain_package_risk`
* MCP tool: `score_lockfile`
* Cursor configuration example
* Claude Code configuration example
* Codex configuration example
* Local REST bridge optional

Acceptance criteria:

* MCP client can validate a package.
* AI-agent request returns allow/warn/block.
* Response includes risk score and reasons.
* Documentation includes setup examples.
* MCP tool does not require cloud connectivity.

## Phase 5: Isolated Behavior Analysis

**Timeline:** Sprint 5-6
**Priority:** Major Differentiator

Objective:

Detect malicious install-time behavior with real containment.

Features:

* Isolated behavior backend
* Fake HOME directory
* Fake credential canaries
* Lifecycle script execution in restricted environment
* File access logging
* Process execution logging
* Network attempt detection
* Timeout and resource limits
* Block if credential canaries are accessed

Protected paths:

```text
~/.aws/credentials
~/.ssh/id_rsa
~/.npmrc
~/.pypirc
.env
.env.local
~/.kube/config
~/.azure/
~/.gcp/
.vault-token
```

Acceptance criteria:

* Package reading fake credentials is blocked.
* Package executing network exfiltration is blocked or high-risk warned.
* Safe lifecycle scripts are not blocked unnecessarily.
* Isolated backend has strict timeout and cleanup behavior.
* Host credentials are never exposed.

## Phase 6: GitHub Action and CI/CD Integration

**Timeline:** Sprint 7
**Priority:** High

Objective:

Enable PkgSafe in CI/CD workflows.

Features:

* GitHub Action
* SARIF output
* JSON output
* Fail-on-block mode
* Warn-only mode
* Dependency lockfile scanning
* Pull request annotation

Acceptance criteria:

* GitHub Action runs on PR.
* Risk findings appear in PR output.
* Critical blocked packages fail workflow.
* SARIF output can be uploaded to security tab.

## Phase 7: PyPI Support

**Timeline:** Sprint 8-10
**Priority:** Medium-High

Objective:

Expand from npm to Python ecosystem.

Features:

* `pkgsafe scan-pypi-package <name>`
* `requirements.txt` scanner
* `pyproject.toml` scanner
* Wheel vs sdist detection
* setup/build backend risk scoring
* PyPI metadata resolver
* Python package trust score

Acceptance criteria:

* PkgSafe scans PyPI metadata.
* PkgSafe detects suspicious Python packaging behavior.
* Requirements files can be scanned.
* JSON output is consistent with npm scanner.

## Phase 8: Enterprise Policy and Governance

**Timeline:** Post-MVP
**Priority:** Enterprise

Objective:

Make PkgSafe useful for organizations.

Features:

* Central policy file
* Team allowlist
* Team denylist
* Private registry support
* Enterprise offline DB mirror
* Audit logs
* ServiceNow evidence export
* SIEM export
* Niyam governance integration
* Azure DevOps integration
* GitHub organization policy

Acceptance criteria:

* Platform team can define standard policy.
* Developers can run locally with org policy.
* CI/CD can enforce same policy.
* Audit evidence can be exported.

## Phase 9: Developer Experience and IDE

**Timeline:** Post-MVP
**Priority:** Medium

Objective:

Improve adoption through IDE and editor workflows.

Features:

* VS Code extension
* Dependency suggestion validation
* Inline package trust warning
* Package hover cards
* Install command interception
* MCP-first architecture
* Local REST API

Acceptance criteria:

* Developer gets warning before adding suspicious package.
* IDE can call local PkgSafe service.
* No cloud account required for basic usage.

## Phase 10: Commercial Platform

**Timeline:** Later
**Priority:** Monetization

Objective:

Convert PkgSafe into a commercial product.

Open-source core:

* CLI scanner
* npm support
* local policy
* MCP server
* JSON output

Paid features:

* Curated malware intelligence
* Enterprise policy sync
* Private registry support
* Air-gapped package DB
* Team dashboard
* Audit reports
* SSO/RBAC
* ServiceNow integration
* SIEM integration
* Azure DevOps and GitHub Enterprise support

## 2. Implementation Plan for Next Sprint

### Sprint Objective

Build the real npm registry scanner.

### Sprint Scope

Implement:

```bash
pkgsafe scan-npm-package <package-name> [--version <version>] [--json]
```

### Engineering Tasks

1. Add npm registry client.
2. Fetch package metadata.
3. Resolve latest version.
4. Extract tarball URL.
5. Download tarball to cache.
6. Safely extract tarball.
7. Locate `package.json`.
8. Reuse existing npm analyzer.
9. Connect result to risk engine.
10. Add JSON output.
11. Add tests with mocked registry response.
12. Add tests with local fixture tarball.
13. Update README.
14. Update CLI help text.
15. Update release packaging.

### Sprint Exit Criteria

* Command works for real npm packages.
* Tests pass.
* Documentation updated.
* Binary builds successfully.
* JSON output is stable enough for MCP/CI usage.

## 3. Packaging and Distribution

### 3.1 CLI Distribution

Initial distribution:

* GitHub releases
* `.tar.gz` for Linux
* `.tar.gz` for macOS
* `.zip` for Windows
* SHA256 checksums

Later distribution:

* Homebrew tap
* npm wrapper package
* Docker image
* GitHub Action
* Winget
* Chocolatey
* apt/yum packages

### 3.2 Versioning

Use semantic versioning.

```text
0.1.x    MVP scanner
0.2.x    npm registry scanner
0.3.x    OSV support
0.4.x    MCP hardening
0.5.x    isolated behavior analysis
1.0.0    stable npm + MCP + CI release
```

## 4. Open-Source Strategy

Recommended model:

### Open-source core

* CLI
* npm scanner
* static analysis
* policy engine
* JSON output
* MCP server
* GitHub Action

### Commercial extensions

* Enterprise policy sync
* Private registry support
* Air-gapped DB
* Curated malware feed
* Audit dashboard
* SSO/RBAC
* SIEM export
* ServiceNow integration
* Organization-wide reporting

This model increases adoption while preserving a monetization path.

## 5. Competitive Differentiation

PkgSafe should not compete directly as a full SCA dashboard.

It should win on:

| Differentiator             | Why It Matters                |
| -------------------------- | ----------------------------- |
| Pre-install scanning       | Stops risk before install     |
| Local-first CLI            | Works in developer workflow   |
| MCP support                | Protects AI coding agents     |
| Isolated behavior roadmap  | Detects malicious intent      |
| Explainable decisions      | Developers trust the tool     |
| Offline-friendly cache     | Useful in enterprise networks |
| Portable binary            | Easy rollout                  |
| Policy-as-code             | Platform engineering friendly |

## 6. Future Vision

PkgSafe should eventually become:

1. A local package firewall for developers
2. A dependency safety engine for AI coding agents
3. A CI/CD package trust gate
4. A governance evidence generator for platform teams
5. A commercial enterprise policy layer for open-source dependency control

The long-term platform opportunity is to make PkgSafe part of a broader **Niyam governance ecosystem**, where AI agents, developer tools, CI/CD pipelines, and enterprise platforms call the same policy engine before risky actions are executed.

## Appendix A: Example Codex Implementation Prompt

```text
We have a Go CLI project called PkgSafe.

Goal:
Implement real npm registry package scanning.

Current baseline:
- CLI exists under cmd/pkgsafe
- Local npm analyzer exists
- Risk engine exists
- Policy structure exists
- MCP stub exists
- Tests pass

Implement the next MVP milestone:

Command:
pkgsafe scan-npm-package <package-name> [--version <version>] [--json]

Requirements:
1. Fetch npm metadata from https://registry.npmjs.org/<package-name>
2. Resolve latest version if --version is not provided.
3. Read dist.tarball URL for the selected version.
4. Download tarball into local cache.
5. Extract tarball safely into a temporary directory.
6. Locate package/package.json inside extracted tarball.
7. Reuse existing npm analyzer to inspect package.json.
8. Detect lifecycle scripts:
   - preinstall
   - install
   - postinstall
   - prepare
9. Detect suspicious script patterns:
   - curl
   - wget
   - Invoke-WebRequest
   - base64
   - eval
   - child_process
   - .env
   - .npmrc
   - .aws
   - .ssh
   - .kube
   - token
   - secret
10. Return allow/warn/block decision using existing risk engine.
11. Support human-readable and JSON output.
12. Add unit tests using mocked npm registry responses and local fixture tarballs.
13. Do not implement isolated behavior execution yet.
14. Do not add a cloud backend.
15. Keep package boundaries clean and testable.

Expected command examples:
pkgsafe scan-npm-package axios
pkgsafe scan-npm-package lodash --json
pkgsafe scan-npm-package some-package --version 1.2.3

Acceptance criteria:
- Existing tests continue to pass.
- New tests cover latest version resolution.
- New tests cover tarball extraction.
- New tests cover package with postinstall script.
- New tests cover package with credential path reference.
- JSON output includes package, version, ecosystem, score, decision, and reasons.
```

## Appendix B: Launch Narrative

PkgSafe is not another dashboard. It is a local package firewall for the AI-assisted development era.

It protects the moment that matters most:

```text
Before the package is installed.
Before the lifecycle script runs.
Before credentials are exposed.
Before the dependency enters source control.
Before the AI agent makes a risky install decision.
```

That is the wedge.
