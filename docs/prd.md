# PkgSafe / Niyam Guard PRD

**Version:** 0.1
**Status:** Draft for MVP Execution
**Product Type:** Developer Security CLI, Local Package Firewall, AI-Agent Supply Chain Guardrail
**Primary Users:** Developers, Platform Engineering Teams, AppSec Teams, DevSecOps Teams, AI Coding Agent Users
**Initial Ecosystem:** npm
**Expansion Ecosystems:** PyPI, Go Modules, Maven, NuGet

## 1. Executive Summary

Modern software development increasingly depends on open-source packages, AI-generated code suggestions, automated dependency installation, and fast-moving developer workflows. This creates a rapidly expanding software supply chain attack surface.

Malicious packages, typosquatting, dependency confusion, lifecycle-script abuse, credential theft, and AI-hallucinated package names are now practical attack paths. Many existing tools focus on CVE scanning, repository dashboards, SBOM generation, or CI/CD-time detection. These are useful, but they often detect risk **after** a package has already entered the developer environment, source repository, or pipeline.

**PkgSafe** is a local-first, developer-friendly package security agent that validates packages **before installation**. It acts as a portable package firewall for developers and AI coding agents.

The MVP will start with npm and provide a CLI that can inspect packages, detect lifecycle scripts, flag suspicious install behavior, identify typosquatting risk, score package trust, and return a clear `allow`, `warn`, or `block` decision.

The strategic differentiator is the combination of:

1. Pre-install package validation
2. Local-first and offline-friendly execution
3. Developer-friendly CLI workflow
4. MCP-compatible interface for AI coding agents
5. Future sandboxed behavioral analysis
6. Human-readable risk explanations

## 2. Product Vision

PkgSafe should become the default local security layer between developers, AI coding agents, package registries, and dependency installation commands.

The long-term vision is:

> A portable developer security agent that prevents malicious, hallucinated, typosquatted, or suspicious open-source packages from entering developer machines, repositories, CI/CD systems, and enterprise software supply chains.

PkgSafe should not replace enterprise SCA platforms. Instead, it should complement them by operating earlier in the workflow: before package installation.

## 3. Product Positioning

### 3.1 One-Line Pitch

PkgSafe is a local-first package firewall that protects developers and AI coding agents from malicious or suspicious open-source dependencies before installation.

### 3.2 Expanded Pitch

PkgSafe validates packages before they are installed by analyzing registry metadata, lifecycle scripts, package reputation, typosquat risk, credential exposure patterns, known vulnerability intelligence, and future sandboxed runtime behavior. It provides clear allow/warn/block decisions through a CLI, JSON API, CI/CD integration, and MCP tools for AI coding agents.

### 3.3 Category

PkgSafe belongs to an emerging product category:

**Pre-Install Software Supply Chain Security**

Related categories:

* Software Composition Analysis
* Package Firewall
* Developer Security Tooling
* AI Coding Agent Guardrails
* Open-Source Dependency Trust Scoring
* DevSecOps Shift-Left Controls

## 4. Problem Statement

Developers install packages quickly, often based on documentation snippets, Stack Overflow answers, AI-generated code, or package search results. This creates several risks:

1. A malicious package may execute during installation.
2. A typosquatted package may mimic a popular package.
3. An AI coding assistant may suggest a non-existent or hallucinated package name.
4. An attacker may register that hallucinated package name.
5. Lifecycle scripts may read credentials, tokens, SSH keys, `.env` files, or cloud configuration files.
6. CVE scanners may not detect malicious intent because the package may not have a known vulnerability.
7. Enterprise tools often detect risk after dependency files are already committed.
8. Developers ignore tools that generate noisy, non-actionable dashboard alerts.

The core problem:

> Developers need a fast, local, explainable package safety decision before installing a dependency.

## 5. Target Users and Personas

### 5.1 Individual Developer

**Needs:**

* Avoid installing suspicious packages.
* Get simple explanations.
* Continue working without excessive friction.
* Use one command instead of learning complex security tools.

**Example:**

```bash
pkgsafe scan-npm-package axios
```

### 5.2 AI-Powered Developer

This user works with Cursor, Claude Code, Codex, Copilot, Gemini Code Assist, or other AI coding assistants.

**Needs:**

* Validate AI-suggested packages before installation.
* Detect hallucinated package names.
* Identify suspicious new packages.
* Prevent agentic tools from installing unsafe dependencies automatically.

**Example:**

An AI agent wants to install:

```bash
npm install react-auth-mongodb-adapter-pro
```

PkgSafe should flag whether the package appears legitimate, suspicious, or hallucinated.

### 5.3 Platform Engineering Team

**Needs:**

* Provide standard developer guardrails.
* Reduce dependency supply chain risk.
* Avoid central bottlenecks.
* Define policies that work across teams.
* Integrate with existing CI/CD and developer workflows.

### 5.4 AppSec / DevSecOps Team

**Needs:**

* Detect malicious package risk early.
* Reduce noisy SCA findings.
* Enforce policy selectively.
* Produce evidence for blocked or approved dependencies.
* Integrate with GitHub Actions, Azure DevOps, and enterprise reporting.

### 5.5 Enterprise Security Team

**Needs:**

* Organization-wide package policy.
* Allowlist and denylist controls.
* Private registry support.
* Air-gapped package intelligence.
* Audit trails and governance evidence.
* Integration with ServiceNow, SIEM, and enterprise security tooling.

## 6. Core Use Cases

### Use Case 1: Scan a Package Before Install

A developer wants to install an npm package.

```bash
pkgsafe scan-npm-package lodash
```

PkgSafe returns:

* Package name
* Version
* Risk score
* Decision
* Reasons
* Recommended action

### Use Case 2: Install Through PkgSafe

A developer installs through PkgSafe.

```bash
pkgsafe npm install axios
```

PkgSafe checks the package first. If allowed, it delegates to npm. If suspicious, it warns or blocks depending on policy.

### Use Case 3: Scan a Lockfile

A developer or CI job scans an existing lockfile.

```bash
pkgsafe scan-lockfile package-lock.json
```

PkgSafe identifies suspicious direct or transitive dependencies.

### Use Case 4: AI Agent Package Validation

An AI coding agent calls PkgSafe through MCP before suggesting or installing a package.

Example MCP request:

```json
{
  "ecosystem": "npm",
  "name": "next-auth-mongodb-adapter-pro",
  "version": "latest",
  "requested_by": "ai_agent"
}
```

PkgSafe returns:

```json
{
  "decision": "warn",
  "risk_score": 72,
  "reasons": [
    "Package was recently published",
    "No linked source repository",
    "Name resembles AI-generated package naming pattern",
    "Low ecosystem reputation"
  ]
}
```

### Use Case 5: Detect Lifecycle Script Risk

A package contains a `postinstall` script that runs `curl`.

PkgSafe should detect:

* Lifecycle script exists
* Network command exists
* Credential-related strings exist
* Obfuscation exists
* Suspicious process execution exists

Decision should be `warn` or `block` depending on severity.

### Use Case 6: Credential Exposure Protection

A package attempts to read:

```text
~/.aws/credentials
~/.ssh/id_rsa
.env
.npmrc
```

PkgSafe should block the package when sandbox analysis is enabled.

## 7. MVP Scope

### 7.1 MVP Goal

Build a working npm-focused CLI that can scan real npm packages before installation and return explainable risk decisions.

### 7.2 MVP Product Name

Recommended product structure:

* Product: **Niyam Guard**
* CLI: **pkgsafe**
* Module: **Package Safety Agent**

This allows future integration into the broader Niyam governance platform while keeping the CLI simple and developer-friendly.

## 8. MVP Functional Requirements

### 8.1 CLI Commands

The MVP should support:

```bash
pkgsafe scan-npm-package <package-name>
pkgsafe scan-npm-package <package-name> --version <version>
pkgsafe scan-npm-package <package-name> --json
pkgsafe scan-local-npm <path>
pkgsafe scan-lockfile <path-to-package-lock.json>
pkgsafe explain <package-name>
pkgsafe update-db
pkgsafe mcp serve
pkgsafe version
```

### 8.2 npm Registry Metadata Resolver

PkgSafe must fetch package metadata from the npm registry.

Required metadata:

* Package name
* Latest version
* Selected version
* Tarball URL
* Maintainers
* Repository URL
* Publish time
* License
* Description
* Dependencies
* Scripts
* Dist integrity
* Download metadata if available

### 8.3 Tarball Downloader

PkgSafe must download the selected npm package tarball into a local cache.

Requirements:

* Avoid repeated downloads for the same package/version.
* Verify tarball integrity when metadata includes integrity hash.
* Store package tarballs under PkgSafe cache directory.
* Support cache cleanup later.

### 8.4 Safe Extractor

PkgSafe must safely extract npm tarballs into a temporary directory.

Requirements:

* Prevent path traversal.
* Prevent overwriting files outside temp directory.
* Locate `package/package.json`.
* Handle invalid tarballs safely.
* Delete temp files after scan unless debug mode is enabled.

### 8.5 Static Package Analyzer

PkgSafe must inspect `package.json`.

Signals to detect:

* `preinstall`
* `install`
* `postinstall`
* `prepare`
* `scripts` containing suspicious command patterns
* Missing repository metadata
* Missing license
* New or unknown package
* Credential-related references
* Shell execution
* Network tools
* Encoded or obfuscated script patterns

Suspicious patterns:

```text
curl
wget
Invoke-WebRequest
powershell
bash -c
sh -c
eval
base64
atob
child_process
exec
spawn
.env
.npmrc
.aws
.ssh
.kube
token
secret
credential
metadata.google.internal
169.254.169.254
```

### 8.6 Risk Engine

PkgSafe must generate a deterministic risk score.

Score range:

```text
0-29    Allow
30-69   Warn
70-100  Block or High-Risk Warn
```

Initial scoring model:

| Signal                                           | Suggested Score |
| ------------------------------------------------ | --------------: |
| Known malicious package                          |             100 |
| Reads credential path                            |             100 |
| Lifecycle script exists                          |             +20 |
| Lifecycle script uses network command            |             +30 |
| Lifecycle script references secrets              |             +40 |
| Obfuscation detected                             |             +25 |
| Missing repository                               |             +10 |
| Missing license                                  |              +5 |
| Package recently published                       |             +15 |
| Low package maturity                             |             +10 |
| Typosquat risk                                   |             +25 |
| No maintainers or suspicious maintainer metadata |             +20 |
| Known trusted package                            |             -20 |

Decision must include explainable reasons.

### 8.7 Output Formats

Human-readable output:

```text
Decision: WARN
Package: npm/example-package@1.2.3
Risk Score: 61/100

Reasons:
- Package defines a postinstall script
- Lifecycle script uses curl
- Package metadata does not include a source repository

Recommended Action:
Review package before installing.
```

JSON output:

```json
{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
  "decision": "warn",
  "risk_score": 61,
  "reasons": [
    "Package defines a postinstall script",
    "Lifecycle script uses curl",
    "Package metadata does not include a source repository"
  ]
}
```

### 8.8 Local Cache

PkgSafe must maintain a local cache.

Initial cache format can be JSON. MVP+ should move to SQLite.

Cache should store:

* Package metadata
* Tarball path
* Scan result
* Scan timestamp
* Risk decision
* Reasons
* Threat DB version
* Policy version

### 8.9 MCP Server

PkgSafe must expose an MCP-compatible server for AI coding agents.

Initial tool:

```text
validate_package_install
```

Input:

```json
{
  "ecosystem": "npm",
  "name": "package-name",
  "version": "latest",
  "requested_by": "human|ai_agent"
}
```

Output:

```json
{
  "decision": "allow|warn|block",
  "risk_score": 0,
  "reasons": [],
  "safe_alternatives": []
}
```

Future MCP tools:

```text
explain_package_risk
score_lockfile
suggest_safe_alternative
validate_install_command
generate_dependency_policy
```

## 9. Non-Functional Requirements

### 9.1 Performance

PkgSafe should feel fast enough for developer workflows.

Targets:

| Operation                 |                              Target |
| ------------------------- | ----------------------------------: |
| Cached metadata scan      |                        Under 500 ms |
| Fresh metadata scan       |                     Under 3 seconds |
| Tarball download and scan | Under 10 seconds for normal package |
| Lockfile scan             |    Under 15 seconds for typical app |
| MCP response from cache   |                        Under 300 ms |

### 9.2 Portability

PkgSafe should ship as a single binary where possible.

Supported platforms:

| Platform      | MVP                    |
| ------------- | ---------------------- |
| Linux amd64   | Required               |
| macOS amd64   | Required               |
| macOS arm64   | Required               |
| Windows amd64 | Required, scanner only |
| Linux arm64   | Future                 |

### 9.3 Privacy

PkgSafe should be local-first.

Principles:

* Do not upload source code by default.
* Do not upload package manifests by default.
* Do not upload dependency graphs by default.
* Do not send developer environment data to cloud services.
* Make telemetry opt-in only.
* Enterprise policy sync should be explicit.

### 9.4 Security

PkgSafe must be secure by design.

Requirements:

* Safe tarball extraction
* No execution of untrusted lifecycle scripts in MVP static scan
* Sandboxed execution only in later phase
* Strict timeout controls
* No default access to host credentials during sandbox runs
* Clear policy decision logging
* Tamper-resistant release artifacts
* Checksums for binaries
* Signed releases in later phase

### 9.5 Explainability

Every decision must include reasons.

Bad output:

```text
Blocked due to high risk.
```

Good output:

```text
Blocked because the postinstall script references ~/.aws/credentials and executes curl.
```

## 10. Out of Scope for MVP

The following should not be built in the first MVP:

* SaaS dashboard
* Enterprise backend
* Full IDE extension
* PyPI support
* Go Modules support
* Maven support
* NuGet support
* ML-based detection
* Registry proxy
* Private registry firewall
* Full sandbox execution
* Organization-wide policy sync
* ServiceNow integration
* SIEM integration

## 11. MVP User Experience

### 11.1 Example: Safe Package

Command:

```bash
pkgsafe scan-npm-package lodash
```

Output:

```text
Decision: ALLOW
Package: npm/lodash@4.17.21
Risk Score: 12/100

Reasons:
- No lifecycle install scripts detected
- Repository metadata exists
- Package is mature and widely used
```

### 11.2 Example: Suspicious Package

Command:

```bash
pkgsafe scan-npm-package react-markdown-renderer-plus
```

Output:

```text
Decision: WARN
Package: npm/react-markdown-renderer-plus@1.0.1
Risk Score: 68/100

Reasons:
- Package was recently published
- Package metadata does not include a source repository
- Package name resembles common AI-generated package naming
- Package has low ecosystem reputation

Recommended Action:
Review before installing. Consider established alternatives.
```

### 11.3 Example: Malicious Install Script

Command:

```bash
pkgsafe scan-npm-package suspicious-package
```

Output:

```text
Decision: BLOCK
Package: npm/suspicious-package@1.0.0
Risk Score: 100/100

Reasons:
- Package defines a postinstall script
- Lifecycle script references ~/.aws/credentials
- Lifecycle script executes curl
- Script appears designed to access credential material

Recommended Action:
Do not install this package.
```

## 12. Success Metrics

### 12.1 Developer Adoption Metrics

| Metric                 |                  Target |
| ---------------------- | ----------------------: |
| GitHub stars           |    500+ in early launch |
| CLI installs/downloads | 1,000+ in first 60 days |
| Repeat users           |                    30%+ |
| MCP setup users        |     100+ early adopters |
| GitHub Action users    |              100+ repos |

### 12.2 Product Quality Metrics

| Metric                                  |           Target |
| --------------------------------------- | ---------------: |
| False positive rate on popular packages |         Below 5% |
| Scan success rate                       |        Above 95% |
| Cached scan response                    |     Under 500 ms |
| Fresh npm package scan                  | Under 10 seconds |
| Test coverage for core packages         |        Above 70% |

### 12.3 Security Metrics

| Metric                                   |    Target |
| ---------------------------------------- | --------: |
| Credential-reading test packages blocked |      100% |
| Known malicious packages blocked         |      100% |
| Suspicious lifecycle scripts flagged     | Above 90% |
| Typosquat candidates warned              | Above 80% |
| Safe common packages allowed             | Above 95% |

## 13. Technical Architecture

### 13.1 High-Level Architecture

```text
Developer / AI Agent
        |
        v
PkgSafe CLI / MCP Server
        |
        v
Package Resolver
        |
        +--> npm Registry Metadata Fetcher
        +--> Tarball Downloader
        +--> Lockfile Parser
        |
        v
Analyzer Layer
        |
        +--> Static Analyzer
        +--> Typosquat Analyzer
        +--> Trust Analyzer
        +--> Vulnerability Analyzer
        +--> Sandbox Analyzer
        |
        v
Risk Engine
        |
        v
Decision Engine
        |
        +--> Allow
        +--> Warn
        +--> Block
        |
        v
Output Layer
        |
        +--> Human Output
        +--> JSON
        +--> SARIF
        +--> MCP Response
```

### 13.2 Suggested Repository Structure

```text
pkgsafe/
  cmd/
    pkgsafe/
      main.go

  internal/
    cli/
    config/
    db/
    registry/
      npm/
      pypi/
    analyzer/
      npm/
      static/
      sandbox/
      typosquat/
      trust/
      vulnerability/
    cache/
    mcp/
    output/
    policy/
    risk/
    types/

  rules/
    default-policy.yaml
    credential-paths.yaml
    suspicious-patterns.yaml

  testdata/
    npm/
      safe-package/
      postinstall-network/
      reads-credentials/
      typosquat/

  docs/
    architecture.md
    threat-model.md
    mcp-usage.md
    roadmap.md
    enterprise.md

  scripts/
    package.sh

  .github/
    workflows/
      ci.yml
      release.yml

  README.md
  Makefile
  go.mod
```

## 14. Policy Model

PkgSafe should support a YAML policy file.

Example:

```yaml
mode: warn

thresholds:
  allow_max_score: 29
  warn_max_score: 69
  block_min_score: 70

protected_paths:
  - "~/.aws"
  - "~/.azure"
  - "~/.gcp"
  - "~/.ssh"
  - "~/.kube"
  - "~/.npmrc"
  - "~/.pypirc"
  - ".env"
  - ".env.local"
  - ".vault-token"

trusted_packages:
  npm:
    - lodash
    - axios
    - react
    - express

blocked_packages:
  npm: []

rules:
  lifecycle_script_present:
    severity: medium
    score: 20

  network_command_in_lifecycle:
    severity: high
    score: 30

  credential_path_reference:
    severity: critical
    score: 100

  typosquat_candidate:
    severity: high
    score: 25

  missing_repository:
    severity: low
    score: 10
```

## 15. Security Design Principles

PkgSafe must follow these principles:

1. Local-first by default
2. No source code upload by default
3. No telemetry without opt-in
4. Explain every decision
5. Do not execute untrusted package scripts unless sandboxed
6. Never expose real developer credentials to package scripts
7. Prefer warning over blocking unless risk is clear
8. Enterprise policies must be transparent to developers
9. Cache results for speed
10. Fail safely when package metadata is incomplete

## 16. Risks and Mitigations

| Risk                                    | Mitigation                                                  |
| --------------------------------------- | ----------------------------------------------------------- |
| False positives frustrate developers    | Default to warn mode and provide clear reasons              |
| Sandbox support is hard cross-platform  | Start with static scan, then Linux/macOS sandbox            |
| Enterprise tools already exist          | Position as pre-install local firewall, not SCA replacement |
| npm metadata can be incomplete          | Use multiple signals, not one signal                        |
| AI hallucination detection is imperfect | Start with heuristics and reputation scoring                |
| Registry rate limits                    | Use local cache                                             |
| Developers bypass tool                  | Make CLI fast and useful                                    |
| MCP clients vary                        | Keep MCP server simple and well-documented                  |

## 17. MVP Acceptance Criteria

The MVP is successful when:

1. `pkgsafe scan-npm-package <name>` works for real npm packages.
2. `pkgsafe scan-local-npm <path>` works for local package folders.
3. `pkgsafe scan-lockfile package-lock.json` works for npm lockfiles.
4. CLI returns `allow`, `warn`, or `block`.
5. CLI explains every decision.
6. JSON output is available.
7. Lifecycle scripts are detected.
8. Suspicious script patterns are detected.
9. Typosquat candidates are warned.
10. MCP `validate_package_install` returns package safety decision.
11. Tests pass in CI.
12. Release binaries are generated for Linux, macOS, and Windows.
