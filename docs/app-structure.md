# PkgSafe App Structure

This file captures the current repository structure in a Graphify-style form for future reference. It is a human-readable map of the app's current state, not a generated API reference.

Generated from the repository state on 2026-06-27 using `rg --files`, `find`, and `go list`.

## System Snapshot

PkgSafe is a local-first package safety CLI for developer and AI-agent workflows. The main surfaces are:

- CLI binary: `cmd/pkgsafe`
- Local REST API: `internal/api`
- MCP stdio server: `internal/mcp`
- GitHub Action entrypoint: `action.yml` and `scripts/github-action-entrypoint.sh`
- Shell/interception shims: `internal/intercept`, `internal/cli`, and `docs/*-interception.md`
- VS Code extension prototype: `editors/vscode`

The core loop is:

```text
user/tool command
  -> cmd/pkgsafe command router
  -> scanner or workflow package
  -> registry/dependency/analyzer/intel/policy/risk packages
  -> types.ScanResult
  -> output, cache, report, API, or MCP response
```

## Top-Level Tree

```text
.
|-- cmd/pkgsafe/              CLI entrypoint and command wiring
|-- internal/                 Go application packages
|-- docs/                     product, architecture, policy, MCP, CI/CD docs
|-- editors/vscode/           VS Code extension source and package metadata
|-- scripts/                  install and GitHub Action entrypoint scripts
|-- benchmarks/               benchmark fixture definitions
|-- testdata/                 scan, parser, CI, and corpus fixtures
|-- default-policy.yaml       embedded/reference default policy
|-- action.yml                GitHub Action metadata
|-- Makefile                  build/test/package tasks
|-- go.mod, go.sum            Go module definition
```

## Entry Points

`cmd/pkgsafe/main.go` is the command router. It dispatches these command families:

- Package scans: `scan-npm-package`, `scan-pypi-package`, `scan-python-deps`, `scan-go-deps`, `scan-cargo-deps`, `scan-local-npm`, `scan-lockfile`
- Package explanation/install safety: `explain`, `explain-pypi`, `npm-install`
- Policy and enterprise packs: `policy validate`, `policy explain`, `policy pack ...`
- Registry operations: `registry list`, `registry test`, `registry auth status`
- Reporting: `report generate`, `report evidence-pack`, `report ci`, SIEM/ServiceNow/Azure DevOps exports
- Agent/API surfaces: `mcp serve`, `serve-api`
- CI and validation: `ci scan`, `test corpus`, `test benchmark`, readiness checks
- Interception/shims: `npm`, `pip`, `python`, `run`, `init shell`
- Maintenance: `update-db`, `db status`, `doctor`, `inventory`, `version`

## Main Package Groups

| Package | Role |
| --- | --- |
| `internal/types` | Shared contracts such as `ScanResult`, `Reason`, `Decision`, vulnerability, sandbox, artifact, policy, registry, trust, and exception evidence. |
| `internal/policy` | Default/custom policy loading, thresholds, rule scores, trust rules, exceptions, scoped rules, registry config, enterprise controls. |
| `internal/risk` | Converts reasons/signals into `allow`, `warn`, `block`, or `unknown`; applies enterprise controls. |
| `internal/scanner/npm` | Full npm package scanner: registry metadata, tarball download/integrity, static analysis, OSV/cached vulnerability checks, sandbox summary. |
| `internal/scanner/pypi` | PyPI package scanner: registry/artifact metadata, static Python packaging analysis, vulnerability checks, typosquat signals. |
| `internal/scanner/golang` | Go dependency/package scanner using OSV/intel and policy/risk evaluation. |
| `internal/scanner/cargo` | Cargo dependency/package scanner using OSV/intel and policy/risk evaluation. |
| `internal/analyzer/npm` | Static npm package and lockfile analysis: lifecycle scripts, suspicious script patterns, typosquat and vulnerability reason generation. |
| `internal/analyzer/pypi` | Static PyPI source metadata analysis: setup/pyproject patterns and suspicious packaging behavior. |
| `internal/registry/npm` | npm metadata client, version resolution, tarball download, integrity verification, tar extraction, package.json lookup. |
| `internal/registry/pypi` | PyPI metadata/artifact client, artifact inspection, version handling. |
| `internal/registry` | Registry selection, auth config, policy-backed registry routing, public/private scope checks. |
| `internal/intel` and `internal/intel/osv` | OSV advisory ingestion, version impact checks, malware/advisory classification. |
| `internal/db` | SQLite schema, migrations, vulnerability and metadata storage. |
| `internal/cache` | Local scan-result cache for offline and repeat scans. |
| `internal/deps/*` | Dependency inventory/parsers for npm, Python, Go, and Cargo manifests/lockfiles. |
| `internal/intercept` | Command parsing, validation, enforcement, audit logging, shell command execution, redaction. |
| `internal/cli` | CLI helpers for shims, doctor, DB update/status, shell initialization. |
| `internal/ci` | CI lockfile scan workflow, concurrency, summaries, exit-code behavior. |
| `internal/mcp` | MCP JSON-RPC server and tools for package validation, risk explanation, lockfile scoring, governance reports, recent decisions, policy evidence. |
| `internal/api` | Local HTTP API for package validation through npm/PyPI scanners. |
| `internal/report` | Governance/report generation in JSON, Markdown, HTML, CSV, SARIF, evidence pack, SIEM, ServiceNow, Azure DevOps formats. |
| `internal/enterprise` | Signed policy packs, keys, checksums, metadata, install/create/verify/export flows. |
| `internal/sandbox` | Fake-home process runner and behavior-analysis request/result plumbing. |
| `internal/agent` | AI-agent install command parsing, safe alternatives, AI squatting heuristics. |
| `internal/audit` | Audit reader for recent decisions and report inputs. |
| `internal/git` | Git metadata/diff helpers for inventory, reporting, CI. |
| `internal/output` | Human and JSON `ScanResult` output formatting. |
| `internal/validation` | Corpus, benchmark, rollout-readiness, and production-readiness validation workflows. |
| `internal/logging` | Shared logging setup. |
| `internal/typosquat` | String heuristics for package-name similarity. |
| `internal/version` | Build version/commit source of truth. |

## Dependency Graph

High-level source dependencies between internal packages:

```text
cmd/pkgsafe
  -> analyzer/npm
  -> api
  -> cache
  -> ci
  -> cli
  -> deps/{cargo,golang,npm,python}
  -> enterprise
  -> intercept
  -> mcp
  -> output
  -> policy
  -> registry
  -> report
  -> scanner/{cargo,golang,npm,pypi}
  -> types
  -> validation
  -> version

scanner/npm
  -> agent
  -> analyzer/npm
  -> cache
  -> db
  -> deps/npm
  -> intel, intel/osv
  -> policy
  -> registry, registry/npm
  -> risk
  -> sandbox
  -> types

scanner/pypi
  -> agent
  -> analyzer/pypi
  -> cache
  -> db
  -> intel, intel/osv
  -> policy
  -> registry, registry/pypi
  -> risk
  -> types
  -> typosquat

scanner/{golang,cargo}
  -> cache
  -> db
  -> intel, intel/osv
  -> policy
  -> registry
  -> risk
  -> types

analyzer/npm
  -> db
  -> intel
  -> policy
  -> risk
  -> types
  -> typosquat

analyzer/pypi
  -> policy
  -> risk
  -> types

mcp
  -> agent
  -> audit
  -> db
  -> intel
  -> output
  -> policy
  -> registry
  -> report
  -> risk
  -> scanner/{npm,pypi}
  -> types
  -> typosquat

api
  -> policy
  -> scanner/{npm,pypi}
  -> types

ci
  -> cache
  -> deps/python
  -> logging
  -> policy
  -> scanner/{npm,pypi}
  -> types

intercept
  -> cache
  -> deps/python
  -> policy
  -> registry
  -> scanner/{npm,pypi}
  -> types

report
  -> audit
  -> cache
  -> deps/python
  -> git
  -> policy
  -> registry
  -> scanner/{npm,pypi}
  -> types
```

## Key Runtime Flows

### npm Package Scan

```text
cmd/pkgsafe scan-npm-package
  -> loadPolicy
  -> scanner/npm.New().ScanPackage
  -> registry.ResolveRegistry
  -> registry/npm.FetchMetadata
  -> registry/npm.ResolveVersion
  -> registry/npm.DownloadTarball
  -> registry/npm.VerifyTarballIntegrity
  -> registry/npm.ExtractTarball
  -> analyzer/npm.AnalyzePackageDir
  -> optional sandbox.ProcessRunner
  -> db/intel OSV vulnerability lookup
  -> risk.Evaluate
  -> risk.ApplyEnterpriseControls
  -> cache save
  -> output.Write
```

### PyPI Package Scan

```text
cmd/pkgsafe scan-pypi-package
  -> loadPolicy
  -> scanner/pypi.New().ScanPackage
  -> registry.ResolveRegistry
  -> registry/pypi metadata/artifact inspection
  -> analyzer/pypi source metadata checks
  -> typosquat/agent heuristics
  -> db/intel OSV vulnerability lookup
  -> risk.Evaluate
  -> risk.ApplyEnterpriseControls
  -> cache save
  -> output.Write
```

### Install Interception

```text
pkgsafe npm|pip|python|run
  -> internal/cli shim command
  -> internal/intercept parser
  -> scanner validation
  -> enforcement decision using policy mode
  -> optional command execution
  -> audit/cache output
```

### MCP Tool Call

```text
pkgsafe mcp serve
  -> internal/mcp.Serve
  -> JSON-RPC initialize/tools/list/tools/call
  -> tool handler
  -> scanner/report/audit/policy logic
  -> MCP CallToolResult
```

### REST API

```text
pkgsafe serve-api
  -> internal/api.Serve
  -> HTTP validation endpoint
  -> npm or PyPI scanner
  -> JSON ScanResult response
```

### CI Scan

```text
pkgsafe ci scan
  -> internal/ci scan options
  -> lockfile/dependency diff where configured
  -> scanner validation
  -> summary and exit-code mapping
```

### Governance Report

```text
pkgsafe report ...
  -> internal/report generator
  -> audit/cache/git/policy/registry inputs
  -> selected exporter
  -> file output
```

## Data Contracts

The central output contract is `types.ScanResult`:

```text
ScanResult
  Package: ecosystem/name/version
  Mode: audit|warn|block
  Score: risk score
  Decision: allow|warn|block|unknown
  Thresholds: allow/warn/block cutoffs
  Reasons: rule_id, severity, message, evidence, score
  Vulnerabilities: advisory metadata and fixed versions
  Lifecycle/Suspicious/SafeAlternates
  Enforcement and Recommended action
  Sandbox and Artifact summaries
  Policy, Registry, Trust, Exception evidence
```

Most user-facing surfaces eventually emit or embed this contract:

- CLI human/JSON output
- MCP tool results
- REST API responses
- CI summaries
- Reports/evidence packs
- Local cache/audit-derived history

## Repo State Notes

- Go module path: `github.com/niyam-ai/pkgsafe`
- Go version in `go.mod`: `1.25.0`
- Current architecture doc is minimal and older than the current package surface; this file is the more detailed current-state map.
- `graphify extract . --no-cluster --out .` was attempted but requires an LLM API key because the repo contains documentation files. Without `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or another supported provider key, Graphify refuses full semantic extraction for this mixed code/docs corpus.

## Refresh Commands

Use these commands to refresh the source facts behind this file:

```bash
rg --files -g '!*node_modules*' -g '!*.lock' -g '!dist' -g '!build'
find internal cmd editors scripts docs -maxdepth 2 -type d | sort
env GOCACHE=/private/tmp/pkgsafe-gocache go list ./...
env GOCACHE=/private/tmp/pkgsafe-gocache go list -f '{{.ImportPath}} {{join .Imports " "}}' ./...
```

If an LLM API key is available, generate actual Graphify artifacts with:

```bash
graphify extract . --no-cluster --out .
graphify tree --graph graphify-out/graph.json --output graphify-out/GRAPH_TREE.html --root . --label pkgsafe
```
