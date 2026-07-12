# PkgSafe architecture

PkgSafe is a single Go binary that validates packages **before install**. It
does not send your source code to a hosted service. Registry metadata, OSV
advisories, and optional package artifacts are fetched only as needed (or from
a local DB / offline bundle).

## High-level flow

```text
Developer or AI agent
        │
        ▼
  CLI / MCP / GitHub Action / loopback API
        │
        ▼
  Resolve package(s) + policy
        │
        ▼
  Analyzer (metadata, scripts, tarball/wheel heuristics, typosquat)
        │
        ▼
  Intelligence (OSV / local DB) + risk scoring
        │
        ▼
  Decision: ALLOW | WARN | BLOCK
        │
        ├── print / JSON / SARIF / evidence pack
        └── optional: run real npm/pip only if allowed
```

Default path is **static**. Package code runs only if you opt into
`--behavior heuristic` or `--behavior isolated`.

## Main packages (repo)

| Area | Role |
|------|------|
| `cmd/pkgsafe` | Thin main; calls `pkg/cli` |
| `pkg/cli` | Command dispatch and user-facing CLI |
| `internal/scanner/*` | Ecosystem scanners (npm, pypi, golang, cargo) |
| `internal/analyzer/*` | Static content / lifecycle analysis |
| `internal/deps/*` | Lockfile and manifest inventory |
| `internal/risk` + `internal/policy` | Scoring and policy evaluation |
| `internal/intel` / OSV | Vulnerability intelligence |
| `internal/intercept` | npm/pip pass-through wrappers |
| `internal/mcp` | MCP server for AI agents |
| `internal/api` | Localhost REST API |
| `internal/ci` | CI scan, SARIF, summaries |
| `internal/report` | JSON, Markdown, HTML, CSV, evidence packs |
| `internal/db` + `dbbundle` | Local sqlite + offline bundles |
| `internal/sandbox` | Optional behavior backends |
| `pkg/capability` | Neutral downstream capability interface; OSS local provider grants none |

## Surfaces

| Surface | Entry |
|---------|--------|
| CLI | `pkgsafe …` |
| MCP | `pkgsafe mcp serve` |
| GitHub Action | `sairintechnologycom/pkgsafe@v…` |
| CI command | `pkgsafe ci scan` |
| Local API | `pkgsafe serve-api` (loopback) |

## Ecosystems

| Ecosystem | Status |
|-----------|--------|
| npm | Public beta — metadata, lockfiles, tarball/lifecycle analysis, OSV |
| PyPI | Public beta — metadata, common lockfiles, wheel/sdist static analysis, OSV |
| Go | Preview — metadata + OSV + go.mod/sum |
| Cargo | Preview — metadata + OSV + Cargo.lock |

## Safety principles

1. **Fail closed** when advisory data is required but missing (especially offline).
2. **Unknown / unscannable** is not treated as clean.
3. **Heuristic behavior** is host execution — never marketed as isolation.
4. **Isolated behavior** is Linux + bubblewrap only; no silent fallback to host.
5. **Open core** — enterprise features live behind interfaces / private repo.
   See [architecture/open-core-boundary.md](architecture/open-core-boundary.md).

## Related

- [Getting started](getting-started.md)
- [Policy guide](policy-guide.md)
- [Behavior analysis](behavior-analysis.md)
- [Threat model](threat-model.md)
- [Known limitations](known-limitations.md)
