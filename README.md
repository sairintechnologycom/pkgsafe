# PkgSafe

PkgSafe is a local-first package safety CLI for developer and AI-agent workflows. It validates open-source packages before installation using registry metadata, lifecycle-script analysis, suspicious-pattern detection, typosquat heuristics, policy scoring, and MCP-compatible JSON-RPC tools.

> MVP focus: npm packages and `package-lock.json` scanning.
> Private beta focus: npm is strongest; PyPI, Go, and Cargo are early ecosystem coverage and are not npm-equivalent yet.

## Install

PkgSafe is a single static binary (CGo-free). Pick one:

**Pre-built release** (recommended once a release is tagged):

```bash
# Download the archive for your OS/arch from the Releases page, then:
tar -xzf pkgsafe_<version>_<os>_<arch>.tar.gz
sudo mv pkgsafe /usr/local/bin/
pkgsafe version
```

Release archives ship a `checksums.txt` (SHA-256) plus a cosign signature and
per-archive SBOMs. Verify before trusting a binary:

```bash
sha256sum -c checksums.txt
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

**From source** (Go 1.25+):

```bash
go install github.com/niyam-ai/pkgsafe/cmd/pkgsafe@latest
# or, from a clone, with version metadata baked in:
make build && ./dist/pkgsafe version
```

> Platform note: the firewall/CLI runs on Linux, macOS, and Windows. The
> lifecycle behavior-analysis runner is Unix-only (Linux/macOS).

## Commands

```bash
pkgsafe scan-local-npm ./testdata/npm/safe-package
pkgsafe scan-npm-package axios
pkgsafe scan-npm-package lodash --json
pkgsafe scan-npm-package some-package --version 1.2.3
pkgsafe scan-npm-package axios --policy ./default-policy.yaml
pkgsafe scan-npm-package axios --mode audit
pkgsafe scan-npm-package axios --mode warn
pkgsafe scan-npm-package axios --mode block
pkgsafe scan-lockfile ./package-lock.json
pkgsafe explain axios
pkgsafe npm-install axios --mode warn
pkgsafe mcp serve
```

`scan-npm-package` fetches metadata from the npm registry, resolves `latest` when no version is provided, downloads the selected tarball into the local cache, verifies npm integrity/shasum metadata when present, safely extracts `package/package.json`, and reuses the npm static analyzer.

## Decisions

PkgSafe returns one of:

- `allow`: low risk
- `warn`: suspicious signals, developer confirmation recommended
- `block`: critical behavior such as credential path access, known malware, or strong exfiltration indicators

## Policy and modes

PkgSafe uses the embedded default policy when `--policy` is omitted. A YAML policy can tune thresholds, trusted and blocked npm packages, protected credential paths, and per-rule scores:

```bash
pkgsafe scan-npm-package axios --policy ./default-policy.yaml
pkgsafe scan-local-npm ./testdata/npm/postinstall-curl --policy ./default-policy.yaml --mode audit
```

Modes control enforcement language without hiding the underlying risk decision:

- `audit`: report the decision, but never enforce a block
- `warn`: default mode; warn for suspicious packages and block critical findings
- `block`: strict mode; packages at or above the block threshold should not be installed

Example human output:

```text
Decision: WARN
Mode: WARN
Enforcement: User review recommended
Package: npm/example-package@1.2.3
Risk Score: 62/100

Reasons:
- [medium +20] lifecycle_script_present: Package defines a postinstall script
- [high +30] network_command_in_lifecycle: Lifecycle script uses curl

Recommended Action:
Review package before installing.
```

## Build

```bash
make test
make build
make package
```

Artifacts are written to `dist/`.

## MCP tool

Start the MCP-compatible stdio server:

```bash
pkgsafe mcp serve
```

Example JSON-RPC request:

```json
{"jsonrpc":"2.0","id":1,"method":"validate_package_install","params":{"ecosystem":"npm","name":"axios"}}
```

CLI JSON output uses the stable scan contract:

```json
{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
  "mode": "warn",
  "decision": "warn",
  "risk_score": 62,
  "thresholds": {
    "allow_max_score": 29,
    "warn_max_score": 69,
    "block_min_score": 70
  },
  "reasons": [
    {
      "rule_id": "lifecycle_script_present",
      "severity": "medium",
      "score": 20,
      "message": "Package defines a postinstall script"
    }
  ],
  "recommended_action": "Review package before installing."
}
```

## Capability matrix

PkgSafe is alpha (`v0.1.0`). Maturity varies by ecosystem and surface:

| Ecosystem | Metadata + OSV | Lockfile parsing | Artifact/content analysis |
|-----------|:--:|:--:|:--:|
| **npm** | ✅ | ✅ `package-lock.json` | ✅ tarball + lifecycle heuristics |
| **PyPI** | ✅ | ⚠️ `requirements.txt` only (poetry/uv/Pipfile/conda are stubs) | ⚠️ no behavior analysis |
| **Go** | ✅ | ✅ `go.mod`/`go.sum` | ❌ metadata-only |
| **Cargo** | ✅ | ✅ `Cargo.lock` | ❌ metadata-only |

Surfaces: CLI, REST API, MCP stdio server, GitHub Action, policy engine,
ed25519-signed policy packs, evidence packs.

## Operational notes

**Local-first, but advisory data needs the network.** OSV advisory data is
fetched online and cached in a local SQLite DB. `pkgsafe update-db --ecosystem all`
performs a real bulk OSV sync so you can scan offline afterward; until a package
has been synced/cached, an `--offline` scan of it will fail or warn rather than
silently pass. OSV lookups **fail closed** — a network/rate-limit error surfaces
`vulnerability_data_unavailable` rather than scoring the package clean.

**Behavior analysis is disabled by default and must be requested explicitly.**
Use `--behavior heuristic` only in disposable environments: it runs lifecycle
scripts on the host **without OS isolation**; detection is pattern/canary based
and `network_mode` is not enforced. `--behavior isolated` is reserved for a real
isolation backend and reports unavailable until that backend exists. Do not call
heuristic mode a secure sandbox.

**Real repo validation gates GA.** Use
`pkgsafe test benchmark --repo-list benchmarks/real-repos.json --json` and
`pkgsafe report beta-evidence --repo-list benchmarks/real-repos.json` to build
private-beta evidence. Production readiness reports GA blockers explicitly when
real repository validation is below threshold.

**The REST API is loopback-only and unauthenticated by default.** It binds to
localhost and is intended for local tooling. There is currently no TLS, request
rate limiting, or body-size cap — **do not expose it on a non-loopback interface**
until the service-hardening milestone lands. Set a bearer token (`--token`) for
defense in depth even on localhost.

**Dependencies.** Pure-Go, CGo-free build. Uses a small set of vetted external
modules (e.g. `modernc.org/sqlite`, `gopkg.in/yaml.v3`); see `go.mod`.
