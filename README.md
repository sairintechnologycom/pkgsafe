# PkgSafe

**A supply-chain firewall for AI coding agents — and the developers who run them.**

Coding agents now run `npm install` and `pip install` on their own, and
"slopsquatting" (an LLM hallucinating a package name an attacker has already
registered) is a real attack. PkgSafe checks a package *before* it is installed
— against OSV advisories, lifecycle-script analysis, typosquat heuristics, and
your policy — and returns a clear **allow / warn / block** decision. It runs
locally and speaks **MCP**, so your agent has to ask PkgSafe first.

> GA scope: npm and PyPI supply-chain guardrails for package scanning,
> lockfile/CI gating, policy controls, OSV intelligence, and evidence reports.
> Go and Cargo are preview coverage and are not GA-equivalent yet.

## Quick start

Install — single static binary, CGo-free, no runtime dependencies:

```bash
curl -fsSL https://raw.githubusercontent.com/sairintechnologycom/pkgsafe/main/scripts/install-remote.sh | bash
```

The installer downloads the signed release for your OS/arch and verifies its
SHA-256 checksum. Prefer to install by hand or with full signature
verification? See [Install](#install) below.

Scan a package before you install it:

```bash
pkgsafe scan-npm-package axios
```

Catch a package that runs a suspicious install hook:

```text
$ pkgsafe scan-local-npm ./testdata/npm/postinstall-curl --mode block
Decision: BLOCK
Package: npm/postinstall-curl-example@1.0.0
Risk Score: 65/100
Reasons:
- [medium +20] lifecycle_script_present: Package defines a postinstall script
- [high +30]   network_command_in_lifecycle: Lifecycle script uses curl
Recommended Action: Do not install this package.
```

Guard an AI agent — add PkgSafe as an MCP server in Claude Code or Cursor:

```json
{
  "mcpServers": {
    "pkgsafe": { "command": "pkgsafe", "args": ["mcp", "serve"] }
  }
}
```

The agent must now call `validate_package_install` before installing anything:
`BLOCK` means never install, `WARN` means ask a human first.

## Install

PkgSafe is a single static binary (CGo-free). npm and PyPI package and
lockfile scanning are the GA production scope; Go and Cargo remain preview
coverage and are not GA-equivalent yet.

Install a published release:

```bash
VERSION=1.6.0
OS=linux
ARCH=amd64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/
pkgsafe version
pkgsafe doctor
```

See [docs/install.md](docs/install.md) for macOS arm64, macOS amd64, Linux
amd64, and Windows zip examples.

Release archives ship `checksums.txt`, a cosign signature, GitHub Artifact
Attestations, and per-archive SBOMs. Verify before trusting a binary:

```bash
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/checksums.txt"
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/checksums.txt.sig"
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/checksums.txt.pem"
sha256sum -c checksums.txt
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz" --repo sairintechnologycom/pkgsafe
```

Full release checks are documented in
[docs/release-verification.md](docs/release-verification.md).

**From source** (Go 1.25+):

```bash
go install github.com/sairintechnologycom/pkgsafe/cmd/pkgsafe@latest
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

## Feedback

For false positives, false blocks, scanner crashes, private registry issues,
OSV/update-db issues, and GitHub Action adoption problems, see
[docs/feedback.md](docs/feedback.md). Reports should include sanitized output
and rule IDs when available; do not paste secrets, tokens, private registry
credentials, or proprietary source code.

## MCP tool

Start the MCP-compatible stdio server:

```bash
pkgsafe mcp serve
```

PkgSafe speaks standard MCP: `initialize`, then `tools/list` to discover
tools, then `tools/call` to invoke one. The package-safety tools are exposed
via `tools/call` (not as top-level JSON-RPC methods).

Example: ask PkgSafe whether an AI agent should install a package:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_package_install","arguments":{"ecosystem":"npm","name":"axios","requested_by":"ai_agent"}}}
```

Available MCP tools include `validate_package_install`,
`validate_install_command` (validate a full `npm install …` / `pip install …`
string), `suggest_safe_alternative` (for risky, unknown, or hallucinated
package names), `explain_package_risk`, `score_lockfile`, and governance/audit
reports. Run `tools/list` for the full, self-describing schema.

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

PkgSafe GA covers npm and PyPI. Maturity varies by ecosystem and surface:

| Ecosystem | Metadata + OSV | Lockfile parsing | Artifact/content analysis |
|-----------|:--:|:--:|:--:|
| **npm** | Production-ready GA v1 scope | ✅ `package-lock.json` | ✅ tarball + lifecycle heuristics |
| **PyPI** | GA (pip-parity resolution, large-artifact caps, real-repo validated) | ✅ `requirements.txt` (incl. `--hash`), `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile`, `Pipfile.lock` with inventory dedup (conda is a stub) | ⚠️ wheel + sdist static analysis (RECORD, bytecode, build-backend); no behavior analysis |
| **Go** | Preview | ✅ `go.mod`/`go.sum` | ❌ metadata-only |
| **Cargo** | Preview | ✅ `Cargo.lock` | ❌ metadata-only |

Surfaces: CLI, REST API, MCP stdio server, GitHub Action, policy engine,
offline intelligence bundles, and local evidence packs.

## Operational notes

**Local-first, but advisory data needs the network.** OSV advisory data is
fetched online and cached in a local SQLite DB. `pkgsafe update-db --ecosystem all`
performs a real bulk OSV sync so you can scan offline afterward; until a package
has been synced/cached, an `--offline` scan of it will fail or warn rather than
silently pass. OSV lookups **fail closed** — a network/rate-limit error surfaces
`vulnerability_data_unavailable` rather than scoring the package clean.
For air-gapped environments, export, verify, and import signed advisory bundles
with `pkgsafe db export-bundle`, `pkgsafe db verify-bundle`, and
`pkgsafe db import-bundle`; see
[docs/offline-intelligence-bundle.md](docs/offline-intelligence-bundle.md).

**Behavior analysis is disabled by default and must be requested explicitly.**
Use `--behavior heuristic` only in disposable environments: it runs lifecycle
scripts on the host **without OS isolation**; detection is pattern/canary based
and `network_mode` is not enforced. `--behavior isolated` runs lifecycle
scripts inside Linux user/mount/pid/ipc/uts/network namespaces via bubblewrap
with **network disabled by default (enforced)**; it requires `bwrap` and
unprivileged user namespaces, reports unavailable otherwise, and never falls
back to host execution. Isolation reduces host exposure but shares the host
kernel. Do not call heuristic mode sandboxing or containment. See
[docs/behavior-analysis.md](docs/behavior-analysis.md).

**Real repo validation gates GA.** Use
`pkgsafe test benchmark --repo-list benchmarks/real-repos.json --json` and
`pkgsafe report beta-evidence --repo-list benchmarks/real-repos.json` or
`pkgsafe report ga-evidence --repo-list benchmarks/real-repos.json --output pkgsafe-ga-evidence.zip`
to build evidence. Production readiness reports GA blockers explicitly when
real repository validation, release signing, provenance, SBOM, or checksum
verification is below threshold.

**The REST API is loopback-only and unauthenticated by default.** It binds to
localhost and is intended for local tooling. There is currently no TLS, request
rate limiting, or body-size cap — **do not expose it on a non-loopback interface**
until the service-hardening milestone lands. Set a bearer token (`--token`) for
defense in depth even on localhost.

**Dependencies.** Pure-Go, CGo-free build. Uses a small set of vetted external
modules (e.g. `modernc.org/sqlite`, `gopkg.in/yaml.v3`); see `go.mod`.
