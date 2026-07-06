# PkgSafe

**A supply-chain firewall for AI coding agents — and the developers who run them.**

Coding agents now run `npm install` and `pip install` on their own, and
"slopsquatting" (an LLM hallucinating a package name an attacker has already
registered) is a real attack. PkgSafe checks a package *before* it is installed
— against OSV advisories, lifecycle-script analysis, typosquat heuristics, and
your policy — and returns a clear **allow / warn / block** decision. It runs
locally and speaks **MCP**, so your agent has to ask PkgSafe first.

![PkgSafe warns on a typosquat and blocks a package that reads your AWS credentials](demo/pkgsafe-demo.gif)

> GA scope: npm and PyPI supply-chain guardrails for package scanning,
> lockfile/CI gating, policy controls, OSV intelligence, and evidence reports.
> Go and Cargo are preview coverage and are not GA-equivalent yet.

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [Usage](#usage) — scan packages, lockfiles, and install commands
- [Guard your AI agent (MCP)](#guard-your-ai-agent-mcp)
- [Gate your CI (GitHub Action)](#gate-your-ci-github-action)
- [Decisions and scoring](#decisions-and-scoring)
- [Policy and modes](#policy-and-modes)
- [Capability matrix](#capability-matrix)
- [Operational and security notes](#operational-and-security-notes)
- [Build and contribute](#build-and-contribute)

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

Then wire it into your AI agent so it asks first — see
[Guard your AI agent](#guard-your-ai-agent-mcp).

## Install

PkgSafe is a single static binary (CGo-free). npm and PyPI package and
lockfile scanning are the GA production scope; Go and Cargo remain preview
coverage and are not GA-equivalent yet.

**Quickest** — the install script (verifies the SHA-256 checksum for you):

```bash
curl -fsSL https://raw.githubusercontent.com/sairintechnologycom/pkgsafe/main/scripts/install-remote.sh | bash
# pin a version or install dir:
PKGSAFE_VERSION=1.6.0 PKGSAFE_BIN_DIR="$HOME/.local/bin" \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/sairintechnologycom/pkgsafe/main/scripts/install-remote.sh | bash'
```

**Manual** — download a published release archive:

```bash
VERSION=1.6.0
OS=linux            # linux | darwin | windows
ARCH=amd64          # amd64 | arm64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/
pkgsafe version
pkgsafe doctor
```

See [docs/install.md](docs/install.md) for macOS arm64/amd64, Linux amd64, and
Windows zip examples.

**Verify the supply chain.** Release archives ship `checksums.txt`, a cosign
signature, GitHub Artifact Attestations, and per-archive SBOMs:

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

Full release checks: [docs/release-verification.md](docs/release-verification.md).

**From source** (Go 1.25+):

```bash
go install github.com/sairintechnologycom/pkgsafe/cmd/pkgsafe@latest
# or, from a clone, with version metadata baked in:
make build && ./dist/pkgsafe version
```

> Platform note: the firewall/CLI runs on Linux, macOS, and Windows. The
> lifecycle behavior-analysis runner is Unix-only (Linux/macOS).

## Usage

Run `pkgsafe doctor` first to check your environment, and `pkgsafe --help` for
the full command list.

**Scan a package** (fetches registry metadata, downloads and statically
analyzes the artifact, checks OSV):

```bash
pkgsafe scan-npm-package axios                 # latest
pkgsafe scan-npm-package lodash --version 4.17.21
pkgsafe scan-pypi-package requests
pkgsafe scan-npm-package axios --mode block    # audit | warn | block
pkgsafe scan-npm-package axios --json          # machine-readable (see below)
```

**Scan a local package directory** (no download — analyzes what's on disk):

```bash
pkgsafe scan-local-npm ./path/to/package
```

**Scan a lockfile / dependency manifest** (direct and transitive deps):

```bash
pkgsafe scan-lockfile ./package-lock.json       # npm
pkgsafe scan-python-deps ./requirements.txt     # PyPI (also pyproject.toml, poetry.lock, uv.lock, Pipfile)
pkgsafe scan-go-deps ./go.sum                    # Go (preview, metadata-only)
```

**Explain a decision** in plain language:

```bash
pkgsafe explain axios            # npm
pkgsafe explain-pypi requests    # PyPI
```

**Guarded install** — scan, then install only if the decision allows it:

```bash
pkgsafe npm-install axios --mode warn
```

**Machine-readable output.** `--json` (and the MCP tools) emit a stable scan
contract:

```json
{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
  "mode": "warn",
  "decision": "warn",
  "risk_score": 62,
  "thresholds": { "allow_max_score": 29, "warn_max_score": 69, "block_min_score": 70 },
  "reasons": [
    { "rule_id": "lifecycle_script_present", "severity": "medium", "score": 20,
      "message": "Package defines a postinstall script" }
  ],
  "recommended_action": "Review package before installing."
}
```

## Guard your AI agent (MCP)

PkgSafe ships an MCP stdio server so an agent (Claude Code, Cursor, or any
MCP client) must consult it before installing anything. Add it to your client:

```json
{
  "mcpServers": {
    "pkgsafe": { "command": "pkgsafe", "args": ["mcp", "serve"] }
  }
}
```

The agent then calls `validate_package_install` before installing —
**`BLOCK` means never install, `WARN` means ask a human first.**

PkgSafe speaks standard MCP: `initialize`, then `tools/list` to discover tools,
then `tools/call` to invoke one. Package-safety tools are exposed via
`tools/call` (not as top-level JSON-RPC methods):

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_package_install","arguments":{"ecosystem":"npm","name":"axios","requested_by":"ai_agent"}}}
```

Available tools:

| Tool | Purpose |
|------|---------|
| `validate_package_install` | Allow/warn/block a single package (`requested_by: ai_agent` for agent context) |
| `validate_install_command` | Extract and validate every package in a full `npm install …` / `pip install …` string |
| `suggest_safe_alternative` | Suggest real packages for risky, unknown, or **hallucinated** names |
| `explain_package_risk` | Explain why a package is safe, suspicious, or blocked |
| `score_lockfile` | Score a lockfile's direct and transitive dependencies |
| `generate_governance_report`, `get_recent_package_decisions`, `get_policy_evidence` | Governance / audit evidence |

Run `tools/list` for the full, self-describing schema.

## Gate your CI (GitHub Action)

Block risky dependency changes before they merge. The action scans changed
dependencies on a pull request, comments a summary, uploads SARIF to Code
Scanning, and fails the job per your threshold:

```yaml
name: Dependency gate
on: pull_request
jobs:
  pkgsafe:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write     # PR summary comment
      security-events: write   # SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: sairintechnologycom/pkgsafe@v1.6.0
        with:
          mode: warn
          fail-on: block         # fail on any BLOCK (none | warn | block)
          changed-only: true     # only newly added/changed deps
          # lockfile: package-lock.json
          # dependency-file: requirements.txt
          # policy: .pkgsafe/policy.yaml
```

Key inputs: `lockfile`, `dependency-file`, `ecosystem` (autodetect if empty),
`policy`, `mode`, `fail-on`, `changed-only`, `baseline`, `comment-pr`,
`upload-sarif`, `generate-evidence-pack`. Outputs include `decision`,
`risk-score`, `block-count`, and paths to the JSON/SARIF/Markdown reports and
evidence pack. Full reference: [docs/github-action.md](docs/github-action.md).

## Decisions and scoring

PkgSafe scores each package 0–100 and maps it to one decision:

- **`allow`** — low risk; install may proceed.
- **`warn`** — suspicious signals (e.g. a typosquat candidate, an unexplained
  lifecycle script); developer confirmation recommended.
- **`block`** — critical behavior such as credential-path access, known malware,
  or strong exfiltration indicators; install should not proceed.

Every decision is itemized by rule (`rule_id`, severity, score contribution, and
a human message) so it is auditable, not a black box.

## Policy and modes

PkgSafe uses an embedded default policy when `--policy` is omitted. A YAML
policy tunes thresholds, trusted/blocked packages, protected credential paths,
and per-rule scores:

```bash
pkgsafe scan-npm-package axios --policy ./default-policy.yaml
pkgsafe scan-local-npm ./testdata/npm/postinstall-curl --policy ./default-policy.yaml --mode audit
```

Modes control enforcement language without hiding the underlying risk decision:

- **`audit`** — report the decision, but never enforce a block.
- **`warn`** — default; warn for suspicious packages, block critical findings.
- **`block`** — strict; packages at or above the block threshold should not install.

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

## Operational and security notes

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

## Build and contribute

```bash
make test
make build      # -> dist/pkgsafe
make package    # release archives -> dist/
```

Questions, false positives, false blocks, scanner crashes, private-registry or
OSV issues, and GitHub Action adoption problems are all welcome — see
[docs/feedback.md](docs/feedback.md) and
[GitHub Discussions](https://github.com/sairintechnologycom/pkgsafe/discussions).
When reporting, include sanitized output and rule IDs; **never paste secrets,
tokens, private-registry credentials, or proprietary source**.
