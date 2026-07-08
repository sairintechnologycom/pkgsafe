# PkgSafe

**A supply-chain firewall for AI coding agents — and the developers who run them.**

Coding agents now run `npm install` and `pip install` on their own, and a
mistyped or hallucinated package name can pull in malware before anyone looks.
PkgSafe checks a package **before** it is installed and gives you a clear
**allow / warn / block** — from your terminal, your CI, or straight from your AI
agent over MCP.

![PkgSafe warns on a typosquat and blocks a package that reads your AWS credentials](demo/pkgsafe-demo.gif)

PkgSafe inspects each package for:

- **Malicious install hooks** — `postinstall` scripts that pipe `curl … | sh` or read `~/.aws/credentials` and `~/.ssh`.
- **Typosquats & "slopsquats"** — names that impersonate popular packages (`axois` → `axios`).
- **Known vulnerabilities** — OSV advisories, and it fails safe: an unknown package is never scored as clean.
- **Suspicious artifacts** — the actual npm tarball and PyPI wheel/sdist contents, not just the metadata.

It runs locally as a single static binary. Nothing about your code leaves your
machine.

## Install

```bash
curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash
```

That's it — one binary, no runtime dependencies. Confirm it's working:

```bash
pkgsafe doctor
```

Works on **macOS and Linux** (Intel & Apple Silicon) and **Windows**.

<details>
<summary>Other ways to install &amp; verifying the download</summary>

**Homebrew / manual** — download a release archive for your platform:

```bash
VERSION=1.6.0
OS=darwin           # linux | darwin | windows
ARCH=arm64          # amd64 | arm64
curl -LO "https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}/pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv pkgsafe /usr/local/bin/
```

**From source** (Go 1.25+):

```bash
go install github.com/sairintechnologycom/pkgsafe/cmd/pkgsafe@latest
```

**Verify signatures.** Every release ships `checksums.txt` with a cosign
signature, GitHub attestations, and per-archive SBOMs. To verify before
trusting a binary:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify "pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz" --repo sairintechnologycom/pkgsafe
```

Full details: [docs/install.md](docs/install.md) ·
[docs/release-verification.md](docs/release-verification.md).

The install script honors `PKGSAFE_VERSION` (pin a version) and
`PKGSAFE_BIN_DIR` (install location, e.g. `$HOME/.local/bin`).

</details>

## Use it

### 1. Scan packages & dependencies

**Check a package before you install it:**

```bash
pkgsafe scan-npm-package axios
pkgsafe scan-pypi-package requests
```

When something's wrong, PkgSafe tells you exactly why:

```text
$ pkgsafe scan-npm-package sketchy-pkg
Decision: BLOCK
Package: npm/sketchy-pkg@1.0.0
Risk Score: 100/100
Reasons:
- [medium +20]   lifecycle_script_present: Package defines a postinstall script
- [critical +100] credential_path_reference: Lifecycle script references ~/.aws/credentials
Recommended Action: Do not install this package.
```

**Check your whole project's dependencies:**

```bash
pkgsafe scan-lockfile ./package-lock.json       # npm
pkgsafe scan-python-deps ./requirements.txt     # PyPI (also pyproject.toml, poetry.lock, uv.lock, Pipfile)
pkgsafe scan-go-deps ./go.mod                   # Go (preview)
pkgsafe scan-cargo-deps ./Cargo.lock             # Cargo (preview)
```

**Install with a built-in safety check** (scans first, installs only if allowed):

```bash
pkgsafe npm-install axios
pkgsafe pip install requests
```

**Understand a decision** in plain language:

```bash
pkgsafe explain axios            # npm
pkgsafe explain-pypi requests    # PyPI
```

### 2. Visualize & verify lockfiles

**Visualize dependency trees with risk highlighting:**
Inspect your npm dependencies and easily filter out safe nodes to focus on the packages that PkgSafe flags:

```bash
pkgsafe tree package-lock.json --only-risky
```

**Verify lockfile integrity:**
Audit your lockfile's package integrity and cryptographic hashes against registry and vulnerability records to detect tampering or lockfile-poisoning attacks:

```bash
pkgsafe verify package-lock.json
```

### 3. Manage local safety policy

PkgSafe enforces a configurable security policy. By default, it uses a sensible default policy, but you can fully customize rule severities, risk score weights, custom trusted/blocked package lists, and protected paths:

*   **Edit policy interactively**:
    ```bash
    pkgsafe policy edit
    ```
*   **Validate policy syntax**:
    ```bash
    pkgsafe policy validate ./policy.yaml
    ```
*   **Explain how a policy scores risk**:
    ```bash
    pkgsafe policy explain ./policy.yaml
    ```

### 4. Diagnostics & history

*   **Audit installation history**:
    Review previous safety scans and decisions recorded in the local audit log:
    ```bash
    pkgsafe history
    ```
*   **Check system health & environment**:
    Confirm database status, registry connectivity, OIDC verification setup, and local package managers:
    ```bash
    pkgsafe doctor
    ```

<details>
<summary>Modes, policy flag, and JSON output</summary>

**Modes** decide how strict enforcement is (add `--mode` to any scan):

- `audit` — report the decision, never block.
- `warn` — *(default)* warn on suspicious packages, block critical ones.
- `block` — block anything at or above the block threshold.

**Policy** — pass `--policy ./policy.yaml` to tune thresholds, trusted/blocked
packages, protected credential paths, and per-rule scores. Without it, a sensible
default policy is used.

**JSON** — add `--json` for a stable machine-readable contract (same shape the
MCP tools return):

```json
{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
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

</details>


## Guard your AI agent (MCP)

PkgSafe ships an MCP server so an agent — Claude Code, Cursor, or any MCP client
— must consult it before installing anything. Add it to your client config:

```json
{
  "mcpServers": {
    "pkgsafe": { "command": "pkgsafe", "args": ["mcp", "serve"] }
  }
}
```

Now the agent calls `validate_package_install` before it installs — **`BLOCK`
means never install, `WARN` means ask a human first** — and can look up a real
package when it invents a name that doesn't exist.

| Tool | What it does |
|------|--------------|
| `validate_package_install` | Allow / warn / block a single package |
| `validate_install_command` | Validate every package in a full `npm install …` / `pip install …` command |
| `suggest_safe_alternative` | Suggest real packages for risky, unknown, or **hallucinated** names |
| `explain_package_risk` | Explain why a package is safe, suspicious, or blocked |
| `score_lockfile` | Score a lockfile's direct and transitive dependencies |

<details>
<summary>Talking to the server directly</summary>

PkgSafe speaks standard MCP: `initialize`, then `tools/list` to discover tools,
then `tools/call` to run one (tools are called via `tools/call`, not as
top-level methods):

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"validate_package_install","arguments":{"ecosystem":"npm","name":"axios","requested_by":"ai_agent"}}}
```

Governance tools (`generate_governance_report`, `get_recent_package_decisions`,
`get_policy_evidence`) are also available. Run `tools/list` for the full schema.

</details>

## Gate your CI (GitHub Action)

Stop risky dependency changes before they merge. The action scans changed
dependencies on a pull request, posts a summary comment, uploads results to
Code Scanning, and fails the job on your terms:

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
```

Configure the lockfile/manifest, ecosystem, policy, and thresholds via inputs —
see [docs/github-action.md](docs/github-action.md).

## Supported ecosystems

| Ecosystem | Support | What's checked |
|-----------|---------|----------------|
| **npm** | Full | metadata, OSV, `package-lock.json`, tarball + install-hook analysis |
| **PyPI** | Full | metadata, OSV, `requirements.txt` / `pyproject.toml` / `poetry.lock` / `uv.lock` / `Pipfile`, wheel & sdist analysis |
| **Go** | Preview | metadata + OSV, `go.mod` / `go.sum` (no content analysis) |
| **Cargo** | Preview | metadata + OSV, `Cargo.lock` (no content analysis) |

## Good to know

- **It works offline.** Run `pkgsafe update-db --ecosystem all` once to sync OSV
  advisory data into a local database, then scan with `--offline` anytime. For
  air-gapped machines, PkgSafe can export and import signed advisory bundles —
  see [docs/offline-intelligence-bundle.md](docs/offline-intelligence-bundle.md).

- **Running install scripts to observe them is opt-in — and not a sandbox.**
  `--behavior heuristic` executes a package's lifecycle scripts on your machine
  **without OS isolation**; only use it in a throwaway environment. On Linux,
  `--behavior isolated` runs them inside bubblewrap namespaces with networking
  off. Plain scanning (the default) never executes package code.
  See [docs/behavior-analysis.md](docs/behavior-analysis.md).

- **The local REST API is for you, not the network.** It binds to localhost and
  is unauthenticated with no TLS — don't expose it on a public interface.

## Docs & help

Questions, false positives, or a package PkgSafe got wrong? Open a
[Discussion](https://github.com/sairintechnologycom/pkgsafe/discussions) or see
[docs/feedback.md](docs/feedback.md). When reporting, include the output and rule
IDs — but **never paste secrets, tokens, credentials, or private source**.

Contributions welcome:

```bash
make test
make build      # -> dist/pkgsafe
```
