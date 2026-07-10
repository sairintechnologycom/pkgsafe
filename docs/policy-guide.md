# Policy guide

PkgSafe turns scan findings into **allow**, **warn**, or **block** using a
policy file. If you pass no `--policy`, it uses the built-in default
(same shape as `default-policy.yaml` in the repo).

## Quick start

```bash
# Validate a file
pkgsafe policy validate .pkgsafe/policy.yaml

# Explain thresholds and rules in human text
pkgsafe policy explain .pkgsafe/policy.yaml

# Use it on a scan
pkgsafe scan-lockfile ./package-lock.json --policy .pkgsafe/policy.yaml
```

Interactive edit (when available):

```bash
pkgsafe policy edit
```

---

## Core fields

| Field | Meaning |
|-------|---------|
| `schema_version` | Policy schema. Current: `"1.0"`. |
| `mode` | `audit`, `warn`, or `block` (see below). |
| `thresholds` | Score bands for allow / warn / block. |
| `ecosystems` | Enable npm, pypi, etc. |
| `trusted_packages` | Names that get a reputation score reduction. |
| `blocked_packages` | Always-deny lists per ecosystem. |
| `rules` | Per-rule enable, severity, and score. |
| `protected_paths` | Credential paths the scanner treats as sensitive. |
| `sandbox` | Behavior analysis defaults (usually leave disabled). |
| `mcp` | Defaults for AI-agent MCP tools. |
| `install_interception` | How wrappers treat WARN/BLOCK and audit logs. |
| `ci` | Defaults for CI fail-on / changed-only / SARIF (when set). |
| `registries` | Private registry routing (see [private-registry.md](private-registry.md)). |

### Modes

| Mode | Effect |
|------|--------|
| `audit` | Report only. Never blocks installs or CI by itself. |
| `warn` | Default. Suspicious → WARN; critical rules still BLOCK. |
| `block` | Anything at or above `block_min_score` is BLOCK. |

You can also override mode per command with `--mode`.

### Default score bands

From the default policy:

| Band | Score |
|------|-------|
| ALLOW | 0–29 |
| WARN | 30–69 |
| BLOCK | 70+ |

Rules add (or subtract) points. Hard-block rules can force BLOCK even when the
sum is lower.

---

## Trusted and blocked packages

```yaml
trusted_packages:
  npm:
    - lodash
    - axios
  pypi:
    - requests
    - pydantic

blocked_packages:
  npm:
    - evil-package
  pypi: []
```

- **Trusted** applies a negative score (reputation reduction). It does **not**
  override malware or critical credential findings.
- **Blocked** is an explicit deny list.

---

## Rules (what the scores mean)

Each rule has `enabled`, `severity`, and `score`. Important groups:

### Always serious (often force block)

| Rule ID | What it catches |
|---------|-----------------|
| `known_malware_indicator` | Known malware signal |
| `credential_path_reference` | Install script touches credential paths |
| `credential_canary_*` | Behavior mode saw credential access |
| `shell_download_execute` | `curl \| sh` style patterns |
| `cloud_metadata_access` | Cloud metadata endpoints |
| `ssh_key_access` / `npm_token_access` / `env_secret_access` | Secret access patterns |
| Many `pypi_*` credential / base64-exec rules | PyPI artifact equivalents |

Policy hard flags (default true):

- `install_interception.block_known_malware_always`
- `install_interception.block_credential_access_always`

Do not turn these off in production.

### Common risk signals

| Rule ID | Typical severity |
|---------|------------------|
| `lifecycle_script_present` | medium — package has install hooks |
| `network_command_in_lifecycle` | high |
| `typosquat_candidate` | high — name looks like a popular package |
| `ai_package_squatting_candidate` | high — slopsquat / hallucinated-name risk |
| `new_package` | medium — very new publish date |
| `known_vulnerability_critical` / `_high` / … | OSV severity bands |
| `obfuscated_script` | high |
| `missing_repository` / `missing_license` | low |

Full list lives in `default-policy.yaml`. Use
`pkgsafe policy explain` for the file you deploy.

---

## Exceptions (time-boxed overrides)

When a finding is a known false positive you must ship past:

1. Prefer fixing the dependency over weakening global rules.
2. Add an exception with **id**, **package**, **reason**, **approved_by**, and a
   future **allowed_until**.
3. Expired exceptions fail validation.

Never use exceptions to silence known malware or credential theft without a
formal security review.

---

## MCP and install interception

Defaults (simplified):

```yaml
mcp:
  enabled: true
  default_mode: warn
  ai_agent_default_install_allowed_on_warn: false   # agents need human on WARN
  human_default_install_allowed_on_warn: true

install_interception:
  confirm_on_warn: true
  force_risk_accept_requires_reason: true
  non_interactive_warn_blocks_by_default: true
  audit_log_enabled: true
  audit_log_path: "~/.pkgsafe/audit.log"
```

That means: AI agents should not silently install on WARN; CI and scripts fail
closed on WARN unless you change policy deliberately.

---

## Behavior analysis in policy

```yaml
sandbox:
  enabled: false
  behavior_mode: disabled    # disabled | heuristic | isolated
```

- `disabled` — recommended default.
- `heuristic` — runs scripts on the **host** (not a sandbox).
- `isolated` — Linux bubblewrap only.

CLI `--behavior` overrides for a single run. See
[behavior-analysis.md](behavior-analysis.md).

---

## Validate before you ship policy

```bash
pkgsafe policy validate .pkgsafe/policy.yaml
pkgsafe policy test testdata/policy-fixtures   # if you maintain fixtures
```

Fixture convention: files named `invalid-*` must fail validation; other YAML
files must pass.

---

## Practical recipes

**Stricter monorepo CI**

```yaml
mode: block
thresholds:
  allow_max_score: 19
  warn_max_score: 49
  block_min_score: 50
```

**Team allowlist for internal packages**

```yaml
trusted_packages:
  npm:
    - "@mycorp/ui"
    - "@mycorp/sdk"
```

**Deny a bad package immediately**

```yaml
blocked_packages:
  npm:
    - event-stream-malicious-example
```

---

## Related docs

- [Getting started](getting-started.md)
- [Commands](commands.md)
- [Known limitations](known-limitations.md)
- [Troubleshooting](troubleshooting.md)
- [CI/CD](ci-cd.md)
