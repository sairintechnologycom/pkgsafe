# PkgSafe documentation

PkgSafe checks open-source packages **before** they install. It returns a clear
**allow**, **warn**, or **block** decision from your terminal, CI, or AI coding
agent.

**Public beta scope today:** npm and PyPI.
**Preview:** Go modules and Cargo (metadata + OSV; not full artifact depth).

---

## Start here

| Doc | When to use it |
|-----|----------------|
| [Getting started](getting-started.md) | First install, first scan, first policy |
| [Install](install.md) | Binary install, Homebrew-style paths, Windows |
| [Release verification](release-verification.md) | Checksums, cosign, attestations, SBOM |
| [GA / production checklist](ga-checklist.md) | Path to PRODUCTION_GA_READY |
| [Commands](commands.md) | Full command list and common flags |
| [Troubleshooting](troubleshooting.md) | Doctor failures, offline mode, false blocks |

## Day-to-day use

| Doc | Topic |
|-----|--------|
| [Policy guide](policy-guide.md) | Modes, scores, trusted/blocked lists, exceptions |
| [Known limitations](known-limitations.md) | What GA does **not** claim |
| [Behavior analysis](behavior-analysis.md) | Optional script execution (`heuristic` / `isolated`) |
| [Offline intelligence bundles](offline-intelligence-bundle.md) | Air-gapped advisory data |
| [Private registry](private-registry.md) | Private npm/PyPI routing |

## CI and automation

| Doc | Topic |
|-----|--------|
| [GitHub Action](github-action.md) | PR gates, SARIF, summary comments |
| [CI/CD](ci-cd.md) | `pkgsafe ci scan` on any runner |
| [Install interception](install-interception.md) | Safe wrappers around `npm` / `pnpm` / `yarn` / `pip` / `uv` |

## AI agents (MCP)

| Doc | Topic |
|-----|--------|
| [Claude Code](integrations/claude-code.md) | MCP setup for Claude Code |
| [Codex](integrations/codex.md) | OpenAI Codex |
| [Gemini CLI](integrations/gemini-cli.md) | Gemini CLI |
| [GitHub Copilot agent](integrations/github-copilot-agent.md) | Copilot agent |
| [Slash commands](integrations/slash-commands.md) | Agent skill packs |
| [Generic MCP client](mcp-generic-client.md) | Any MCP host |
| [Cursor (legacy path)](mcp-cursor.md) | Cursor-specific notes |

Also see root README section **Guard your AI agent (MCP)**.

## Feedback and help

| Doc | Topic |
|-----|--------|
| [Feedback](feedback.md) | How to report false positives/negatives safely |
| [GitHub Discussions](https://github.com/sairintechnologycom/pkgsafe/discussions) | Questions and community |

Never paste secrets, tokens, private source, or registry credentials into
public issues.

## Internal / product (not end-user guides)

These support maintainers and product planning. Prefer the tables above if you
are installing or running PkgSafe.

| Doc | Topic |
|-----|--------|
| [Architecture (current)](architecture.md) | How the binary is structured |
| [Open-core boundary](architecture/open-core-boundary.md) | OSS vs enterprise |
| [Threat model](threat-model.md) | High-level threats |
| [PRD](prd.md) | Product requirements (historical + planning) |
| [Roadmap](roadmap.md) | Direction |
| [App structure](app-structure.md) | Repo layout |
| [Launch kit](launch-kit.md) | Go-to-market checklist |
| [Private beta guide](private-beta-guide.md) | Beta process notes |

---

## One-line map

```text
Install binary  →  pkgsafe doctor
Scan package    →  pkgsafe scan-npm-package <name>
                  pkgsafe scan-pypi-package <name>
Scan project    →  pkgsafe scan-lockfile ./package-lock.json
                  pkgsafe scan-python-deps ./requirements.txt
CI gate         →  GitHub Action or pkgsafe ci scan
AI agent        →  pkgsafe mcp serve
Tune rules      →  --policy ./policy.yaml  (see policy-guide.md)
```
