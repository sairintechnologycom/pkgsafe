# Threat model

PkgSafe is a **local-first** supply-chain guardrail for installs, repo scans, CI
gates, and AI-agent package checks.

## Assets

- Developer machines and CI runners  
- Manifests and lockfiles  
- Private registry credentials  
- Policy files and exceptions  
- Vulnerability cache and scan evidence  

## Main threats

| Threat | Example |
|--------|---------|
| Malicious install hooks | `postinstall` that steals credentials |
| Typosquat / slopsquat | `axois` instead of `axios`; AI-invented names |
| Known vulnerable versions | OSV critical/high CVEs |
| Secret access | Scripts reading `~/.aws`, `.env`, SSH keys |
| Dependency confusion | Private name resolved from public registry |
| Agent auto-install | Coding agent installs without review |
| Secret leakage | Tokens in SARIF, logs, or evidence packs |

## Controls

- Pre-install static analysis (metadata, lifecycle, artifacts where supported)
- OSV lookup + local sqlite cache; fail closed when intel is missing
- Policy modes, hard-block rules, private registry routing
- MCP and CI fail-closed defaults for agents / non-interactive WARN
- Redaction of secrets in reports
- Signed releases, checksums, SBOM, attestations

## Non-goals

- Not a hosted registry proxy  
- Not a full enterprise SCA platform  
- Not a malware ML classifier  
- Behavior analysis is **opt-in** and must be described honestly (heuristic ≠ sandbox)  

## Related

- [Architecture](architecture.md)
- [Known limitations](known-limitations.md)
- [Behavior analysis](behavior-analysis.md)
- [Open-core boundary](architecture/open-core-boundary.md)
