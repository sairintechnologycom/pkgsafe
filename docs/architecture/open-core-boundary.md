# PkgSafe Open-Core Boundary

PkgSafe OSS is the local-first package supply-chain guardrail core. Enterprise distributions may extend the OSS core through supported interfaces for centralized policy, evidence retention, registry governance, and organization-level workflows.

This document defines the public/private boundary for the public repository:

- Public repo: `github.com/sairintechnologycom/pkgsafe`
- Private repo: `github.com/sairintechnologycom/pkgsafe-enterprise`

## Product Model

PkgSafe Enterprise is a private downstream superset of PkgSafe OSS.

The public repository contains the OSS core and extension contracts. The private repository consumes the public core and adds private enterprise modules. Public capabilities should flow into the private distribution. Private implementation must not flow into this public repository unless it has been explicitly reviewed and reclassified as OSS-safe.

## OSS Core

The public repository may contain:

- CLI scanner and install guardrail workflows
- npm-first scanning
- OSV integration
- local policy evaluation
- SARIF, JSON, and Markdown outputs
- basic GitHub Action
- basic MCP guardrail
- local evidence pack generation
- public documentation
- extension interfaces
- no-op or local implementations

## Private Enterprise Superset

The private enterprise repository may contain all public OSS capabilities plus:

- enterprise build wrapper
- hosted evidence archive
- central policy sync
- enterprise policy packs
- commercial or private intelligence feed
- SSO, SAML, and RBAC
- licensing
- dashboard and backend services
- enterprise registry integrations
- customer-specific integrations
- premium tests and fixtures
- enterprise documentation

## Public/Private Flow Rule

| Direction | Allowed? | Condition |
| --- | ---: | --- |
| Public to private | Yes | Always allowed |
| Private to public | Restricted | Only after explicit open-core boundary review |
| Premium implementation to public | No | Never |
| Premium tests or fixtures to public | No | Never |
| Premium docs or roadmaps to public | No | Never, unless sanitized to high-level public wording |
| Interface or stub to public | Yes | Allowed only when implementation-free |

## Disallowed Leakage Examples

Do not add premium implementation to this public repository, including:

- licensing or license server logic
- hosted evidence service implementation
- central policy sync service implementation
- commercial intelligence feed logic or rules
- private feed credentials, endpoints, or schemas
- SAML, SSO, or RBAC implementation
- enterprise dashboard backend or frontend implementation
- billing or paid-feature enforcement
- customer-specific configuration, policy, registry examples, or fixtures
- premium test fixtures or customer reproduction cases

Do not hide premium implementation behind runtime checks or feature flags in public code. For example, public code must not include private logic guarded by license checks. The public repository may define an interface, but the private repository must provide the implementation.

## Extension Interface Policy

Public interfaces are allowed when they are implementation-free and useful to OSS users. A public interface may define a provider contract, local fallback, or no-op adapter. It must not include:

- private service endpoints
- proprietary rule logic
- customer identifiers
- premium workflow orchestration
- private data models that reveal implementation details

When in doubt, keep the interface small and place implementation in `pkgsafe-enterprise`.

## Build And Release Model

The preferred enterprise architecture is:

1. The public OSS core is released from `github.com/sairintechnologycom/pkgsafe`.
2. The private enterprise repository imports the public core as a Go module.
3. The private repository adds enterprise modules and an enterprise binary.
4. The private repository may vendor the public core for reproducible or air-gapped enterprise builds.

The private repository should avoid copying public source unless vendoring or mirroring is explicitly required. Premium implementation must not be copied into this public repository.

Recommended private `go.mod` shape:

```go
module github.com/sairintechnologycom/pkgsafe-enterprise

require github.com/sairintechnologycom/pkgsafe v1.0.1
```

## Contributor Guidance

Before adding a feature, classify it using `docs/architecture/feature-classification.md`.

Use this rule:

- If it is useful to all local-first users and contains no private service dependency, it can be OSS core.
- If it is a contract that enables extension without revealing implementation, it can be a public interface.
- If it depends on organization-level services, paid distribution, customer-specific data, or private intelligence, it belongs in the private enterprise repository.

Do not add private implementation, premium tests, customer fixtures, enterprise policy packs, or private roadmap details to this repository.

## Codex And AI-Agent Guidance

AI agents working in this public repository must:

- preserve all OSS functionality
- avoid implementing premium enterprise features here
- add only implementation-free interfaces or local/no-op fallbacks when extension points are needed
- keep customer-specific examples and private service details out of generated docs, tests, fixtures, and code
- run `scripts/check-public-boundary.sh` before proposing changes that mention enterprise-only concepts

If a request asks for premium functionality in this repository, document the public interface only and state that the implementation belongs in `github.com/sairintechnologycom/pkgsafe-enterprise`.
