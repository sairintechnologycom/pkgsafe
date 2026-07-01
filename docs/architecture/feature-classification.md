# Feature Classification

Every PkgSafe feature should be classified before it is added to the public repository.

## Labels

### OSS_CORE

Functionality that belongs in the public OSS core.

Examples:

- CLI scanner
- npm scanner
- OSV database update and lookup
- local policy evaluation
- local evidence ZIP generation
- SARIF, JSON, and Markdown outputs
- basic GitHub Action
- basic MCP guardrail
- offline bundle import, export, and verification

### PUBLIC_INTERFACE

Implementation-free contracts, stubs, local fallbacks, or no-op adapters that allow downstream distributions to extend OSS behavior without exposing private implementation.

Examples:

- provider interfaces for evidence sinks
- policy source interfaces
- registry resolver interfaces
- local-only provider implementations
- no-op adapters for unsupported external services

### PRIVATE_ENTERPRISE

Premium implementation that must live only in `github.com/sairintechnologycom/pkgsafe-enterprise`.

Examples:

- hosted evidence archive implementation
- central policy sync implementation
- enterprise policy pack delivery
- commercial intelligence feed implementation
- SSO, SAML, or RBAC implementation
- licensing enforcement
- dashboard or backend services
- enterprise registry integrations

### PRIVATE_TEST

Tests, fixtures, simulations, or golden files that exercise private enterprise implementation or customer-specific behavior.

Examples:

- enterprise service integration tests
- premium policy-pack fixtures
- private feed fixtures
- customer reproduction cases
- enterprise dashboard test data

### PRIVATE_DOC

Documentation that explains private enterprise implementation, premium operations, private service deployment, or commercial packaging.

Examples:

- licensing internals
- hosted evidence service architecture
- central policy sync operations
- private intelligence feed runbooks
- enterprise dashboard internals
- customer onboarding playbooks

### PRIVATE_CUSTOMER

Customer-specific information that must never be committed to the public repository.

Examples:

- customer names or tenant identifiers
- customer registry URLs
- customer-specific policy exceptions
- private credentials or tokens
- customer reproduction fixtures
- customer deployment topology

## Classification Examples

| Feature | Classification |
| --- | --- |
| npm scanner | `OSS_CORE` |
| OSV DB update | `OSS_CORE` |
| local evidence ZIP | `OSS_CORE` |
| basic MCP guardrail | `OSS_CORE` |
| team evidence local report | `OSS_CORE` or `PUBLIC_INTERFACE` |
| evidence sink provider interface | `PUBLIC_INTERFACE` |
| hosted evidence archive | `PRIVATE_ENTERPRISE` |
| central policy sync | `PRIVATE_ENTERPRISE` |
| SAML, SSO, and RBAC | `PRIVATE_ENTERPRISE` |
| enterprise policy templates | `PRIVATE_DOC` or `PRIVATE_ENTERPRISE` |
| commercial intelligence feed | `PRIVATE_ENTERPRISE` |
| customer-specific registry config | `PRIVATE_CUSTOMER` |

## Review Rule

Public to private movement is allowed. Private to public movement requires an open-core boundary review. Premium implementation, premium tests, premium docs, and customer-specific material must not be moved into the public repository.
