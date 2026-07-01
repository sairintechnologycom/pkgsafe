# Contributing To PkgSafe

PkgSafe is maintained as an open-core project. The public repository contains the OSS core and implementation-free extension contracts.

## Public/private Feature Boundary

PkgSafe Enterprise is a private downstream superset of PkgSafe OSS. It includes all public OSS capabilities plus private enterprise-only modules. Public OSS code may flow into the private enterprise distribution. Private implementation must not flow back into this public repository unless it has been explicitly reviewed and classified as OSS-safe.

Before adding a feature, read:

- `docs/architecture/open-core-boundary.md`
- `docs/architecture/feature-classification.md`

Do not add the following to this public repository:

- premium implementation
- customer-specific configs, examples, fixtures, or reproduction cases
- enterprise policy packs
- private intelligence rules or private feed logic
- licensing enforcement or license server logic
- hosted service internals
- enterprise dashboard internals
- premium tests or fixtures
- private roadmap details

Interfaces and stubs are allowed when they contain no private implementation. Prefer small provider interfaces, local fallbacks, and no-op adapters over feature-flagged premium logic.

Run the public-boundary guardrail before submitting changes:

```sh
scripts/check-public-boundary.sh
```

or:

```sh
make check-public-boundary
```

## General Checks

For code changes, run:

```sh
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
make build
```
