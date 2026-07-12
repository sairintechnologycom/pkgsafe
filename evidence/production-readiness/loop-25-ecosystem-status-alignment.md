# Loop 25 — Ecosystem Status Alignment

Date: 2026-07-12

## Feature spec

An aggregate GA result must identify which ecosystem is GA. It must not emit
`PRODUCTION_GA_READY` while simultaneously labelling npm public beta.

## Build loop

- Preserved pre-qualification maturity as npm/PyPI public beta and Go/Cargo
  preview.
- Promoted the ecosystem status only after every GA blocker is cleared.
- Defined production-qualified statuses:
  - `npm-ga-pypi-public-beta-go-cargo-preview`;
  - `npm-ga-go-cargo-preview`.
- Kept PyPI at public beta and Go/Cargo at preview when npm qualifies.
- Retained fail-closed rejection of unknown ecosystem-scope status values.

## Validation loop

Focused tests verify:

- a complete GA-ready report promotes npm to GA;
- PyPI remains public beta when its corpus is present;
- Go and Cargo remain preview;
- insufficient repository evidence still blocks GA.

Commands and results:

```text
go test ./internal/validation -run \
  '^(TestComputeReadinessStageProductionGA|TestProductionEcosystemDepthKeepsPyPIBeta|TestProductionReadinessGABlockedWhenRepoCountLow)$'  PASS
make fmt-check                                      PASS
go test ./...                                       PASS
go vet ./...                                        PASS
golangci-lint v1.64.8 run --timeout 5m              PASS
go test -count=1 -race ./internal/validation        PASS
```

Loop 23 already captured the complete aggregate gate with every GA blocker
cleared. Loop 25 changes only the maturity label derived after that gate; it
does not weaken any readiness threshold or promote PyPI, Go, or Cargo.

## Review loop

Before this loop, `gaBlockers` accepted an npm-public-beta ecosystem label and
`computeReadinessStage` then returned `PRODUCTION_GA_READY` without changing
that label. The output contradicted itself and could mislead documentation or
release automation.

The final status and ecosystem scope now form one coherent statement: npm may
be production-qualified while PyPI remains public beta and Go/Cargo remain
preview.

## Completion gate

```text
PRODUCTION_GA_READY + npm public beta combination: impossible
npm GA label requires all GA blockers clear: PASS
PyPI remains public beta: PASS
Go/Cargo remain preview: PASS
unknown ecosystem scope fails closed: PASS
```
