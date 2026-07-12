# Loop 02 — OSS / Enterprise Boundary Correction

Date: 2026-07-11  
Status: accepted

## Result

PSR-002 is closed in the public tree.

Removed from OSS:

- `pkg/license` entitlement verifier, feature catalog, wire format, and tests;
- enterprise command injection/dispatch hooks and premium command tests;
- `RunConfig` entitlement and CI enterprise-mode gates;
- hidden CI evidence enrichment switches.

Local policy, registry, trust, and exception evidence is OSS functionality and
is now emitted consistently rather than hidden behind a premium mode.

The public module retains only the neutral `pkg/capability.Provider` contract.
Its local implementation grants no downstream capabilities and contains no
commercial feature names or entitlement policy.

## Structural boundary checks

`scripts/check-public-boundary.sh` now rejects:

- forbidden implementation paths such as `pkg/license`, `pkg/enterprise`, and
  `internal/enterprise`;
- entitlement, premium-dispatch, signed-feature, and CI premium-mode symbols;
- the existing forbidden commercial implementation vocabulary.

Negative fixtures executed outside the repository:

| Fixture | Evasion | Result |
| --- | --- | --- |
| `/tmp/pkgsafe-boundary-path/pkg/license/verifier.go` | benign source text in forbidden path | rejected, exit 1 |
| `/tmp/pkgsafe-boundary-symbol/internal/neutral/model.go` | `Entitlement` symbol outside obvious path | rejected, exit 1 |

## Downstream compatibility

A clean temporary downstream Go module imported `pkg/cli` and
`pkg/capability`, implemented the neutral provider, built a downstream binary,
and executed `version` successfully:

```text
pkgsafe v1.0.2-dev (none)
```

This proves the public module remains consumable without any private package.
Verification of a real private repository was not possible because it was not
provided to this public-workspace task; the public-side compatibility contract
is compile-tested.

## Commands

```text
make check-public-boundary
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test -race ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go vet ./...
PASS

temporary downstream go mod tidy/build/version
PASS
```

## Completion gate

| Gate | Result |
| --- | --- |
| PSR-002 | CLOSED |
| public premium implementation | 0 detected |
| customer-specific artifacts introduced | 0 |
| public module consumed downstream | PASS |
| structural boundary fixture | PASS (rejected) |
| keyword/symbol-evasion fixture | PASS (rejected) |
