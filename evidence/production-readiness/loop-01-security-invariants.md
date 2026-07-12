# Loop 01 — Security Invariants and Strict Offline Semantics

Date: 2026-07-11  
Base commit: `df143fe6eec47d02632b757987c2babe14561981`  
Status: accepted

## Feature result

PkgSafe now uses explicit `advisory`, `policy_block`, and `security_block`
enforcement classes. The security-block taxonomy and precedence are documented
in `docs/architecture/security-enforcement.md` and implemented by
`policy.EnforcementClassFor`.

Security blocks are evaluated before trust and exceptions. Controlled
exceptions remain available for ordinary policy blocks, including critical
vulnerability policy where permitted.

Strict offline behavior is validated inside npm and PyPI scanners before
registry/cache acquisition or runner selection. Heuristic host execution is
rejected offline. Isolated execution requires disabled networking and an
available isolated backend; there is no fallback.

## Invariant matrix

| Finding | Trust | Exception | Requester | Expected | Result |
| --- | ---: | ---: | --- | --- | --- |
| Malware | yes | active | agent | BLOCK | PASS |
| Credential path access | yes | active | agent | BLOCK | PASS |
| Dependency confusion | yes | active | agent | BLOCK | PASS |
| Private scope on public registry | yes | active | agent | BLOCK | PASS |
| Unapproved registry | yes | active | agent | BLOCK | PASS |
| Critical vulnerability policy block | no | active | human | WARN | PASS |
| WARN in agent mode | n/a | n/a | agent | human approval | PASS (existing MCP/interceptor suite) |

## Commands and observed results

```text
env GOCACHE=/tmp/pkgsafe-gocache go test ./internal/policy ./internal/risk ./internal/sandbox
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test ./internal/scanner/npm ./internal/scanner/pypi
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test -race ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go vet ./...
PASS

docker run --rm --privileged -e PKGSAFE_REQUIRE_ISOLATED_E2E=1 ...
  go test -v -run Isolated ./internal/sandbox/
PASS: 10 isolated tests
```

The first scanner test attempt inside the managed host sandbox could not bind
`httptest` loopback ports (`operation not permitted`). It was rerun with the
same test command under approved local-test permissions and passed; this was an
environment restriction, not a product failure.

## Network-trap evidence

- Host listener connection from isolated runner: **0 attempts received**.
- DNS resolution inside offline isolated namespace: **failed as required**.
- Isolated `network_mode=host` control case: **connected**, proving the trap can
  detect a shared network rather than producing an unconditional pass.
- Offline heuristic runner creation: **0**; validation fails before scanner
  cache lookup and runner selection.

## BLOCK execution evidence

Existing scanner/MCP tests plus the full suite verify that a statically blocked
package does not execute behavior analysis. Loop 01 changes do not move behavior
execution ahead of static policy evaluation.

## Known limitations

- Linux isolation shares the host kernel and is not a VM boundary.
- The privileged Docker container is a validation harness; production uses the
  bubblewrap backend directly on supported Linux hosts.
- `REVIEW_REQUIRED` is now part of the core decision vocabulary, but complete
  cross-output schema unification belongs to the trusted-profile loop.

## Completion gate

| Gate | State |
| --- | --- |
| PSR-001 | CLOSED |
| PSR-003 | CLOSED |
| hard-block matrix | PASS |
| offline network attempts | 0 |
| BLOCK execution attempts | 0 |
