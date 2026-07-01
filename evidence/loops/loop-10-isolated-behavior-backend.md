# Loop 10 Evidence: Isolated Behavior Backend

Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/27

Branch: `loop-10-isolated-behavior-backend`

## Feature Spec

Add a real isolated behavior analysis backend without enabling behavior analysis
by default. Linux is the first supported target. Unsupported platforms and hosts
without the required backend must fail closed by reporting `not_performed`; they
must not fall back to heuristic host execution.

## Files Changed

Loop 10 files:

- `cmd/pkgsafe/main_test.go`
- `cmd/pkgsafe/report.go`
- `docs/behavior-analysis.md`
- `docs/known-limitations.md`
- `docs/policy-guide.md`
- `docs/private-beta-guide.md`
- `internal/mcp/protocol.go`
- `internal/sandbox/isolated_runner_linux.go`
- `internal/sandbox/isolated_runner_unsupported.go`
- `internal/sandbox/result.go`
- `internal/sandbox/runner.go`
- `internal/sandbox/sandbox_test.go`
- `internal/scanner/npm/scanner.go`
- `internal/scanner/npm/scanner_test.go`
- `internal/scanner/pypi/scanner.go`
- `internal/types/types.go`
- `evidence/loops/loop-10-isolated-behavior-backend.md`

This branch is stacked on earlier loop work, so `git status` also shows files
from Loops 1-9.

## Already Implemented And Reused

- Existing `SandboxRunner` lifecycle-script execution contract.
- Existing fake HOME, canary, cleaned environment, timeout, and behavior finding
  analysis.
- Existing npm scanner behavior-analysis metadata and BLOCK skip invariant.
- Existing behavior-analysis JSON contract under `behavior_analysis`.
- Existing policy config for `sandbox.behavior_mode`, `network_mode`,
  `timeout`, and `keep_sandbox`.

## Newly Implemented

- Runner selection layer:
  - `sandbox.SelectRunner`
  - `sandbox.RunnerMetadata`
  - `sandbox.IsolatedRunner`
  - `sandbox.NewIsolatedRunner`
- Linux isolated backend using bubblewrap (`bwrap`) when available.
- Non-Linux isolated backend that reports unavailable and never executes.
- Linux backend controls:
  - private user namespace
  - private pid/ipc/uts/cgroup namespaces
  - private mount view
  - private network namespace by default
  - explicit `network_mode=host` opt-in to share host networking
  - fake HOME bind
  - disposable workspace bind
  - cleaned environment
  - non-root uid/gid `65534`
  - timeout enforcement
  - file descriptor limit
  - cleanup after execution unless `keep_sandbox` is requested
- Behavior trace output per script.
- npm scanner integration for both registry tarball scans and local package
  scans.
- Tests that isolated mode does not fall back to heuristic host execution.
- Tests that static `BLOCK` packages still never execute lifecycle scripts,
  including when isolated mode is requested.
- Docs updated from planned/unimplemented language to experimental Linux-only
  backend language.

## Validation Commands Run

```bash
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
make build
make package
go test ./internal/sandbox ./internal/scanner/npm ./internal/scanner/pypi ./internal/output ./cmd/pkgsafe
./dist/pkgsafe scan-local-npm testdata/npm/safe-package --behavior isolated --json
./dist/pkgsafe scan-local-npm testdata/npm/reads-credentials --behavior isolated --json
command -v bwrap
uname -s
rg -n "secure sandbox|secure containment|full PyPI|PyPI GA|full Go|full Cargo|SaaS|billing|SSO|hosted service|behavior analysis enabled by default|isolated behavior backend is not implemented" docs/behavior-analysis.md docs/known-limitations.md docs/policy-guide.md docs/private-beta-guide.md cmd/pkgsafe/report.go internal/sandbox internal/scanner/npm internal/scanner/pypi internal/types internal/mcp/protocol.go
```

## Validation Results

`gofmt -w .`: pass.

`go test ./...`: pass.

`go test -race ./...`: pass.

`go vet ./...`: pass.

`make build`: pass.

`make package`: pass. This includes Linux amd64 cross-compilation of the
Linux-only isolated backend.

Focused tests:

```text
ok  	github.com/niyam-ai/pkgsafe/internal/sandbox
ok  	github.com/niyam-ai/pkgsafe/internal/scanner/npm
ok  	github.com/niyam-ai/pkgsafe/internal/scanner/pypi
ok  	github.com/niyam-ai/pkgsafe/internal/output
ok  	github.com/niyam-ai/pkgsafe/cmd/pkgsafe
```

Host/backend availability:

```text
uname -s
Darwin
```

`command -v bwrap` returned no path on this host, so runtime isolated execution
was correctly unavailable here.

## Sample Output

Safe local npm package with isolated mode requested on unsupported host:

```json
{
  "decision": "allow",
  "behavior_analysis": {
    "mode": "isolated",
    "enabled": true,
    "executed": false,
    "isolated": true,
    "runner": "isolated-unavailable",
    "network_policy": "disabled",
    "not_performed": true,
    "reason": "isolated behavior analysis is currently supported only on Linux hosts with bubblewrap"
  }
}
```

Static BLOCK package with isolated mode requested:

```json
{
  "decision": "block",
  "behavior_analysis": {
    "mode": "isolated",
    "enabled": true,
    "executed": false,
    "isolated": true,
    "runner": "isolated-unavailable",
    "network_policy": "disabled",
    "not_performed": true,
    "reason": "behavior analysis skipped because static analysis already blocked the package"
  }
}
```

The sample scans emitted OSV sync warnings because network access was unavailable
in this environment. Those warnings did not affect the isolated-mode behavior
validation.

## Wording Audit

Scoped audit command found no new misleading claims in Loop 10 code/docs. The
only matches were:

- `docs/known-limitations.md`: explicit statement that PyPI has no GA claim.
- `cmd/pkgsafe/report.go`: existing Loop 2 wording that team evidence does not
  upload to a hosted service.

No Loop 10 code or docs claim heuristic mode is secure sandboxing or secure
containment. No Loop 10 work claims full PyPI, Go, or Cargo GA. No SaaS,
billing, SSO, or hosted-service behavior was introduced. Behavior analysis
remains disabled by default.

## Review Results

- Strong enough to call isolated: experimental only. The Linux backend uses
  bubblewrap namespaces and private mounts; it is not promoted to GA.
- Supported platforms: Linux hosts with working bubblewrap user namespace
  isolation.
- Unsupported platforms: macOS, Windows, and Linux hosts without usable
  bubblewrap report unavailable and do not execute.
- Network disabled by default: yes for the Linux backend through private network
  namespace; `network_mode=host` is an explicit opt-in.
- Host HOME protection: Linux backend mounts a fake HOME and does not mount host
  HOME paths into the private root view.
- BLOCK never executes: pass, covered by scanner tests and sample output.
- Default behavior unchanged: pass, behavior analysis remains disabled by
  default.

## Known Limitations

- Runtime isolated execution could not be exercised on this host because it is
  Darwin and `bwrap` is unavailable.
- Linux runtime behavior is experimental and depends on host kernel/user
  namespace and bubblewrap configuration.
- The backend binds common runtime directories read-only so shell commands can
  execute; this is intentionally limited but still needs Linux-host validation
  before GA claims.
- PyPI behavior execution remains unavailable for PyPI package flows.
- `network_mode=host` intentionally shares host networking and should not be used
  for untrusted package execution outside controlled testing.

## Learning Loop

- The existing scanner already enforced the most important invariant: static
  `BLOCK` packages skip behavior execution.
- The main gap was the absence of a runner abstraction that could select
  heuristic versus isolated execution without fallback ambiguity.
- The next hardening step should be Linux CI with bubblewrap installed to run
  positive isolation tests for host HOME, credential paths, network blocking,
  timeout, cleanup, and non-root execution.
- macOS/Windows support needs a separate backend design and should remain
  unavailable until validated.

## Completion Criteria

- Isolated backend works on supported platform: implemented and cross-compiled;
  runtime validation requires a Linux host with bubblewrap.
- Behavior execution remains disabled by default: complete.
- BLOCK package never executes: complete.
- All tests pass: complete.
