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
ok  	github.com/sairintechnologycom/pkgsafe/internal/sandbox
ok  	github.com/sairintechnologycom/pkgsafe/internal/scanner/npm
ok  	github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi
ok  	github.com/sairintechnologycom/pkgsafe/internal/output
ok  	github.com/sairintechnologycom/pkgsafe/cmd/pkgsafe
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

---

# Loop 10 Completion (2026-07-03): Real-Linux Validation and Hardening

The sections above record the original experimental implementation, whose own
Learning Loop named the missing step: Linux CI with bubblewrap running
positive isolation tests. This completion pass performed that step, found that
the experimental backend had never actually executed, and promoted the backend
to supported.

- Branch: `loop-10-isolated-backend` (the older
  `loop-10-isolated-behavior-backend` remote branch is a stale draft and was
  left untouched)
- PR: https://github.com/sairintechnologycom/pkgsafe/pull/34

## Defects Found

1. **Every real isolated run failed.** The runner passed `--rlimit-nofile 64`;
   bubblewrap has no `--rlimit-*` options (verified against upstream
   `bwrap.xml`). The availability probe did not use that flag, so
   `available: true` was reported for a backend that could never execute a
   script. This was undetectable on the Darwin dev host and is exactly why the
   completion pass added mandatory Linux CI execution.
2. **Failures were invisible.** Both npm scanner lifecycle loops silently
   dropped errored runs (`if err != nil { continue }`). Isolated mode would
   have produced zero analysis with no indication. Non-zero script exits and
   timeouts were also propagated as errors and dropped, losing legitimate
   behavioral observations.
3. **Teardown could leak hostile sandbox contents.** A script running
   `chmod 000` on a directory it created defeated `os.RemoveAll`. The first
   fix attempt also failed on real Linux because `filepath.Walk` reads a
   directory before invoking the callback; the final fix restores directory
   permissions iteratively, unlocking one nesting level per pass, and is
   covered by a cross-platform unit test
   (`TestRemoveAllForceHandlesHostilePermissions`) plus the Linux E2E hostile
   teardown test.

## Hardening Delivered

- Availability probe mirrors the real namespace/mount set, so `Available()`
  cannot pass for a configuration `RunLifecycleScript` would fail on.
- Fixed in-sandbox `PATH`; the host `PATH` value is never forwarded.
- `--hostname pkgsafe`, `--unshare-cgroup-try`, synthetic read-only
  `/etc/passwd` and `/etc/group` (nobody identity) instead of the host account
  database.
- Guarded in-sandbox `ulimit` caps (file descriptors, processes, file size)
  replacing the invalid bwrap flag.
- Network disabled by default via unshared network namespace — enforced, not
  declared. `network_mode=host` opts in explicitly and ro-binds
  `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and CA certificate
  paths; any other mode fails closed to disabled and the trace records it.
- Infrastructure failures recorded per script via new
  `SandboxScriptResult.Error` (JSON `error`; text output prints
  "script was NOT analyzed"). Non-zero exit and timeout are observations.
- Text output prints "Network Mode (enforced)" only for isolated runs;
  heuristic keeps "declared, not enforced". Isolated runner metadata carries
  an honest kernel-sharing warning (not a hypervisor boundary).

## Real-Linux E2E Evidence (GitHub Actions ubuntu-latest)

CI job `isolated-behavior-e2e` installs bubblewrap, relaxes the Ubuntu
AppArmor unprivileged-userns restriction, and runs the suite with
`PKGSAFE_REQUIRE_ISOLATED_E2E=1` so an unavailable runner fails the job
instead of skipping — a green job is proof the backend executed in bubblewrap.

| Check | Test | Result |
| --- | --- | --- |
| Loopback TCP connect to a live host listener blocked by default | `TestIsolatedNetworkDisabledByDefault` | PASS |
| Same connect succeeds under `network_mode=host` (positive control) | `TestIsolatedNetworkHostModeShares` | PASS |
| Host `$HOME` invisible; `$HOME=/home/pkgsafe`; uid 65534; hostname `pkgsafe`; canary HOME mounted | `TestIsolatedHostHomeInvisibleAndIdentity` | PASS |
| Host environment variable does not leak (`--clearenv`) | `TestIsolatedEnvironmentIsCleared` | PASS |
| Teardown clean after hostile `chmod 000` | `TestIsolatedTeardownIsCleanEvenWhenHostile` | PASS (after teardown fix; failed on first run, see Defects) |
| Non-zero exit / timeout are results, not errors | `TestIsolatedNonzeroExitAndTimeoutAreNotErrors` | PASS |
| Credential canary finding flows end-to-end from an isolated run | `TestIsolatedCanaryFindingEndToEnd` | PASS |
| Trace reports enforced network state | `TestIsolatedTraceReportsNetworkState` | PASS |
| Isolated mode never falls back to heuristic | `TestSelectRunnerForIsolatedModeDoesNotFallbackToHeuristic` | PASS |

## Constraints Preserved

- Behavior analysis remains disabled by default.
- Heuristic mode wording unchanged: host execution, never sandboxing or
  containment.
- Docs promoted isolated mode to "supported on Linux" with the explicit
  caveat that namespace isolation shares the host kernel.

## Deferred

- macOS isolation backend — separate design, remains unavailable-and-honest.
- Syscall-level observation (seccomp notify / eBPF); findings remain
  canary/pattern based inside the namespace boundary.
- Per-run cgroup memory/CPU quotas (bwrap cannot set them; needs a cgroup
  manager).
