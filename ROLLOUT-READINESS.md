# PkgSafe — User Rollout Readiness

**Assessed:** 2026-07-05 · **Version:** `v1.6.0` (GA) · **Branch:** `main`

## Verdict

**Ready for general user rollout as an npm + PyPI supply-chain guardrail.**
PkgSafe ships as a signed, installable GA binary with honest, documented scope.
The distribution, honest-UX, and service-safety milestones that gated the
original alpha (M0–M2 below) are all landed, and the two ecosystems in GA scope
(npm and PyPI) are real-repo validated. What remains is **test/CI depth and
optional breadth**, not a rollout blocker.

This supersedes the 2026-06-27 alpha assessment, which predated the v1.0.0→v1.6.0
release series. See [`REMEDIATION.md`](./REMEDIATION.md) for the security thread
history.

### Rollout tiers

| Tier | Audience / use | Status |
|------|----------------|--------|
| **T0 — Internal / advisory** | CI advisory gate & manual scans, npm only, always-online, API loopback-only | ✅ Shipped |
| **T1 — Early external users** | Installable signed binary, documented offline caveat, npm + PyPI, honest capability matrix | ✅ Shipped (v1.6.0) |
| **T2 — General / enterprise** | Multi-surface (CLI/API/MCP/Action), hardened loopback API, audit trail, signed releases + SBOM + provenance, parallel scans, offline intelligence bundles | ✅ Shipped |

## What's shipped (verified)

- **Installable, signed GA releases** (`v1.6.0`, 11 tags): goreleaser across
  linux/macos/windows × amd64/arm64, `checksums.txt`, keyless cosign
  signatures, GitHub Artifact Attestations, and per-archive SBOMs. Version is
  wired from build via `internal/version` (ldflags), self-report verified per
  release ritual. Install + verification docs in `README.md`,
  [`docs/install.md`](docs/install.md), and
  [`docs/release-verification.md`](docs/release-verification.md).
- **npm** — full firewall path: package/lockfile scanning, tarball fetch +
  integrity check + hardened extraction, lifecycle-script heuristics.
- **PyPI** — GA: pip-parity (PEP 440) resolution, poetry/uv/Pipfile lockfile
  parsing, wheel/sdist static analysis, extraction budgets, real-repo validated
  (6/6 benchmark). No behavior execution.
- **OSV** advisory data with real bulk sync; **fails closed** on lookup error.
  Offline intelligence bundles (`db export-bundle`/`verify-bundle`/`import-bundle`).
- **Service safety (M2):** loopback-only unauthenticated API by default; binding
  a non-loopback address requires `--token` + TLS or refuses to start; request
  timeouts, 1 MiB body cap, per-IP rate limiting. Bounded-concurrency scans.
  `DecisionUnknown` for un-scannable packages (no fail-open). Structured logging.
- **Surfaces:** CLI, REST API, MCP stdio server, GitHub Action, policy engine,
  local policy files, evidence packs.
- **Isolated behavior backend** (Linux, bubblewrap): supported and CI-validated;
  network disabled by default (enforced); never falls back to host execution.
  Heuristic mode is honestly labelled "runs on host, not sandboxing."
- **CI quality gates:** `-race` test suite on Linux + macOS, `go build`/`go vet`
  on Windows, `golangci-lint` (errcheck/gosimple/govet/ineffassign/staticcheck/
  unused/misspell, pinned via [`.golangci.yml`](.golangci.yml)), isolated-backend
  E2E job, and a self-scan dogfood gate against a clean lockfile.

## What's pending (non-blocking)

Ordered by value. None gate the npm + PyPI GA rollout; they widen coverage or
deepen assurance.

- [ ] **Test coverage depth** — OSV client, public report exporters, and sandbox
  heuristics remain lightly tested relative to the source surface. Highest-value
  next investment for a security tool.
- [ ] **Windows test execution** — CI builds + vets on Windows but does not yet
  run the suite there (race detector needs a cgo toolchain; suite not yet
  validated on Windows). Promote `build-windows` to a full test job once the
  Windows-path behavior is confirmed.
- [ ] **Go & Cargo content analysis** — currently metadata-only preview
  (documented as such). Promote to first-class policy ecosystems to make them
  GA-equivalent.
- [ ] **conda lockfile parsing** — still a stub; the other PyPI lockfiles are GA.
- [ ] **macOS isolated behavior backend** — isolation is Linux-only; macOS
  behavior analysis stays heuristic (host, no isolation).
- [ ] **Deeper isolation** — seccomp/eBPF observation and cgroup quotas for the
  Linux backend; SLSA provenance beyond cosign cert + SBOM.

## Non-code rollout checklist

- [ ] Decide the launch audience and messaging (T0/T1/T2 above are all technically open).
- [ ] Establish a support/feedback channel and a versioned docs entry point.
- [ ] Confirm the release cadence and the manual publish gate (goreleaser cuts drafts).
