# PkgSafe — User Rollout Readiness

**Assessed:** 2026-06-27 · **Version:** `0.1.0` (alpha) · **Branch:** `feat/dependency-inventory-diff`

## Verdict

**Not ready for general user rollout.** PkgSafe is a credible alpha. The security
*honesty* problems are fixed (P0+P1 in [`REMEDIATION.md`](./REMEDIATION.md) — pack
signatures, DB-overwrite, sandbox relabel, OSV fail-closed, real advisory sync all
merged). What now gates rollout is **distribution + UX + breadth**, not security theater.

Concretely: a user today **cannot install it** (no release, no tags, no install docs),
the tool only fully works **online** and only for **npm**, and the API is not safe to
expose. It is fine to roll out *now* to a narrow, supervised audience; it is not ready
as a general installable security tool.

### Rollout tiers (what's safe today vs. what's gated)

| Tier | Audience / use | Status |
|------|----------------|--------|
| **T0 — Internal / advisory** | CI advisory gate & manual `scan-npm-package`, npm only, always-online, API loopback-only | ✅ Usable now (build from source) |
| **T1 — Early external users** | Installable binary, documented offline caveat, npm + PyPI, honest "what works" matrix | ⛔ Blocked by M0+M1 below |
| **T2 — General / enterprise** | Multi-ecosystem, exposable API, audit trail, signed releases, parallel scans | ⛔ Blocked by M2+M3 below |

---

## What works today (verified)

- `go build ./...`, `go vet ./...`, and `go test ./...` all clean — **33 packages pass, 0 fail**.
- **npm** is the full firewall path: `scan-npm-package`, `scan-lockfile`, `scan-local-npm`, `npm-install` gate, tarball fetch + integrity check + safe extraction.
- **PyPI** nearly complete (no real sandbox; lifecycle analysis is heuristic).
- **OSV** advisory data for 4 ecosystems with real bulk `all.zip` sync; **fails closed** on lookup error.
- CLI, REST API, MCP stdio server, GitHub Action, policy engine, **ed25519-signed policy packs**, evidence packs.
- Self-readiness gate exists (`internal/validation/alpha_readiness.go`): corpus, extraction hardening, secret redaction, registry routing, MCP stdio, install enforcement.

---

## What's missing — rollout roadmap

Ordered by what unblocks the next tier. Security items (S#/M#) cross-reference
`REMEDIATION.md`; rollout-specific items are R#.

### M0 — Make it installable (blocks **all** external rollout) ✅ landed (tag push pending)

- [x] **R1 — Release pipeline.** Added `.goreleaser.yaml` (was missing entirely — `release.yml` referenced GoReleaser with no config) building linux/macos/windows × amd64/arm64, and upgraded the workflow to goreleaser-action@v6 / GoReleaser v2 with cosign + syft installers and `id-token` permission. **Owner action remaining:** push a `v0.1.0` tag to trigger the first real release.
- [x] **R2 — Wire version from build.** New `internal/version` package is the single source of truth; injected via `-ldflags` in the Makefile and GoReleaser. Removed the hardcoded `0.1.0` from `cmd/pkgsafe/main.go` and `internal/enterprise/metadata.go`; the min-version gate now reads the real version and skips for dev builds. (= S7)
- [x] **R3 — Install instructions in README.** Added an Install section (release archive, `go install`, `make build`) with checksum + cosign verification steps and the Unix-only-runner platform note.
- [x] **R4 — Sign release artifacts + SBOM + checksums.** GoReleaser now emits `checksums.txt`, keyless cosign signatures, and per-archive SBOMs (syft). SLSA provenance still optional follow-up.

### M1 — Honest UX (blocks T1 external users) 🟠

- [ ] **R5 — Document the offline caveat prominently.** "Local-first" but offline scanning still needs a prior *online* cached scan of the target package. Surface this in README + CLI help; consider a seeded/bootstrapped cache.
- [ ] **R6 — Fix stale README "Notes."** Still claims it "avoids … external Go modules" (false — uses `modernc.org/sqlite` et al.). Add a "What works / what's metadata-only / what's stubbed" capability matrix. (= M3)
- [ ] **R7 — Document API exposure policy.** Make explicit it is loopback-only and unauthenticated by default; tell users not to expose it until M2 lands.
- [ ] **R8 — Resolve the perpetually-red self-scan CI gate.** "PkgSafe Package Gate Self-Scan" fails on every PR because CI scans the intentional `axois@1.0.0` typosquat fixture online. Point it at a real lockfile or run it `offline:true` so the signal is meaningful.

### M2 — Safe to operate (blocks T2 / exposable service) 🟡

- [ ] **S3 — API hardening:** require auth for non-loopback, TLS, server read/write/idle timeouts, request-body cap, basic rate limiting (`internal/api/server.go`).
- [ ] **S4 — Parallelize scans:** bounded worker pool / `errgroup`; don't abort the whole scan on one dependency error; add registry retry/backoff (`internal/ci/scan.go`).
- [ ] **S5 — Kill the fail-open report stub:** unknown/un-scannable packages must surface as "unknown," not `ALLOW / score 0` (`internal/report/generator.go:172`).
- [ ] **S6 — Structured logging + decision audit trail** for SOC/enterprise use; stop swallowing errors.

### M3 — Breadth & trust (T2 polish) 🟢

- [ ] **S8 — Go & Cargo content analysis** (currently metadata-only) → first-class policy ecosystems.
- [ ] **S9 — PyPI lockfile parsers** (poetry.lock, uv.lock, Pipfile.lock, conda) — currently stubs.
- [ ] **M1(sec) — CI maturity:** add `golangci-lint`, `-race`, coverage gate, and a Windows/macOS matrix (sandbox paths never tested off Ubuntu).
- [ ] **M2(sec) — Test coverage:** OSV client, report exporters (siem/servicenow/sarif/html/csv/…), sandbox heuristics are light (~40 test files / 172 source).
- [ ] **R9 — Real OS isolation for lifecycle analysis** (container/namespaces/microVM), or keep the honest "heuristic, runs on host" label permanently. (= B3 follow-up)

### Engineering cleanups (non-gating)

- [ ] **R10 — Dedup the npm inventory parser:** `ScanInventoryGit` in `internal/deps/npm/diff.go` duplicates `ScanInventory` (`inventory.go`) verbatim.

---

## Suggested sequence

1. **M0** (R1–R4) — one focused PR series; makes the tool installable + a release exists.
2. **M1** (R5–R8) — docs + CI signal; makes external evaluation honest. → **opens T1 rollout.**
3. **M2** (S3–S6) — service hardening + operability. → **opens T2.**
4. **M3** — ecosystem breadth, CI/test maturity, real isolation. → general/enterprise polish.
