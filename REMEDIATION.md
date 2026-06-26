# PkgSafe — Production-Readiness Remediation Plan

**Status as of 2026-06-26:** credible alpha/MVP (`v0.1.0`). Solid hardening primitives,
but **not production-ready as a security control** — two marquee enterprise features
(signed policy packs, sandboxed lifecycle execution) do not deliver the security
property they claim, and the vulnerability-data path fails open.

This document tracks the work required to make PkgSafe trustworthy as an enforcement
boundary. Findings are grounded in source (`file:line`). Severities:

- **BLOCKER** — defeats the tool's core security promise; must fix before any "secure" claim.
- **SERIOUS** — materially weakens protection or operability.
- **MINOR** — correctness/quality/maturity.

Suggested order is top-to-bottom: blockers first, then the OSV data path, then API
hardening and operability, then ecosystem/maturity breadth.

---

## P0 — Blockers (the security model does not hold today)

### B1. Policy-pack signatures are not cryptographically verified
- [ ] Implement real signature verification (e.g. ed25519/minisign or cosign), with a
      configured/trusted public key, over a canonical digest of pack contents.
- [ ] Make `checksums.txt` cover **all** files and be itself covered by the signature;
      stop treating `signature.sig` as out-of-band trust.
- [ ] Fail closed when `Signing.Required` is set and verification fails or no key is configured.
- [ ] Use the parsed `Signing.Algorithm` field instead of ignoring it.

**Evidence:** `internal/enterprise/pack_verify.go:103-108` only checks that
`signature.sig` exists (`_, hasSig := files["signature.sig"]`) — no key, no algorithm,
no byte verification. `internal/enterprise/checksums.go:51` excludes `signature.sig`
from checksum coverage. `internal/enterprise/metadata.go:13-16` parses
`Signing.Algorithm` but never uses it. No `ed25519`/`rsa`/`Verify(` primitives exist in
the repo. **Impact:** authenticity is theater — anyone who can hand you a pack can
recompute checksums and forge "signed" status.

### B2. Installing a policy pack silently overwrites the active vulnerability DB
- [ ] Never write a pack-supplied `pkgsafe.db` to `db.DefaultDBPath()`.
- [ ] If packs may legitimately carry advisory data, import it into a namespaced/merged
      store with provenance — never replace the live DB unconditionally.
- [ ] Back up + version the DB and require explicit confirmation for any DB-altering action.
- [ ] Reconsider `ExportBundle` shipping the local DB inside packs (normalizes the risk).

**Evidence:** `internal/enterprise/pack_install.go:42-53` writes any pack file named
`pkgsafe.db` directly to `~/.pkgsafe/pkgsafe.db` via `os.WriteFile(dbPath, content, 0o644)`,
bypassing the per-pack `installDir` sandboxing used for all other files (`:54-61`).
`ExportBundle` (`:157-164`) bundles the local DB into packs. **Impact:** combined with
B1, a malicious pack can replace the entire vuln DB (e.g. empty it) to blind the scanner.

### B3. The "sandbox" provides no real isolation
- [ ] Either implement genuine isolation (container/namespaces+seccomp+network namespace,
      or a microVM/gVisor) for lifecycle execution, **or**
- [ ] Honestly relabel the feature as "heuristic behavior analysis" everywhere in code,
      output, and docs, and remove the implication that untrusted code is contained.
- [ ] If kept as exec-based, actually enforce `NetworkMode == "disabled"` (currently a no-op).
- [ ] Implement (or clearly mark unimplemented) PyPI lifecycle analysis instead of a stub.

**Evidence:** `internal/sandbox/process_runner_unix.go:13-17` runs scripts via
`exec.Command("sh", "-c", cmdStr)` as the current user; only `Setpgid` + cleaned env, no
namespaces/seccomp/chroot/container. `internal/sandbox/runner.go:52-55` prints
"isolation is best-effort" and does not block network even when disabled. Detection is
substring matching on command/stdout (`internal/sandbox/behavior_analyzer.go:114-237`)
plus canary atime/token matching (`:50-77`). PyPI sandbox not implemented
(`internal/scanner/pypi/scanner.go:181`, `internal/output/output.go:168`). **Impact:**
a real payload reads the host FS outside the fake HOME, opens real sockets, and persists
files — none contained; detection is trivially evaded.

---

## P1 — Vulnerability data path (fails open today)

### S1. OSV lookup fails open on network/rate-limit errors
- [ ] On OSV query error, fail closed (or degrade to a clearly-surfaced "unknown" state),
      never silently score the package as having zero vulnerabilities.
- [ ] Add retries with backoff and explicit `429`/rate-limit handling.
- [ ] Surface a visible warning/exit signal when advisory data could not be fetched.

**Evidence:** `internal/scanner/npm/scanner.go:310-320` proceeds with `len(rawVulns)==0`
on error (scored as clean, no warning). `internal/intel/osv/client.go:17-22,45-47`
single 15s client, no retries, treats non-200 (incl. 429) as generic error.
`internal/cli/update_db.go:75-78` swallows per-package errors. **Impact:** a transient
outage or rate-limit yields a false "clean" verdict.

### S2. No real bundled / synced advisory database
- [ ] Provide a real OSV bulk import / periodic sync (not per-cached-package refresh).
- [ ] Ship or bootstrap a seeded DB so a clean machine isn't empty offline.
- [ ] Replace the hardcoded 5-package seed with a genuine update path.
- [ ] Make offline scans explicit about staleness instead of proceeding silently.

**Evidence:** `internal/db/sqlite.go:17-35` opens/migrates an empty DB.
`internal/cli/update_db.go:59-65` only refreshes already-cached packages and seeds
`lodash, axios, react, express, typescript` "to make update-db look nice."
`internal/scanner/npm/scanner.go:96-109` offline path hard-fails on cache miss / warns
but proceeds when stale. **Impact:** no trustworthy offline posture; thin online sync.

---

## P2 — API & service hardening

### S3. API unauthenticated by default; missing transport/DoS hardening
- [ ] Require auth (or fail to start without it) for any non-loopback exposure.
- [ ] Add TLS support (`ListenAndServeTLS`) for non-localhost use.
- [ ] Add server read/write/idle timeouts (replace raw `http.ListenAndServe`).
- [ ] Cap request body size on JSON decoders; add basic rate limiting.

**Evidence:** auth only wired when `cfg.Token != ""`
(`internal/api/server.go:202-204`; flag default empty `cmd/pkgsafe/main.go:1106`).
Mitigations present: localhost bind (`server.go:257`), `localhostOnly`
(`server.go:220-230`), constant-time token compare (`server.go:239`, recent fix).
Gaps: no TLS, no rate limit, no body cap (`server.go:79,173`), no server timeouts.
**Impact:** mitigated today only by the loopback bind; not safe to expose.

---

## P3 — Operability & robustness

### S4. Scans are fully serial; no retries
- [ ] Add a bounded worker pool / `errgroup` for per-dependency scans.
- [ ] Don't abort the whole scan on a single dependency error; collect and report.
- [ ] Add retry/backoff to registry clients.

**Evidence:** serial loops `internal/ci/scan.go:137-141` (npm), `:314-321` (pypi); a
single error returns immediately. Registry clients have timeouts but no retries
(`internal/registry/npm/registry.go:63,266`; `internal/registry/pypi/client.go:30,119`).

### S5. Fail-open report stub for unknown packages
- [ ] Stop defaulting un-scannable/uncached packages to `Decision: ALLOW, Score: 0`;
      represent them as "unknown" and let policy decide.

**Evidence:** `internal/report/generator.go:172-179`.

### S6. No structured logging / metrics / audit trail
- [ ] Introduce leveled structured logging and stop silently swallowing errors.
- [ ] Add a decision audit trail suitable for SOC/enterprise use.

**Evidence:** ad-hoc `fmt.Fprintln(os.Stderr,...)` throughout; swallowed errors at
`internal/cli/update_db.go:75-77`, `internal/scanner/npm/scanner.go:148-150`.

### S7. Hardcoded version gating for pack min-version
- [ ] Derive `currentVersion` from the real binary version (ldflags), not a literal.
- [ ] Make `compareVersions` handle pre-release/build metadata and malformed input safely.

**Evidence:** `internal/enterprise/metadata.go:50-52` hardcodes `"0.1.0"`;
`compareVersions` (`:61-74`) ignores pre-release and treats malformed as `0.0.0`.

---

## P4 — Ecosystem breadth & release maturity

### S8. Go & Cargo are metadata-only
- [ ] Add artifact download + content static analysis for Go and Cargo (currently only
      age + OSV + yanked), and make them first-class policy ecosystems.

**Evidence:** `internal/scanner/golang/scanner.go:142,229`,
`internal/scanner/cargo/scanner.go:148,241`; policy models npm/pypi only
(`internal/policy/policy.go:49-56,125`).

### S9. PyPI lockfile parsers are stubs
- [ ] Implement poetry.lock, uv.lock, Pipfile(.lock), conda environment.yml parsing.

**Evidence:** `internal/deps/python/poetry.go:6,10,14,18,22` all return
"designed but not implemented in this milestone," despite being referenced in
`internal/ci/scan.go:403,427`.

### M1. CI / release pipeline gaps
- [ ] Add `go vet`, `golangci-lint`, `-race`, and a coverage gate to CI.
- [ ] Add a multi-OS matrix (Windows/macOS code paths are never tested).
- [ ] Sign release artifacts and publish checksums + SLSA provenance.

**Evidence:** `.github/workflows/ci.yml` runs `go test -v ./...` + self-scan only;
`.github/workflows/release.yml` uses GoReleaser with no signing/provenance configured.
Unix-only sandbox but CI is `ubuntu-latest` only. **Impact:** an unsigned-binary
supply-chain tool is itself a supply-chain gap.

### M2. Test coverage breadth
- [ ] Add tests for `internal/intel/osv/*`, the report exporters
      (`siem/servicenow/azure_devops/sarif/html/csv/markdown/evidence_pack`), and the
      sandbox behavior heuristics.

**Evidence:** ~36 `_test.go` for 166 source files; listed subsystems have no/light tests.

### M3. Stale README
- [ ] Update README "Notes" (claims no external modules / no SQLite — both now false) and
      align the maturity statement with current capabilities.

---

## Already shipped (this hardening effort)

- Constant-time bearer-token compare — `internal/api/server.go` (branch
  `security/consttime-token-csv-redaction`, PR #1).
- CSV report secret redaction via `registry.RedactSecrets` + test coverage (PR #1).
- Zip-extraction actual-bytes cap (defense in depth) + regression tests —
  `internal/registry/pypi/artifacts.go` (branch `security/extractzip-byte-cap`, PR #2).
- Pre-existing extraction hardening in the working tree: symlink/hardlink rejection and
  stricter `cleanArchivePath` (Windows drive letters, UNC, absolute paths).

---

## Suggested milestones

1. **"Honest security" (P0):** B1 + B2 + B3 — make signed packs real, stop DB overwrite,
   either isolate or relabel the sandbox. Gate any "secure"/"firewall" marketing on this.
2. **"Trustworthy data" (P1):** S1 + S2 — fail closed on OSV, real advisory sync/bundle.
3. **"Safe to operate" (P2/P3):** S3–S7 — API hardening, parallelism, logging, no fail-open.
4. **"Breadth & shipping" (P4):** S8 + S9 + M1–M3 — Go/Cargo depth, lockfiles, CI/release, docs.
