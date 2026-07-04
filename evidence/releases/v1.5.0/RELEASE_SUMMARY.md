# pkgsafe v1.5.0 Release Verification

- Tag: `v1.5.0` (commit `c6575b5`)
- Published: 2026-07-04 (draft verified before publish)
- Scope: Loop 10 — isolated behavior backend promoted from experimental to
  supported, CI-validated Linux isolation (PR #34). Final roadmap loop.

## What shipped

- `--behavior isolated` is now a supported Linux backend: lifecycle scripts
  execute as uid 65534 inside bubblewrap user/mount/pid/ipc/uts/cgroup/network
  namespaces with a cleared environment, fixed `PATH`, synthetic
  `/etc/passwd`/`/etc/group`, read-only system mounts, and in-sandbox
  `ulimit` caps. Network is disabled by default and enforced via an unshared
  network namespace; `network_mode=host` is an explicit opt-in.
- Fixed: the experimental runner passed an invalid `--rlimit-nofile` flag to
  bwrap, so every real isolated run had failed while `available: true` was
  still reported; behavior-analysis runs that fail to execute are no longer
  silently dropped (per-script `error` field); teardown force-removes
  hostile `chmod 000` directories.
- New CI job `isolated-behavior-e2e` proves isolation on a real kernel with
  `PKGSAFE_REQUIRE_ISOLATED_E2E=1` (fails instead of skipping): loopback
  connect blocked by default, host-mode positive control, host HOME
  invisible, environment cleared, hostile-teardown cleanup, canary findings
  end-to-end. Evidence: `evidence/loops/loop-10-isolated-behavior-backend.md`.
- Behavior analysis remains disabled by default; heuristic mode is still
  never described as sandboxing.

## Verification ritual results

| Check | Result |
|---|---|
| All assets downloaded (archives, SBOMs, checksums, sig, pem) | PASS |
| `shasum -a 256 -c checksums.txt` | PASS (12/12 OK, 0 failures) |
| `cosign verify-blob` (checksums.txt, GitHub OIDC identity) | PASS (`Verified OK`) |
| `gh attestation verify` (darwin_arm64 archive) | PASS (exit 0) |
| Binary version self-report | PASS (`pkgsafe 1.5.0 (c6575b5)`) |
| Publish gate | Published manually after all checks passed |
