# pkgsafe v1.4.0 Release Verification

- Tag: `v1.4.0` (commit `d419ea6`)
- Published: 2026-07-03 (draft verified before publish)
- Scope: Loop 9 public half — offline intelligence bundle freshness
  reporting and hardening (PR #33). Signed-bundle workflows ship in the
  private enterprise distribution; see the Loop 9 evidence there.

## What shipped

- `db status --json` and `db verify-bundle --json` machine-readable reports.
- Verify-time freshness: `freshness_at_verify` per sync key plus an overall
  `stale` flag, re-evaluated at verification time instead of trusting the
  manifest's export-time freshness; `db status` warns on stale advisory data.
- Hardening: bundle reads bounded by file count (16) and total bytes (1 GiB),
  bundle kind + manifest schema version required, `import-bundle` refuses
  non-SQLite payloads.

## Verification ritual results

| Check | Result |
|---|---|
| All assets downloaded (archives, SBOMs, checksums, sig, pem) | PASS |
| `shasum -a 256 -c checksums.txt` | PASS (12/12 OK, 0 failures) |
| `cosign verify-blob` (checksums.txt, GitHub OIDC identity) | PASS (`Verified OK`) |
| `gh attestation verify` (darwin_arm64 archive) | PASS (exit 0) |
| Binary version self-report | PASS (`pkgsafe 1.4.0 (d419ea6)`) |
| Publish gate | Published manually after all checks passed |
