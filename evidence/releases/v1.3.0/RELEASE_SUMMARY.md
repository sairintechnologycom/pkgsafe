# pkgsafe v1.3.0 Release Verification

- Tag: `v1.3.0` (commit `b067dff`)
- Published: 2026-07-03T04:06:27Z (draft verified before publish)
- Release workflow run: 28604218770 (completed, success, 4m23s)
- Scope: Loop 8 — PyPI Production Depth (PR #32, merge `4b7fde6`).
  See `evidence/pypi/pypi-ga-readiness.md` for the feature evidence.

## What shipped

- PyPI inventory depth: table-aware poetry.lock/uv.lock parsing, lockfile
  hash/registry/source capture, requirements `--hash` + continuation +
  PEP 508 direct-reference handling, Pipfile.lock hashes and index
  resolution, PEP 503 name canonicalization, inventory dedup, Pipfile
  discovery in `ci scan`, direct URL/VCS deps surfaced as UNKNOWN,
  honest direct/transitive marking.
- New artifact findings: orphaned compiled bytecode, wheel RECORD
  missing/unlisted-files, in-tree build backend (`backend-path`),
  direct-URL build requirements; wheel `*.data/scripts/` treated as an
  install execution surface.
- Calibration fix: nested example/test manifests no longer score
  (click 8.1.7: BLOCK 100 → ALLOW 20).

## Verification ritual results

| Check | Result |
|---|---|
| All 15 assets downloaded (archives, SBOMs, checksums, sig, pem) | PASS |
| `shasum -a 256 -c checksums.txt` | PASS (12/12 OK, 0 failures) |
| `cosign verify-blob` (checksums.txt, GitHub OIDC identity) | PASS (`Verified OK`) |
| `gh attestation verify` (darwin_arm64 and linux_amd64 archives) | PASS (exit 0) |
| Binary version self-report (`pkgsafe version` from darwin_arm64 archive) | PASS (`pkgsafe 1.3.0 (b067dff)`) |
| Publish gate | Published manually after all checks passed |

## Notes

- Version self-report matches the tag and release commit — the v1.0.x
  ldflags-module-path defect remains fixed and is checked every release.
- PyPI documentation status changed from "Preview" to
  "Preview (GA-candidate)". No GA claim is made; the three open gates are
  recorded in `evidence/pypi/pypi-ga-readiness.md`.
