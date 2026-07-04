# pkgsafe v1.6.0 Release Verification

- Tag: `v1.6.0` (commit `1ad1393`)
- Published: 2026-07-04 (draft verified before publish)
- Scope: PyPI GA — all three gates from `evidence/pypi/pypi-ga-readiness.md`
  closed (PR #35, merge `38f33dd`). First post-roadmap release.

## What shipped

- **pip-parity version resolution:** in-repo PEP 440 parser/ordering
  (`internal/registry/pypi/pep440.go`, no new dependency) mirroring pip's
  `packaging` sort key. Default resolution picks the highest stable
  release; pre-releases only when explicitly pinned or when no stable
  release exists. httpx resolves 0.28.1 instead of 1.0.dev3.
- **Large-artifact handling:** PyPI extraction budgets raised
  5,000 files / 100 MiB → 40,000 files / 2 GiB per artifact (sized from
  measured top-of-PyPI artifacts with 2-3x headroom), still fail-closed;
  artifact downloads move to a 15-minute client (was the 20-second
  metadata timeout) with a new 4 GiB on-disk cap (previously unbounded).
  Zip-bomb defenses retained; readiness-gate fixtures re-sized past the
  new caps (forged-central-directory bomb).
- **Real-repo benchmark:** six pinned real Python repos (poetry, pydantic,
  pipenv, flask, requests, httpx) covering every supported
  manifest/lockfile format pass 6/6 with zero false blocks. Fixed the
  benchmark Python inventory to mirror `ci scan` (dedup, local-source
  skip, manifest-provenance direct/transitive).
- Docs flipped to "npm and PyPI GA; Go and Cargo preview".
- Evidence: `evidence/pypi/pypi-ga-gates-closed.md`,
  `evidence/pypi/python-real-repo-benchmark.json`.

## Verification ritual results

| Check | Result |
|---|---|
| All assets downloaded (archives, SBOMs, checksums, sig, pem) | PASS (15 assets) |
| `shasum -a 256 -c checksums.txt` | PASS (12/12 OK, 0 failures) |
| `cosign verify-blob` (checksums.txt, GitHub OIDC identity) | PASS (`Verified OK`) |
| `gh attestation verify` (darwin_arm64 archive) | PASS (exit 0) |
| Binary version self-report | PASS (`pkgsafe 1.6.0 (1ad1393)`) |
| GA behavior smoke test (released binary) | PASS (httpx → 0.28.1 allow; numpy → 2.5.0 warn 30) |
| Publish gate | Published after all checks passed |

## CI at merge

PR #35: Build & Test PASS, Isolated Behavior Backend E2E (Linux) PASS,
PkgSafe Package Gate Self-Scan PASS.
