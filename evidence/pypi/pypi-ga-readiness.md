# PyPI GA Readiness — Loop 8 Evidence (PyPI Production Depth)

- Date: 2026-07-02T16:02:06Z
- Branch: `loop-08-pypi-production-depth`
- Implementation commit: `cbd391c`
- Scope: Loop 8 of the loop-engineering roadmap — "improve Python dependency
  and artifact coverage while keeping PyPI preview until readiness gates pass."

## Verdict

**Recommendation: promote PyPI from "preview" to "preview (GA-candidate)".
Do not claim GA yet.** Inventory and static artifact analysis are now
npm-comparable in depth and pass calibration on real packages, but three
named gates (below) remain open. The GA flip should be its own future loop
that closes those gates and re-runs this evidence.

## What changed in Loop 8

### Dependency inventory depth (`internal/deps/python`)

| Capability | Before Loop 8 | After Loop 8 |
|---|---|---|
| poetry.lock / uv.lock parsing | Naive line scan; keys in sub-tables (`[package.dependencies]`, `[package.source]`) could clobber name/version | Table-aware; sub-tables isolated |
| uv.lock project self-entry | Scanned against PyPI under the project's own name (bogus target, dependency-confusion noise) | Marked `local_source`, skipped with a stderr note |
| git / direct-URL lock sources | Scanned as if they were the same-named PyPI package (wrong artifact) | Recorded as `direct_url`; CI surfaces them as UNKNOWN (fail closed) |
| Lockfile-recorded hashes | Ignored | Captured (poetry `files`, uv `wheels`/`sdist`, Pipfile.lock `hashes`, requirements `--hash`) |
| Explicit registries | Ignored | Captured (uv `source.registry`, poetry `[package.source] url`, Pipfile.lock index-name→URL) |
| requirements.txt continuations | `--hash` continuation lines mis-parsed as separate entries | Backslash continuations joined; `pip-compile --generate-hashes` layout parses correctly |
| PEP 508 `name @ url` | Name absorbed the URL (garbage scan target) | Name + `direct_url` split; bare URL/path lines rejected |
| Name normalization | Lowercase only (`Foo_Bar` ≠ `foo-bar`) | PEP 503 canonical (`[-_.]+` → `-`) plus name validation |
| Multi-file inventory | Every file's entries scanned independently (same package scanned 2-4×) | `Dedupe()`: one target per `name@version`; unpinned manifest entries collapse into their lockfile pin and keep direct provenance |
| Pipfile / Pipfile.lock in `ci scan` | Parsers existed but files were never discovered | Discovered and ecosystem-detected |
| Direct vs transitive | Every finding hardcoded `direct: true` | `direct` reflects manifest provenance; lockfile-only entries are transitive |

### Artifact inspection depth (`internal/analyzer/pypi`)

New structural checks (all rule-backed in `policy.Default()` and
`default-policy.yaml`):

| Finding | Severity/score | Signal |
|---|---|---|
| `pypi_compiled_bytecode_payload` | high / 40 | `.pyc`/`.pyo` shipped without matching `.py` source (payload hidden from source review) |
| `pypi_wheel_record_missing` | medium / 25 | Wheel lacks its `.dist-info/RECORD` manifest |
| `pypi_wheel_record_unlisted_files` | high / 35 | Extracted wheel files not declared in RECORD (smuggled files); scoped per artifact so the sdist extracted alongside is not misflagged |
| `pypi_in_tree_build_backend` | high / 45 | PEP 517 `backend-path`: build backend loaded from code inside the package — arbitrary code at build time regardless of declared backend name |
| `pypi_build_requires_direct_reference` | high / 60 | `[build-system] requires` pulls code from a direct URL/VCS reference instead of the index |

Also: wheel `{name}-{version}.data/scripts/` files are now analyzed as
install execution surfaces (they land on PATH), and `[build-system]` parsing
is section-aware (keys with the same names in other TOML tables are ignored).

### Calibration fix found by Loop 8 validation

`click==8.1.7` (healthy, top-tier package) **false-blocked at score 100**
before this loop: its sdist ships 11 example `setup.py` files and each scored
`pypi_setup_py_present` (11 × 15, clamped). Only the artifact-root
`setup.py`/`pyproject.toml` participates in build/install; nested
example/test manifests are inert. After gating to install-root manifests:
`click==8.1.7` → ALLOW, score 20. This extends the Loop 1 lesson (score only
install surfaces) from file content to file position.

## Validation evidence

### Test suites (2026-07-02, local, Go 1.25.2 darwin/arm64)

- `go vet ./...` — clean.
- `go test ./...` — full suite green (includes 6 new parser depth tests,
  7 new analyzer artifact-depth tests, 1 new hermetic CI inventory test).
- `go test -race` on `internal/ci`, `internal/deps/python`,
  `internal/analyzer/pypi`, `internal/scanner/pypi`, `internal/policy`,
  `internal/risk` — green.
- Detection corpus (`pkgsafe test corpus --json`): dependency precision 1.0,
  recall 1.0, direct/transitive recall 1.0, source-import recall 1.0,
  false_warn_rate 0, false_block_rate 0, critical_detection_rate 1.0.
- Hermetic-test hardening: PyPI CI tests now isolate the home-keyed artifact
  cache (`t.Setenv("HOME", tmp)`); a cross-package cache collision on
  same-named fixture tarballs was observed and eliminated.

### Live registry scans (real PyPI, 2026-07-02)

| Package | Result | Notes |
|---|---|---|
| `requests==2.31.0` | BLOCK 100 | Correct: real advisories (GHSA-9hjg-9r4m-mvj7 malware indicator + 2 high CVEs); root setup.py shell-exec finding; wheel RECORD checks produced **no** false positives on a real wheel |
| `flask` (3.1.3) | ALLOW 0 | `flit_core.buildapi` recognized; no new-finding false positives |
| `click` (8.4.2) | ALLOW 20 | missing_license + new_package only |
| `click==8.1.7` | ALLOW 20 (was BLOCK 100) | Calibration fix above |
| `httpx` | ALLOW 0 | **Gate 1 observed:** default resolution selected `1.0.dev3` (a pre-release pip would not install) |
| `numpy` | scan error | **Gate 2 observed:** "artifact has too many files" (MaxExtractedFiles=5000); CI surfaces as UNKNOWN, direct scan fails hard |

### Live `ci scan --ecosystem pypi` (fixture repo: pyproject.toml + uv.lock)

Fixture: `demo-app` (virtual root) + `click 8.1.7` (registry, also in
pyproject) + `patched-lib` (git source). Result:

- `demo-app` skipped ("local project or path source in uv.lock") — the
  project itself is no longer scanned against PyPI.
- `click 8.1.7` scanned **once** (dedup verified by registry hit count in
  the hermetic test), `direct: true` (manifest provenance), ALLOW 20.
- `patched-lib 1.0.0` → decision `unknown`, `direct: false`, reason
  `direct_url_dependency_not_scanned` (fail closed).
- Overall decision: allow; summary `{scanned: 2, allow: 1, unknown: 1}`.

## Remaining gates before a PyPI GA claim

1. **pip-parity version resolution.** Default resolution can select
   pre-releases (`httpx` → `1.0.dev3`) where `pip install` would pick the
   latest stable. A GA scanner must scan what pip would install.
2. **Large-artifact handling.** Packages exceeding extraction caps
   (numpy: >5000 files) fail as unscannable. Fail-closed is correct, but GA
   needs either raised/streaming caps or a documented partial-scan mode so
   the top of PyPI by downloads is actually scannable.
3. **Real-repo benchmark.** Run the existing benchmark harness
   (`pkgsafe test benchmark --repo-list`) against a Python repo corpus
   (poetry/uv/Pipfile projects) and record false-positive/negative rates,
   as was done for npm before its GA.

Non-gating known limitations (documented in `docs/known-limitations.md`):
conda `environment.yml` unimplemented; no behavior execution for Python
packages (static analysis only); `ci scan` requires `--ecosystem pypi` (the
npm lockfile default short-circuits auto-detection).

## Loop summary

- **Built:** table-aware lock parsing, hash/registry/source capture,
  inventory dedup with direct/transitive honesty, direct-URL fail-closed
  handling, orphaned-bytecode + wheel RECORD + data-scripts checks,
  section-aware build-system risk (backend-path, direct-URL requires),
  5 new policy rules, Pipfile discovery in CI.
- **Reused:** existing `[[package]]` scan loop shape, `ParseRequirementSpec`,
  install-surface calibration principle from Loop 1, `parallelScan`/
  `DecisionUnknown` fail-closed plumbing from the S4/S5 work, hermetic
  httptest registry pattern from `TestCI_RunScan_PyPI`.
- **Fixed:** nested-manifest false block (click 8.1.7), uv.lock project
  self-scan, `pkg @ url` name corruption, hash-line mis-parse, CI test cache
  collision.
- **Deferred:** the three GA gates above; per-dependency registry routing
  from lockfile-recorded registries into the scanner; using recorded hashes
  to cross-check downloaded artifacts (needs per-version hash indexing).
- **Tested:** full suite + race + corpus + live scans as recorded above.
