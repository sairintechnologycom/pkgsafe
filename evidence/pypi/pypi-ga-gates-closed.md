# PyPI GA Gates Closed — GA Flip Evidence

- Date: 2026-07-04
- Baseline: `evidence/pypi/pypi-ga-readiness.md` (Loop 8) named three gates
  that had to close before a PyPI GA claim. This document records the closure
  of all three and the promotion of PyPI from "Preview (GA-candidate)" to GA.
- Environment: Go 1.25.x darwin/arm64, live PyPI registry scans on 2026-07-04.

## Gate 1 — pip-parity version resolution: CLOSED

**Was:** default resolution picked whatever sorted highest under
Masterminds semver with a raw-string fallback, so PEP 440 dev/pre-releases
that fail semver parsing won by string comparison (`httpx` resolved
`1.0.dev3`, a version pip would never install by default).

**Now:** `internal/registry/pypi/pep440.go` implements PEP 440 parsing and
ordering (epoch, release, dev/a/b/rc/final/post ranking, normalization
aliases `alpha|beta|c|pre|preview|rev|r`, `v` prefix, `-N` post form,
epoch `N!`, local `+…`), mirroring the sort key of pip's `packaging`
library. `ResolveVersion` default selection now takes the highest stable
release; pre-releases are selected only when explicitly pinned or when no
stable release exists (pip behavior). Yanked handling is unchanged
(non-yanked preferred, yanked fallback).

**Verified:**
- Unit: PEP 440 parse table, strict ascending-order chain
  (`1.0.dev1 < 1.0a1.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1 <
  1!0.5`), normalization equivalences (`1.0 == 1.0.0`, `rc == c`,
  `post1 == -1`), httpx-shaped regression fixture, pre-release-only
  package fallback, explicit pre-release pin, CalVer ordering
  (`2024.10 > 2024.2`).
- Live: `scan-pypi-package httpx` → **0.28.1 allow 0** (was `1.0.dev3`).

## Gate 2 — large-artifact handling: CLOSED

**Was:** `MaxExtractedFiles=5000`, `MaxExtractedBytes=100 MiB`, and a
20-second whole-body HTTP timeout on artifact downloads. numpy (sdist:
8,204 files) failed as unscannable; scipy (5,075 files / 109 MiB) failed
both caps; tensorflow (213 MiB download, 1,080 MiB uncompressed) could not
even download.

**Measured (top of PyPI, 2026-07):** numpy sdist 8,204 files / 64 MiB;
scipy sdist 5,075 files / 109 MiB; tensorflow wheel 12,194 files /
1,080 MiB; torch wheel 12,532 files / 361 MiB.

**Now:** extraction budgets raised to **40,000 files / 2 GiB uncompressed
per artifact** (~2-3x headroom over the measured top of PyPI); artifact
downloads use a dedicated HTTP client with a 15-minute budget instead of
the 20-second metadata timeout, plus a new **4 GiB download cap**
(`MaxDownloadBytes`, enforced against both `Content-Length` and actual
bytes on disk — the previous `io.Copy` was unbounded). Everything remains
fail-closed: over-budget artifacts are reported unscannable, never
partially scanned. Zip-bomb defenses retained and re-verified at the new
budgets (extraction budget checks are parameterized so tests exercise the
same code path with small budgets; the alpha/rollout readiness gate
fixtures were re-sized to exceed the new caps, including a
forged-central-directory bomb replacing the old 101 MiB honest-content
fixture).

**Verified live (scan-pypi-package, real PyPI):**

| Package | Before | After |
|---|---|---|
| numpy 2.5.0 | scan error (too many files) | **warn 30** (10.6s) |
| scipy 1.18.0 | would fail both caps | **warn 45** |
| pandas 3.0.3 | ok | allow 10 |
| tensorflow 2.21.0 | download timeout + byte cap | **allow 20** (29.5s incl. 213 MiB download + 1 GiB extraction) |

Alpha readiness gate (`security_extraction`) green after fixture re-size;
full validation suite green.

## Gate 3 — real-repo Python benchmark: CLOSED

**Corpus:** six real open-source Python repositories, shallow-cloned and
pinned, covering every supported manifest/lockfile format:

| Repo | Pin | Formats |
|---|---|---|
| python-poetry/poetry | `f467023` | poetry.lock + pyproject |
| pydantic/pydantic | `c9688f4` | uv.lock + pyproject |
| pypa/pipenv | `fbce7b4` | Pipfile + Pipfile.lock |
| pallets/flask | `36e4a82` | uv.lock + pyproject |
| psf/requests | `23953c0` | setup.py + requirements-dev.txt |
| encode/httpx | `b5addb6` | requirements.txt + pyproject |

Repo-list spec: `benchmarks/python-real-repos.example.json` (replace
`<corpus-dir>` with the clone directory). Full JSON output:
`evidence/pypi/python-real-repo-benchmark.json`.

**Defect found and fixed by this gate (the reason the gate existed):**
the benchmark's Python inventory path (`scanBenchmarkInventory`) predated
Loop 8 — it parsed each dependency file independently, hardcoded
`Direct: true`, and never deduped, so lockfile-heavy repos reported every
transitive dependency as direct (poetry: 175 direct / 0 transitive). It
now mirrors the `ci scan` inventory: `pydeps.Dedupe`, local/self lock
entries skipped, direct vs transitive from manifest provenance. After the
fix: poetry 30 direct / 74 transitive, pydantic 8 / 188, pipenv 50 / 69,
flask 30 / 73, requests 7 / 0, httpx 27 / 0.

**Results (`pkgsafe test benchmark --repo-list …`):** pass=true; 6/6 repos
passed; 25/25 fixture + known-good packages passed; known-good false block
rate 0; false warn rate 0.10 (within threshold, unchanged from npm GA
baseline); critical fixture block rate 1.0; dependency inventory
precision/recall 1.0; real-repo false blocks 0, false warns 0; timing
trustworthy (avg 29 ms, p95 35 ms per repo inventory).

## GA flip

- `README.md`: PyPI row → GA; GA scope statements now "npm and PyPI".
- `docs/known-limitations.md`: PyPI GA with remaining limitations stated
  (fail-closed above 40k files / 2 GiB, conda stub, static-only, explicit
  `--ecosystem pypi`).
- `docs/feedback.md`, `docs/release-verification.md`: preview lists now
  Go/Cargo only.

## Deferred (unchanged, non-gating)

- Per-dependency registry routing from lockfile-recorded registries.
- Using lockfile-recorded hashes to cross-check downloaded artifacts.
- conda `environment.yml`; Python behavior execution; npm extraction caps
  left at 5000/100 MiB (npm artifacts do not approach them).
