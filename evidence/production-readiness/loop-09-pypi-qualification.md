# Loop 9 — PyPI Qualification

Date: 2026-07-12

## Scope

- Validated PyPI against a separate external-repository subset from the real corpus used in Loop 4.
- Confirmed the readiness model records PyPI as public beta coverage, not GA.
- Corrected readiness vocabulary so it no longer implies npm GA in the ecosystem-depth status field.

## Validation corpus

- External PyPI repositories: 6
- Pinned SHAs from the validated corpus in `/private/tmp/pkgsafe-loop4`

Repositories used:

- `psf/requests`
- `pallets/flask`
- `pydantic/pydantic`
- `python-poetry/poetry`
- `pypa/pipenv`
- `encode/httpx`

## Validation commands

```bash
env GOCACHE=/private/tmp/pkgsafe-gocache go run ./cmd/pkgsafe test benchmark --repo-list /private/tmp/pkgsafe-loop4/real-repos.pypi-only.json --json
env GOCACHE=/private/tmp/pkgsafe-gocache go run ./cmd/pkgsafe test production-readiness --json --repo-list /private/tmp/pkgsafe-loop4/real-repos.pypi-only.json
```

## Benchmark result

- `pass: true`
- `status: PRIVATE_BETA_ACCURACY_CANDIDATE`
- `real_repo_validation_count: 6`
- `pypi_repo_count: 6`
- `npm_repo_count: 0`
- `false_block_count: 0`
- `scanner_crash_count: 0`
- `known_good_false_block_rate: 0`
- `real_repo_timing_trustworthy: true`
- `average_scan_duration_ms: 676`
- `p95_scan_duration_ms: 856`

## Readiness result

- Final status: `BLOCKED`
- `ecosystem_depth_status: npm-public-beta-pypi-public-beta-go-cargo-preview`
- The remaining blockers are GA release-verification gaps, not PyPI scanner regressions:
  - real repo count below GA threshold
  - signed release artifacts not verified locally
  - build provenance not verified locally

## Interpretation

PyPI is validated enough to stay at public beta, with separate external-corpus evidence and no false blocks or scanner crashes in the sampled set. The repository does not yet have evidence to promote PyPI to GA, and the readiness model correctly keeps it short of production trust.
