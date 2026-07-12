# Loop 04 - Genuine External Repository Validation

Date: 2026-07-12  
Status: accepted

## Feature result

Loop 04 closes the external-repository evidence gap by validating PkgSafe
against a pinned corpus of genuine public repositories.

Corpus used for the authoritative run:

- 9 npm repositories
- 6 PyPI repositories
- 15 total external repositories
- pinned to specific commit SHAs under `/private/tmp/pkgsafe-loop4`

Representative corpus entries:

- `expressjs/express@ba006766fb964571723138708eacaba0f55759cd`
- `axios/axios@7a6615e421578081743161eab032d009dc6583a4`
- `vitejs/vite@c961cae2868cc1521457ec60583867f0440e6949`
- `pnpm/pnpm@3acb421adf48deeaf3497eaff8fb9806f05bec3c`
- `npm/cli@7b1f6c173d17b3bf30e45426f6df39473c6a1163`
- `pydantic/pydantic@f59e929c999e8b2efc7b12fd0bc1685c1a186be3`
- `python-poetry/poetry@f46702336862f30050d5c641d5ed6f7568ded793`
- `pypa/pipenv@fbce7b4ff5be762cef1b5b88afc5bb4230a759de`
- `encode/httpx@b5addb64f0161ff6bfe94c124ef76f6a1fba5254`
- `vercel/next.js@1bd2fd585aac793ca2589e6f18f17a412fd11005`

## Validation command

```text
go run ./cmd/pkgsafe test benchmark --repo-list /private/tmp/pkgsafe-loop4/real-repos.external.with-artifacts.json --json
```

## Observed benchmark result

The run completed successfully and reported:

- `pass: true`
- `status: PRIVATE_BETA_ACCURACY_CANDIDATE`
- `real_repo_validation_count: 15`
- `repos_passed: 15`
- `repos_failed: 0`
- `false_block_count: 0`
- `false_warn_count: 0`
- `scanner_crash_count: 0`
- `network_failure_count: 0`
- `real_repo_timing_trustworthy: true`

Artifact generation for the 15 external repositories:

- `json_output_generated_count: 15`
- `sarif_output_generated_count: 15`
- `markdown_summary_generated_count: 15`
- `evidence_pack_generated_count: 15`

Ecosystem distribution:

- `npm_repo_count: 9`
- `pypi_repo_count: 6`

Timing:

- `average_scan_duration_ms: 658`
- `p95_scan_duration_ms: 777`
- `real_repo_scan_duration_avg_ms: 1124`
- `real_repo_scan_duration_p95_ms: 1611`
- `total_runtime_ms: 33328`

Decision mix observed in the external corpus:

- `allow` decisions on smaller npm and PyPI repositories
- `warn` decisions on some npm repositories
- `block` decisions on larger npm repositories such as `next.js`, `pnpm`, `npm/cli`, `vite`, and `axios`

Those `block` decisions were not treated as false blocks because the external
corpus run was observational and carried no false-block expectation metadata.

## Notes

- The repo list lives outside the tracked workspace because it is an
  environment-specific validation corpus.
- The run exercised the full artifact path, including SARIF and evidence-pack
  generation, so the evidence now covers output portability as well as scan
  accuracy.
- The validation remained offline with respect to registry and advisory lookups
 during the scan itself because the repositories were scanned from local
 checkouts.

## Completion gate

| Gate | State |
| --- | --- |
| PSR-004 | CLOSED |
| real external repositories | 15 |
| false blocks | 0 |
| scanner crashes | 0 |
| timing reported | PASS |
| evidence complete | PASS |
