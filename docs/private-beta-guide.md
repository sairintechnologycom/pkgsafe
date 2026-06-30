# PkgSafe Private Beta Guide

PkgSafe private beta is strongest for npm dependency scanning, OSV vulnerability checks, dependency inventory, policy gates, CI outputs, and evidence generation.

## Positioning

- npm has the deepest artifact, lifecycle-script, inventory, and policy coverage.
- PyPI, Go, and Cargo support are available for early validation, but they are not npm-equivalent yet.
- Behavior analysis defaults to `disabled`.
- `heuristic` behavior mode runs lifecycle scripts on the host and is not containment.
- `isolated` behavior mode reports unavailable until a real isolation backend lands.

## Real Repo Validation

Create a repo list from `benchmarks/real-repos.example.json`, then run:

```bash
make build

./dist/pkgsafe update-db --ecosystem all
./dist/pkgsafe db status

./dist/pkgsafe test benchmark \
  --repo-list benchmarks/real-repos.json \
  --json | tee real-repo-benchmark.json

./dist/pkgsafe test production-readiness \
  --repo-list benchmarks/real-repos.json \
  --json | tee production-readiness-real-repos.json

./dist/pkgsafe report beta-evidence \
  --repo-list benchmarks/real-repos.json \
  --output pkgsafe-private-beta-evidence.zip
```

Use `expected_max_false_warn_rate` as a ratio between `0` and `1`. For example,
`0.10` means 10%, and monorepo or more complex repo validation can use `0.15`.
Do not use percentage-style values like `10`.

Batch 1 private beta readiness target:

```json
{
  "private_beta_ready": true,
  "ga_ready": false,
  "production_ready": false,
  "real_repo_validation_count": 3,
  "scanner_crash_count": 0,
  "false_block_count": 0
}
```

Inspect the important fields quickly:

```bash
jq '.real_repo_validation_count, .scanner_crash_count, .false_block_count, .ga_ready, .production_ready' production-readiness-real-repos.json

jq '.summary, .aggregate, .repo_validations[] | {name, scan_completed, warn_count, block_count, false_warn_count, false_block_count, failures}' real-repo-benchmark.json

jq '.. | objects | select(has("decision") and .decision=="warn")' real-repo-benchmark.json
```

Private beta evidence should include real repositories, but GA requires a larger threshold. Current GA blockers are surfaced directly in `production-readiness --json`.

## Private Beta Defaults

Use:

```yaml
sandbox:
  behavior_mode: disabled
```

Only use `--behavior heuristic` in disposable environments. Do not enable heuristic behavior analysis automatically for CI or AI-agent workflows.
