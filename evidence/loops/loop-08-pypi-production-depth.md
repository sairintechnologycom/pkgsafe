# Loop 08 - PyPI Production Depth

Date: 2026-07-01
Branch: loop-08-pypi-production-depth
Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/25

## Feature Spec

Improve Python package scanning depth enough to prepare for a future PyPI GA decision. This loop did not promote PyPI to GA. PkgSafe remains npm-first GA, with PyPI marked preview.

## Files Changed

Loop 8 changes:

- `default-policy.yaml`
- `docs/known-limitations.md`
- `internal/analyzer/pypi/analyzer.go`
- `internal/analyzer/pypi/analyzer_test.go`
- `internal/analyzer/pypi/patterns.go`
- `internal/deps/python/parser_test.go`
- `internal/deps/python/poetry.go`
- `internal/policy/policy.go`
- `internal/types/types.go`
- `evidence/loops/loop-08-pypi-production-depth.md`

The branch is stacked on uncommitted Loop 1-7 work, which was preserved and reused.

## Already Implemented And Reused

- Existing PyPI scanner, metadata client, OSV lookup, and artifact extraction.
- Existing requirements.txt parser.
- Existing pyproject.toml parser.
- Existing setup.py risk detection.
- Existing pyproject build-backend analysis.
- Existing wheel/sdist extraction and hash verification.
- Existing JSON/SARIF/Markdown output plumbing for scan findings.
- Existing benchmark and corpus validation commands.

## Newly Implemented

- Implemented `poetry.lock` dependency parser.
- Implemented `uv.lock` dependency parser.
- Implemented `Pipfile` dependency parser.
- Implemented `Pipfile.lock` dependency parser.
- Added scored PyPI static-analysis rules:
  - `pypi_eval_exec_usage`
  - `pypi_base64_exec_payload`
  - `pypi_network_call`
  - `pypi_credential_path_access`
  - `pypi_env_secret_access`
  - `pypi_cloud_metadata_access`
  - `pypi_native_extension`
- Added native extension artifact metadata: `artifact_analysis.native_extension`.
- Added static Python source checks for eval/exec/compile, base64 decode plus exec, network calls, credential path access, environment secret access, cloud metadata endpoints, and native extensions.
- Added tests for lockfile parsing and static PyPI risk findings.
- Documented PyPI preview caveats and supported dependency formats in `docs/known-limitations.md`.

## Validation Commands Run

```bash
gofmt -w internal/analyzer/pypi/analyzer.go internal/analyzer/pypi/patterns.go internal/analyzer/pypi/analyzer_test.go internal/deps/python/poetry.go internal/deps/python/parser_test.go internal/types/types.go internal/policy/policy.go
go test ./internal/analyzer/pypi ./internal/deps/python ./internal/scanner/pypi ./internal/policy
go test ./...
go test -race ./...
go vet ./...
make build
make package
./dist/pkgsafe policy validate default-policy.yaml
./dist/pkgsafe test corpus --json
./dist/pkgsafe test benchmark --offline --json
ruby -e 'text = File.read("docs/known-limitations.md"); links = text.scan(/\[[^\]]+\]\(([^)]+)\)/).flatten.reject { |href| href.start_with?("http", "#") }; links.each { |href| path = href.split("#", 2).first; next if path.empty?; full = File.expand_path(path, "docs"); abort("missing link: #{href}") unless File.exist?(full) }; puts "links ok"'
! rg -n "secure sandbox|secure containment|full PyPI|PyPI GA|PyPI production|SaaS|billing|SSO|hosted service|behavior analysis enabled by default" internal/analyzer/pypi internal/deps/python internal/policy/policy.go default-policy.yaml docs/known-limitations.md
```

## Test Results

- Focused PyPI analyzer/dependency/scanner/policy tests: pass
- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `make build`: pass
- `make package`: pass
- `policy validate default-policy.yaml`: pass
- Corpus validation: pass
- Offline benchmark: pass
- `docs/known-limitations.md` link check: pass
- Wording audit: pass. The only `PyPI GA` wording is an explicit caveat stating there is no PyPI GA claim.

## Sample Evidence

Focused test coverage:

```text
ok   github.com/niyam-ai/pkgsafe/internal/analyzer/pypi
ok   github.com/niyam-ai/pkgsafe/internal/deps/python
ok   github.com/niyam-ai/pkgsafe/internal/scanner/pypi
ok   github.com/niyam-ai/pkgsafe/internal/policy
```

Default policy validation:

```text
Policy is valid.
```

Corpus validation summary:

```json
{
  "dependency_precision": 1,
  "dependency_recall": 1,
  "false_block_rate": 0,
  "critical_detection_rate": 1
}
```

Offline benchmark summary:

```json
{
  "pass": true,
  "status": "PRIVATE_BETA_ACCURACY_CANDIDATE",
  "online_benchmark": {
    "mode": "offline",
    "status": "skipped_offline"
  }
}
```

## Review Loop

- PyPI dependency inventory is broader: requirements, pyproject, Poetry lock, uv lock, Pipfile, and Pipfile.lock.
- PyPI static analysis is materially deeper without executing setup/build hooks.
- Findings flow through existing scan result structures, so JSON/SARIF/Markdown output paths can surface them.
- PyPI remains preview and is not described as npm-equivalent.
- Known-good online PyPI validation could not be performed in this sandbox because live PyPI DNS/network access was unavailable.

## Learning Loop

- The biggest missing parser gaps were `poetry.lock`, `uv.lock`, and `Pipfile.lock`.
- Static Python package risk needs explicit rule IDs rather than only adding suspicious strings, so policies and reports remain explainable.
- Native extension detection is useful but should remain conservative until more real-repo validation exists.
- PyPI GA needs connected benchmark evidence, real-repo depth, and lower-noise validation on known-good Python packages.

## Known Limitations

- PyPI remains preview.
- Behavior execution remains disabled by default and was not added for PyPI.
- Lockfile parsers are intentionally lightweight and cover common deterministic fields rather than every possible TOML/JSON edge case.
- `scan-python-deps` live CLI sample failed in this environment because PyPI DNS/network access was unavailable; unit tests and offline benchmark passed.
- Real connected PyPI benchmark should be rerun in an environment with registry access before any GA decision.
- The branch remains stacked on uncommitted Loop 1-7 changes.

## Completion Criteria

- PyPI depth materially improved: complete.
- PyPI caveats documented: complete.
- All required validation commands pass: complete.
- No PyPI GA promotion claim: complete.
