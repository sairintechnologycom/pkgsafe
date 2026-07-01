# Loop 4 - False-Positive Feedback Workflow Evidence

## Tracking

- Branch: `loop-04-false-positive-feedback`
- Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/21

## Files Changed

Loop 4 implementation:

- `cmd/pkgsafe/feedback.go`
- `cmd/pkgsafe/main.go`
- `internal/feedback/feedback.go`
- `internal/feedback/feedback_test.go`
- `docs/feedback.md`
- `.github/ISSUE_TEMPLATE/false_positive.yml`
- `evidence/loops/loop-04-false-positive-feedback.md`
- `evidence/loops/loop-04-scan.json`
- `evidence/loops/loop-04-feedback/npm-postinstall-curl-example-10059d15ee2b.json`
- `evidence/loops/loop-04-feedback/npm-postinstall-curl-example-10059d15ee2b.md`

Earlier Loop 1, Loop 2, and Loop 3 changes are also present in this working
branch because those loops are not yet committed or merged.

## Already Implemented And Reused

- Reused existing package scan JSON output shape.
- Reused existing `types.ScanResult`, `types.Reason`, behavior-analysis summary,
  registry evidence, and policy evidence fields.
- Reused existing `registry.RedactSecrets` sanitizer.
- Reused the existing false-positive issue template and feedback guide.

## Newly Implemented

- Added `pkgsafe feedback create`.
- Added local feedback JSON and sanitized Markdown issue body generation.
- Added stable finding fingerprints based on ecosystem, package, version,
  decision, risk score, and sorted rule IDs.
- Added feedback fields for package, ecosystem, version, rule IDs, decision,
  risk score, command used, sanitized finding output, user reason, private
  registry involvement, lifecycle-script involvement, behavior analysis, and
  PkgSafe version.
- Added default local export under `.pkgsafe/feedback/`, with configurable
  `--output-dir`.
- Added false-positive template fingerprint field.
- Added feedback docs for the local artifact workflow.

## Validation Commands

```text
gofmt -w .                                                                 PASS
go test ./internal/feedback ./cmd/pkgsafe                                  PASS
go test ./...                                                              PASS
go test -race ./...                                                        PASS
go vet ./...                                                               PASS
make build                                                                 PASS
./dist/pkgsafe scan-local-npm testdata/npm/postinstall-curl --json > evidence/loops/loop-04-scan.json  PASS
./dist/pkgsafe feedback create --input evidence/loops/loop-04-scan.json --output-dir evidence/loops/loop-04-feedback --reason "Maintainer and source reviewed; lifecycle script is expected for this fixture." --command "pkgsafe scan-local-npm testdata/npm/postinstall-curl --json"  PASS
targeted secret-value scan on generated feedback artifacts                  PASS
malformed feedback input validation                                         PASS
issue-template YAML parse                                                   PASS
feedback docs/template alignment check                                      PASS
Markdown link check                                                         PASS
wording guardrail check                                                     PASS
```

`make build` completed successfully. During one command-level validation, Go
also emitted a sandbox-related module stat-cache warning while trying to write
outside the workspace; it did not fail the build or feedback command.

## Sample Feedback

Generated fingerprint:

```text
10059d15ee2bdda09fc21dcd657950d59908763922c0369cce0dff7bae1a3904
```

Generated files:

- `evidence/loops/loop-04-feedback/npm-postinstall-curl-example-10059d15ee2b.json`
- `evidence/loops/loop-04-feedback/npm-postinstall-curl-example-10059d15ee2b.md`

Sample fields:

```text
package: postinstall-curl-example
ecosystem: npm
version: 1.0.0
decision: warn
risk_score: 65
rule_ids: lifecycle_script_present, missing_license, missing_repository, network_command_in_lifecycle
lifecycle_scripts_involved: true
private_registry_involved: false
behavior_analysis.mode: disabled
```

## Redaction Evidence

- Generated JSON and Markdown were scanned for npm tokens, GitHub tokens, AWS
  access keys, bearer tokens, private key blocks, and basic-auth URL values.
- No matching secret values were found.
- Unit tests verify token-like values in scan output, command text, and user
  reason are redacted.

## Review Loop

- Reduces support friction: PASS. Maintainers receive a stable fingerprint,
  rule IDs, risk score, sanitized JSON, and Markdown issue body.
- Reproducible enough for maintainers: PASS. Command used, package identity,
  decision, rules, lifecycle and private-registry flags are included.
- Avoids collecting secrets: PASS. Artifacts are local-first and sanitized.
- Can later feed a team dashboard: PASS. JSON schema is structured and includes
  stable fingerprints.
- Aligns with issue template: PASS. False-positive template now includes the
  generated fingerprint field and already requests the same core fields.

## Learning Loop

- Rule IDs, risk score, lifecycle-script involvement, private-registry
  involvement, and sanitized scan output are the highest-value support fields.
- A stable fingerprint helps deduplicate repeat reports across repositories.
- Future loops could add direct selection from CI result JSON, multiple finding
  exports, and policy-context summaries.
- False-positive aggregation should stay local until a later loop explicitly
  introduces hosted collection.

## Known Limitations

- `feedback create` currently expects package-scan JSON output. CI result JSON
  contains multiple findings and is not expanded into one feedback file per
  finding yet.
- The command writes local artifacts only; it does not open or submit GitHub
  issues.
- Generated timestamps are run-specific.
- PyPI remains preview coverage; no ecosystem promotion was introduced.
- Behavior analysis remains disabled by default, and heuristic behavior is not
  described as sandboxing or secure containment.
