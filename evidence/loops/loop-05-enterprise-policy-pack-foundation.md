# Loop 05 - Enterprise Policy Pack Foundation

Date: 2026-06-30
Branch: loop-05-enterprise-policy-pack-foundation
Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/22

## Feature Spec

Strengthen local enterprise policy packs while keeping PkgSafe local-first. This loop added policy schema versioning, stronger local validation, policy explanation details, policy fixture tests, and signed policy-pack verification evidence. It did not add SaaS, billing, SSO, or hosted services.

## Files Changed

- `cmd/pkgsafe/enterprise.go`
- `cmd/pkgsafe/main_test.go`
- `default-policy.yaml`
- `docs/policy-guide.md`
- `internal/policy/policy.go`
- `internal/policy/policy_test.go`
- `testdata/policy-fixtures/valid-enterprise-policy.yaml`
- `testdata/policy-fixtures/invalid-expired-exception.yaml`
- `testdata/policy-fixtures/invalid-force-accept-without-reason.yaml`
- `testdata/policy-fixtures/invalid-hard-block-weakened.yaml`
- `evidence/loops/loop-05-enterprise-policy-pack-foundation.md`

The worktree also contains earlier stacked Loop 1-4 changes, which were reused and not reverted.

## Already Implemented And Reused

- Existing `pkgsafe policy validate` and `pkgsafe policy explain` command structure.
- Existing policy model, default policy loading, YAML parser, and validation flow.
- Existing policy-pack commands for create, verify, install, list, export, keygen, and trust.
- Existing signing and verification support for policy packs.
- Existing secret redaction helper from registry handling.

## Newly Implemented

- Added `schema_version: "1.0"` support to the policy model and default policy.
- Added validation rejection for unsupported schema versions.
- Added validation for `ci.fail_on` values.
- Added validation that force-risk accept must require a reason when enabled.
- Added exception audit requirements: `id`, `package`, `reason`, `approved_by`, and non-expired `allowed_until`.
- Added hard-block invariant validation so critical package, credential, malware, dependency-confusion, private-registry, and shell download/execute controls cannot be disabled or weakened below the block threshold.
- Added `pkgsafe policy test [--json] <file-or-dir>`.
- Added deterministic fixture convention: `invalid-*` or `.invalid.` files are expected invalid, other YAML files are expected valid.
- Added policy fixture tests for valid enterprise policy, expired exception, force accept without reason, and weakened hard block.
- Enhanced `policy explain` with schema version, force-risk reason requirement, redacted override audit log, and hard-block rule status.
- Documented schema versioning, hard-block invariants, exception audit fields, force-risk reason requirements, and policy fixture testing.

## Validation Commands Run

```bash
gofmt -w .
go test ./internal/policy ./internal/enterprise ./cmd/pkgsafe
go test ./...
go test -race ./...
go vet ./...
make build
make package
./dist/pkgsafe policy validate default-policy.yaml
./dist/pkgsafe policy explain default-policy.yaml
./dist/pkgsafe policy test testdata/policy-fixtures
./dist/pkgsafe policy test --json testdata/policy-fixtures
./dist/pkgsafe policy validate testdata/policy-fixtures/invalid-hard-block-weakened.yaml
ruby -e 'ARGV.each { |f| require "yaml"; YAML.load_file(f); puts "yaml ok: #{f}" }' default-policy.yaml testdata/policy-fixtures/valid-enterprise-policy.yaml testdata/policy-fixtures/invalid-expired-exception.yaml testdata/policy-fixtures/invalid-hard-block-weakened.yaml testdata/policy-fixtures/invalid-force-accept-without-reason.yaml
ruby -e 'text = File.read("docs/policy-guide.md"); links = text.scan(/\[[^\]]+\]\(([^)]+)\)/).flatten.reject { |href| href.start_with?("http", "#") }; links.each { |href| path = href.split("#", 2).first; next if path.empty?; full = File.expand_path(path, "docs"); abort("missing link: #{href}") unless File.exist?(full) }; puts "links ok"'
! rg -n "sandbox|secure containment|full PyPI|full Go|full Cargo|hosted|SaaS|billing|SSO" cmd/pkgsafe/enterprise.go internal/policy docs/policy-guide.md default-policy.yaml testdata/policy-fixtures
```

## Test Results

- `gofmt -w .`: pass
- `go test ./internal/policy ./internal/enterprise ./cmd/pkgsafe`: pass
- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `make build`: pass
- `make package`: pass
- `policy validate default-policy.yaml`: pass
- `policy explain default-policy.yaml`: pass
- `policy test testdata/policy-fixtures`: pass
- `policy test --json testdata/policy-fixtures`: pass
- `policy validate invalid-hard-block-weakened.yaml`: expected failure, pass for negative validation
- YAML parse check: pass
- Markdown link check for `docs/policy-guide.md`: pass

## Sample Output

Default policy validation:

```text
Policy is valid.
```

Policy explain:

```text
PkgSafe Policy Summary

Policy: enterprise-standard
Schema Version: 1.0
Mode: warn
Owner: Platform Engineering
Version: 2026.06.01

Controls:
- Known malware always blocked
- Credential access always blocked
- AI-agent warn requires confirmation
- Force risk accept: enabled
- Force risk accept requires reason: enabled
- Override audit log: ~/.pkgsafe/audit.log
- Private registry packages: trusted only when registry matches approved source
- Hard-block rules: enforced
```

Policy fixture tests:

```text
[PASS] testdata/policy-fixtures/invalid-expired-exception.yaml expected=invalid error=invalid policy "testdata/policy-fixtures/invalid-expired-exception.yaml": exception EXC-PAST-001 is expired
[PASS] testdata/policy-fixtures/invalid-force-accept-without-reason.yaml expected=invalid error=invalid policy "testdata/policy-fixtures/invalid-force-accept-without-reason.yaml": force risk accept must require a reason
[PASS] testdata/policy-fixtures/invalid-hard-block-weakened.yaml expected=invalid error=invalid policy "testdata/policy-fixtures/invalid-hard-block-weakened.yaml": hard-block rule known_malware_indicator must remain critical
[PASS] testdata/policy-fixtures/valid-enterprise-policy.yaml expected=valid
```

Intentional invalid policy validation:

```text
Validation failed: invalid policy "testdata/policy-fixtures/invalid-hard-block-weakened.yaml": hard-block rule known_malware_indicator must remain critical
```

Signed policy pack verification sample:

```text
Policy pack verified successfully.
```

## Wording Audit

- No Loop 5 docs or templates claim secure sandboxing or secure containment.
- The only `sandbox` matches in Loop 5 files are the existing policy key name and the documentation statement that heuristic behavior mode is non-isolated host execution.
- No Loop 5 docs claim full PyPI, Go, or Cargo GA.
- No SaaS, billing, SSO, or hosted-service behavior was introduced.
- PkgSafe remains npm-first GA; this loop only strengthens local enterprise policy governance.

## Review Loop

- Enterprise platform teams can now validate policies, understand enforced controls, and run local policy fixtures.
- Exceptions are more auditable because they require a reason, approver, package, id, and active expiry.
- Hard-block invariants guard against trusted packages or policy edits weakening critical block behavior.
- `policy explain` is more readable for local review and auditor-facing evidence.
- Signed policy-pack functionality was reused instead of duplicating pack generation logic.

## Learning Loop

- Missing before this loop: schema version visibility, fixture-based policy tests, and clear explain output for override and hard-block controls.
- The most valuable enterprise fields were exception audit data, force-risk reason enforcement, and hard-block invariant status.
- Future paid candidates remain governance workflows around policy approvals, pack distribution, and audit reporting, but those were intentionally not added here.
- The next adoption risk is private registry routing and dependency-confusion evidence, which belongs in Loop 6.

## Known Limitations

- Policy fixture expectations are filename-based; richer fixture metadata can be added later if tests need scenario-specific expected errors.
- Schema version `1.0` is the only accepted explicit policy schema.
- Signed pack verification sample used a temporary metadata file with `min_pkgsafe_version: 0.0.0` because the dirty local build reports a pre-GA dev version.
- The branch is stacked on uncommitted Loop 1-4 work.

## Completion Criteria

- Policy command set strengthened: complete.
- Hard-block invariants hold: complete.
- Policy fixture tests added: complete.
- All required validation commands pass: complete.
- No SaaS introduced: complete.
