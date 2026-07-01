# Loop 06 - Private Registry Governance

Date: 2026-07-01
Branch: loop-06-private-registry-governance
Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/23

## Feature Spec

Strengthen dependency-confusion and private-registry protection for npm private scopes and PyPI private prefixes. This loop stayed local-first and did not introduce SaaS, billing, SSO, hosted services, or behavior-analysis changes.

## Files Changed

Loop 6 changes:

- `cmd/pkgsafe/enterprise.go`
- `cmd/pkgsafe/main.go`
- `cmd/pkgsafe/main_test.go`
- `docs/private-registry.md`
- `internal/enterprise/enterprise_test.go`
- `internal/registry/redaction.go`
- `internal/registry/registry_test.go`
- `internal/registry/test.go`
- `internal/risk/private_registry_rules.go`
- `testdata/registry-governance-policy.yaml`
- `evidence/loops/loop-06-private-registry-governance.md`

The branch is stacked on uncommitted Loop 1-5 work, which was preserved and reused.

## Already Implemented And Reused

- Existing registry resolver for npm scopes and PyPI package prefixes.
- Existing npm and PyPI scanner fail-closed checks for disabled registries.
- Existing private registry risk rules for dependency confusion and public-registry mismatch.
- Existing `pkgsafe registry test <name>` reachability command.
- Existing policy and registry config loading.
- Existing registry secret redaction helper.

## Newly Implemented

- Added package-level routing evidence with `registry.TestPackageRouting`.
- Added CLI support:
  - `pkgsafe registry list [--policy <path>] [--registry-config <path>]`
  - `pkgsafe registry test [--policy <path>] [--registry-config <path>] <name>`
  - `pkgsafe registry test [--policy <path>] [--registry-config <path>] --ecosystem <npm|pypi> --package <name>`
- Added routing output fields for resolved registry, registry type, redacted URL, private match, private registry, public fallback, status, and reason.
- Added PyPI normalized package display for routing tests.
- Strengthened redaction for registry URLs with token-like query parameters.
- Redacted registry test error reasons.
- Updated PyPI private-prefix risk checks to use normalized package matching.
- Added local fixture policy for private npm scope, disabled private npm scope, PyPI private prefix, and disabled public defaults.
- Added tests for private npm routing, disabled-private fail-closed behavior, PyPI normalization, CLI routing flags, token redaction, and normalized dependency-confusion findings.
- Updated private-registry docs with copy-pasteable package-routing and no-public-fallback examples.

## Validation Commands Run

```bash
gofmt -w cmd/pkgsafe/enterprise.go cmd/pkgsafe/main.go cmd/pkgsafe/main_test.go internal/registry/test.go internal/registry/redaction.go internal/registry/registry_test.go internal/risk/private_registry_rules.go internal/enterprise/enterprise_test.go
go test ./internal/registry ./internal/enterprise ./cmd/pkgsafe
go test ./internal/risk
go test ./...
go test -race ./...
go vet ./...
make build
make package
./dist/pkgsafe registry test --policy testdata/registry-governance-policy.yaml --ecosystem npm --package @company/api
./dist/pkgsafe registry test --policy testdata/registry-governance-policy.yaml --ecosystem pypi --package company_internal_pkg
./dist/pkgsafe registry test --policy testdata/registry-governance-policy.yaml --ecosystem npm --package @offline/api
./dist/pkgsafe registry list --policy testdata/registry-governance-policy.yaml
./dist/pkgsafe policy validate testdata/registry-governance-policy.yaml
ruby -e 'ARGV.each { |f| require "yaml"; YAML.load_file(f); puts "yaml ok: #{f}" }' testdata/registry-governance-policy.yaml
ruby -e 'text = File.read("docs/private-registry.md"); links = text.scan(/\[[^\]]+\]\(([^)]+)\)/).flatten.reject { |href| href.start_with?("http", "#") }; links.each { |href| path = href.split("#", 2).first; next if path.empty?; full = File.expand_path(path, "docs"); abort("missing link: #{href}") unless File.exist?(full) }; puts "links ok"'
! rg -n "secure sandbox|secure containment|full PyPI|full Go|full Cargo|SaaS|billing|SSO|hosted service|npm_secret|user:pass" cmd/pkgsafe/enterprise.go cmd/pkgsafe/main.go internal/registry internal/risk docs/private-registry.md testdata/registry-governance-policy.yaml
```

## Test Results

- `gofmt`: pass
- Focused registry/enterprise/CLI tests: pass
- Focused risk tests: pass
- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `make build`: pass
- `make package`: pass
- Registry governance policy YAML parse: pass
- Registry governance policy validation: pass
- Private-registry doc link check: pass
- Wording/secrets audit: pass

## Sample Evidence

Private npm scope resolves only to the approved private registry:

```text
Registry Routing Test: npm/@company/api

Resolved Registry: company
Registry Type: private
Registry URL: https://REDACTED:REDACTED@npm.company.test/?token=REDACTED
Private Match: enabled
Private Registry: company
Public Fallback: disabled
Status: OK
```

PyPI private prefix uses normalized package names:

```text
Registry Routing Test: pypi/company_internal_pkg

Normalized Package: company-internal-pkg
Resolved Registry: company
Registry Type: private
Registry URL: https://pypi.company.test/simple/
Private Match: enabled
Private Registry: company
Public Fallback: disabled
Status: OK
```

Disabled private registry blocks instead of falling back to public npm:

```text
Registry Routing Test: npm/@offline/api

Resolved Registry: offline-company
Registry Type: private
Registry URL: https://npm-offline.company.test/
Private Match: enabled
Private Registry: offline-company
Public Fallback: disabled
Status: BLOCK
Reason: registry is disabled by policy; public fallback is not allowed
```

Registry list redacts URL credentials and token-like query parameters:

```text
NAME              ECOSYSTEM   TYPE      URL                                                          AUTH METHOD
company           npm         private   https://REDACTED:REDACTED@npm.company.test/?token=REDACTED
offline-company   npm         private   https://npm-offline.company.test/
default           npm         public    https://registry.npmjs.org/
company           pypi        private   https://pypi.company.test/simple/
default           pypi        public    https://pypi.org/simple/
```

## Wording Audit

- No Loop 6 docs or CLI text claim secure sandboxing or secure containment.
- No Loop 6 docs claim full PyPI, Go, or Cargo GA.
- No SaaS, billing, SSO, hosted-service, or behavior-analysis behavior was introduced.
- Registry evidence redacts URL credentials and token-like query parameters.

## Review Loop

- Private npm scopes and PyPI prefixes are explainable through local CLI routing evidence.
- Disabled private registries fail closed and do not fall back to public registries.
- PyPI prefix matching now uses the same normalization in risk controls as in the resolver.
- Registry URLs are safer in evidence and error paths because query tokens are redacted.
- The implementation reuses existing resolver/scanner behavior instead of adding a separate registry routing system.

## Learning Loop

- The main missing onboarding piece was a package-level registry routing test; named reachability checks alone did not prove no-public-fallback behavior.
- Platform teams need both a pass case and an expected block case to audit dependency-confusion controls.
- Artifactory, Nexus, Azure Artifacts, and Verdaccio examples would make a later enterprise adoption loop more copy-pasteable.
- Future paid candidates could include policy-pack distribution and richer registry routing reports, but this loop intentionally stayed local.

## Known Limitations

- `registry test --ecosystem --package` validates routing decisions; it does not fetch package metadata.
- The fixture uses `.test` registry hosts and is intended for local routing evidence, not live reachability.
- Registry-specific templates for Artifactory, Nexus, Azure Artifacts, and Verdaccio remain future work.
- The branch remains stacked on uncommitted Loop 1-5 changes.

## Completion Criteria

- Private registry leakage prevention strengthened: complete.
- Dependency-confusion protection demonstrable: complete.
- Registry routing evidence generated: complete.
- Tokens redacted from routing evidence: complete.
- All required validation commands pass: complete.
