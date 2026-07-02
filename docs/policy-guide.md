# PkgSafe Policy Guide

PkgSafe uses `default-policy.yaml` unless `--policy` is supplied.

Core controls:

- `schema_version`: policy schema version; v1 uses `1.0`
- `mode`: `audit`, `warn`, or `block`
- `thresholds`: score bands for allow, warn, and block
- `trusted_packages`: reputation reduction for known packages
- `blocked_packages`: explicit package deny lists
- `rules`: scoring and severity for static, behavioral, registry, and vulnerability findings
- `sandbox.behavior_mode`: legacy policy key for behavior analysis mode: `disabled`, `heuristic`, or `isolated`; `heuristic` is non-isolated host execution, and `isolated` is experimental, Linux-only, and requires bubblewrap
- `ci`: default `fail-on`, `changed-only`, SARIF upload, and PR comment behavior
- `registries`: private npm/PyPI registry routing and public fallback controls

Security rules for vulnerabilities:

- `known_malware_indicator` always blocks.
- `known_vulnerability_critical` blocks.
- `known_vulnerability_high` warns at minimum.
- Trusted package reduction is not applied when a critical or malware finding forces a block.
- Hard-block rules such as credential access, known malware, dependency
  confusion, private-scope public registry use, and shell download/execute
  cannot be disabled or weakened below the block threshold.
- Force-risk accept must require a reason so overrides remain auditable.
- Exceptions must include `id`, `package`, `reason`, `approved_by`, and a future
  `allowed_until`; expired exceptions fail validation.

Validate a policy:

```bash
pkgsafe policy validate .pkgsafe/policy.yaml
pkgsafe policy explain .pkgsafe/policy.yaml
pkgsafe policy test testdata/policy-fixtures
```

Policy fixture tests treat files named `invalid-*` as expected validation
failures and all other `.yaml`/`.yml` files as expected valid policies.
