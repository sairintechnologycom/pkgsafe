# PkgSafe Policy Guide

PkgSafe uses `default-policy.yaml` unless `--policy` or `--policy-pack` is supplied.

Core controls:

- `mode`: `audit`, `warn`, or `block`
- `thresholds`: score bands for allow, warn, and block
- `trusted_packages`: reputation reduction for known packages
- `blocked_packages`: explicit package deny lists
- `rules`: scoring and severity for static, behavioral, registry, and vulnerability findings
- `ci`: default `fail-on`, `changed-only`, SARIF upload, and PR comment behavior
- `registries`: private npm/PyPI registry routing and public fallback controls

Security rules for vulnerabilities:

- `known_malware_indicator` always blocks.
- `known_vulnerability_critical` blocks.
- `known_vulnerability_high` warns at minimum.
- Trusted package reduction is not applied when a critical or malware finding forces a block.

Validate a policy:

```bash
pkgsafe policy validate .pkgsafe/policy.yaml
pkgsafe policy explain .pkgsafe/policy.yaml
```
