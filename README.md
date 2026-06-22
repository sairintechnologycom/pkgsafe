# PkgSafe

PkgSafe is a local-first package safety CLI for developer and AI-agent workflows. It validates open-source packages before installation using registry metadata, lifecycle-script analysis, suspicious-pattern detection, typosquat heuristics, policy scoring, and MCP-compatible JSON-RPC tools.

> MVP focus: npm packages and `package-lock.json` scanning.

## Commands

```bash
pkgsafe scan-local-npm ./testdata/npm/safe-package
pkgsafe scan-npm-package axios
pkgsafe scan-npm-package lodash --json
pkgsafe scan-npm-package some-package --version 1.2.3
pkgsafe scan-npm-package axios --policy ./default-policy.yaml
pkgsafe scan-npm-package axios --mode audit
pkgsafe scan-npm-package axios --mode warn
pkgsafe scan-npm-package axios --mode block
pkgsafe scan-lockfile ./package-lock.json
pkgsafe explain axios
pkgsafe npm-install axios --mode warn
pkgsafe mcp serve
```

`scan-npm-package` fetches metadata from the npm registry, resolves `latest` when no version is provided, downloads the selected tarball into the local cache, verifies npm integrity/shasum metadata when present, safely extracts `package/package.json`, and reuses the npm static analyzer.

## Decisions

PkgSafe returns one of:

- `allow`: low risk
- `warn`: suspicious signals, developer confirmation recommended
- `block`: critical behavior such as credential path access, known malware, or strong exfiltration indicators

## Policy and modes

PkgSafe uses the embedded default policy when `--policy` is omitted. A YAML policy can tune thresholds, trusted and blocked npm packages, protected credential paths, and per-rule scores:

```bash
pkgsafe scan-npm-package axios --policy ./default-policy.yaml
pkgsafe scan-local-npm ./testdata/npm/postinstall-curl --policy ./default-policy.yaml --mode audit
```

Modes control enforcement language without hiding the underlying risk decision:

- `audit`: report the decision, but never enforce a block
- `warn`: default mode; warn for suspicious packages and block critical findings
- `block`: strict mode; packages at or above the block threshold should not be installed

Example human output:

```text
Decision: WARN
Mode: WARN
Enforcement: User review recommended
Package: npm/example-package@1.2.3
Risk Score: 62/100

Reasons:
- [medium +20] lifecycle_script_present: Package defines a postinstall script
- [high +30] network_command_in_lifecycle: Lifecycle script uses curl

Recommended Action:
Review package before installing.
```

## Build

```bash
make test
make build
make package
```

Artifacts are written to `dist/`.

## MCP tool

Start the MCP-compatible stdio server:

```bash
pkgsafe mcp serve
```

Example JSON-RPC request:

```json
{"jsonrpc":"2.0","id":1,"method":"validate_package_install","params":{"ecosystem":"npm","name":"axios"}}
```

CLI JSON output uses the stable scan contract:

```json
{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
  "mode": "warn",
  "decision": "warn",
  "risk_score": 62,
  "thresholds": {
    "allow_max_score": 29,
    "warn_max_score": 69,
    "block_min_score": 70
  },
  "reasons": [
    {
      "rule_id": "lifecycle_script_present",
      "severity": "medium",
      "score": 20,
      "message": "Package defines a postinstall script"
    }
  ],
  "recommended_action": "Review package before installing."
}
```

## Notes

This scaffold intentionally avoids cloud dependencies and external Go modules. The first iteration uses local JSON cache and deterministic policy scoring. SQLite, OSV ingestion, sandboxing, and IDE extensions should be added in later phases.
