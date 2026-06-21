# PkgSafe

PkgSafe is a local-first package safety CLI for developer and AI-agent workflows. It validates open-source packages before installation using registry metadata, lifecycle-script analysis, suspicious-pattern detection, typosquat heuristics, policy scoring, and MCP-compatible JSON-RPC tools.

> MVP focus: npm packages and `package-lock.json` scanning.

## Commands

```bash
pkgsafe scan-local-npm ./testdata/npm/safe-package
pkgsafe scan-npm-package axios
pkgsafe scan-npm-package lodash --json
pkgsafe scan-npm-package some-package --version 1.2.3
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
  "package": {
    "ecosystem": "npm",
    "name": "example-package",
    "version": "1.2.3"
  },
  "risk_score": 61,
  "decision": "warn",
  "reasons": []
}
```

## Notes

This scaffold intentionally avoids cloud dependencies and external Go modules. The first iteration uses local JSON cache and deterministic policy scoring. SQLite, OSV ingestion, sandboxing, and IDE extensions should be added in later phases.
