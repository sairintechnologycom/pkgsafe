# PkgSafe CI/CD Integration

PkgSafe can be run as a package gate inside any CI/CD environment (such as GitHub Actions, GitLab CI, or Azure Pipelines) using the `pkgsafe ci scan` subcommand.

## CI Scan Subcommand

Usage:

```bash
pkgsafe ci scan [flags]
```

### Options

* `--lockfile <path>`: Path to lockfile to scan. Defaults to `package-lock.json`.
* `--policy <path>`: Path to policy file. Defaults to `.pkgsafe/policy.yaml` if present.
* `--mode <mode>`: PkgSafe decision mode (`audit`, `warn`, or `block`).
* `--fail-on <threshold>`: Minimum decision that fails the scan (`none`, `warn`, or `block`). Defaults to `block`.
* `--changed-only`: Scan only direct or transitive package changes between the current branch and a baseline branch.
* `--baseline <branch>`: Baseline branch name. Defaults to `main`.
* `--sandbox`: Run package lifecycle scripts for heuristic behavior analysis. Note: scripts execute on the host without OS isolation (no container/namespace/network sandbox) — not a security sandbox. Use a disposable environment.
* `--offline`: Scan using the cached vulnerability database and locally cached metadata only.
* `--json-output <path>`: Path to write the JSON findings report.
* `--sarif-output <path>`: Path to write the SARIF (Static Analysis Results Interchange Format) version 2.1.0 file.
* `--summary-output <path>`: Path to write the Markdown summary report.

## Deterministic Exit Codes

The `pkgsafe ci scan` command exits with one of the following code ranges:

* `0`: Scan completed successfully and no policy failure threshold was reached.
* `1`: Failure threshold reached (warn/block package findings matching `--fail-on`).
* `2`: Command line usage or configuration error.
* `3`: Scanner internal error or runtime issue.
* `4`: Policy file syntax validation error.
* `5`: Lockfile or package JSON parsing error.

## Examples

### Scan Only PR Changes Against main and Fail on Block Decisions

```bash
pkgsafe ci scan --changed-only --baseline main --fail-on block
```

### Scan Lockfile Offline and Write SARIF Report

```bash
pkgsafe ci scan --offline --sarif-output pkgsafe-results.sarif
```
