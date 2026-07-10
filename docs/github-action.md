# PkgSafe GitHub Action

Stop risky dependency changes before they merge. The action runs
`pkgsafe ci scan`, can upload SARIF to GitHub Code Scanning, and can post a
pull request summary.

**GA:** npm and PyPI. **Preview:** Go and Cargo (not full GA depth).

Also see [ci-cd.md](ci-cd.md) for the raw CLI on any runner, and
[getting-started.md](getting-started.md) for first-time setup.

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `lockfile` | Path to `package-lock.json` | No | `package-lock.json` |
| `dependency-file` | Path to a dependency file such as `requirements.txt` or `pyproject.toml` for preview ecosystem scans | No | `""` |
| `ecosystem` | Ecosystem to scan: `npm`, `pypi`, or empty for autodetect | No | `""` |
| `policy` | Path to PkgSafe policy file; ignored if the file does not exist | No | `.pkgsafe/policy.yaml` |
| `mode` | PkgSafe mode: `audit`, `warn`, or `block` | No | `warn` |
| `fail-on` | Minimum decision that fails the workflow: `none`, `warn`, `block` | No | `block` |
| `changed-only` | Only scan dependencies changed in the pull request | No | `true` |
| `baseline` | Baseline Git ref or baseline `package-lock.json` file for changed dependency detection | No | `main` |
| `sandbox` | Deprecated compatibility input for `--behavior heuristic`; executes lifecycle scripts on the runner host without OS isolation and is not a security sandbox | No | `false` |
| `offline` | Use offline local vulnerability database only | No | `false` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | No | `true` |
| `comment-pr` | Post or update pull request summary comment | No | `true` |
| `registry-config` | Path to `registries.yaml` for private registry routing | No | `""` |
| `generate-evidence-pack` | Generate a governance evidence pack | No | `true` |
| `evidence-pack-output` | Path for generated evidence pack | No | `pkgsafe-evidence-pack.zip` |
| `upload-evidence-artifact` | Upload the evidence pack as a workflow artifact | No | `true` |

## Outputs

| Output | Description |
|---|---|
| `decision` | Overall PkgSafe decision: `allow`, `warn`, `block` |
| `risk-score` | Highest package risk score |
| `packages-scanned` | Number of packages scanned |
| `warn-count` | Number of warning packages |
| `block-count` | Number of blocked packages |
| `json-report` | Path to JSON report |
| `sarif-report` | Path to SARIF report |
| `markdown-summary` | Path to Markdown summary |
| `evidence-pack` | Path to generated evidence pack ZIP when evidence generation is enabled |

## Minimal Pull Request Workflow

Copy this into another npm repository as `.github/workflows/pkgsafe.yml`:

```yaml
name: PkgSafe Dependency Gate

on:
  pull_request:
    paths:
      - "package-lock.json"
      - ".pkgsafe/**"

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  pkgsafe:
    name: PkgSafe Package Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Cache PkgSafe DB
        uses: actions/cache@v4
        with:
          path: ~/.pkgsafe
          key: pkgsafe-${{ runner.os }}-${{ hashFiles('package-lock.json') }}
          restore-keys: |
            pkgsafe-${{ runner.os }}-

      - name: Run PkgSafe
        uses: sairintechnologycom/pkgsafe@v1.0.0
        with:
          lockfile: package-lock.json
          mode: warn
          fail-on: block
          changed-only: true
          baseline: main
          upload-sarif: true
          comment-pr: true
```

This scans npm dependencies from `package-lock.json` on pull requests. With
`fail-on: block`, the workflow fails only when the overall decision is `block`;
`warn` findings are reported but do not fail the job. Set `fail-on: warn` to
fail on both `warn` and `block`, or `fail-on: none` to report only.

`upload-sarif: true` uploads scan findings to GitHub Code Scanning through
`github/codeql-action/upload-sarif`. `comment-pr: true` writes a Markdown
summary as a pull request comment.

## Advanced Workflow

Use this when you have a policy file, want offline scans from a warmed PkgSafe
database, and want to scan only changed lockfile dependencies:

```yaml
name: PkgSafe Advanced Dependency Gate

on:
  pull_request:
    paths:
      - "package-lock.json"
      - ".pkgsafe/**"

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  pkgsafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Restore PkgSafe DB
        uses: actions/cache@v4
        with:
          path: ~/.pkgsafe
          key: pkgsafe-${{ runner.os }}-${{ hashFiles('package-lock.json', '.pkgsafe/policy.yaml') }}
          restore-keys: |
            pkgsafe-${{ runner.os }}-

      - name: Run PkgSafe with policy
        uses: sairintechnologycom/pkgsafe@v1.0.0
        with:
          lockfile: package-lock.json
          policy: .pkgsafe/policy.yaml
          mode: block
          fail-on: block
          changed-only: true
          baseline: main
          offline: true
          upload-sarif: true
          comment-pr: true
          generate-evidence-pack: false
```

`offline: true` uses only local cached advisory and package metadata. It is best
paired with a scheduled job or prior connected scan that runs `pkgsafe update-db`;
otherwise the scan can fail or warn when required data is missing.

`changed-only: true` is supported for pull requests with enough Git history to
diff against `baseline`; keep `fetch-depth: 0` in checkout. `baseline` can also
point at a checked-in baseline lockfile such as `.pkgsafe/baseline-package-lock.json`.

## Baseline File Workflow

Use a baseline file when you want PR scans to compare against an approved
dependency snapshot instead of a branch ref:

```yaml
name: PkgSafe Baseline Dependency Gate

on:
  pull_request:
    paths:
      - "package-lock.json"
      - ".pkgsafe/**"

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  pkgsafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run PkgSafe against baseline file
        uses: sairintechnologycom/pkgsafe@v1.0.0
        with:
          lockfile: package-lock.json
          changed-only: true
          baseline: .pkgsafe/baseline-package-lock.json
          fail-on: block
          upload-sarif: true
          comment-pr: true
```

With `fail-on: block`, the workflow fails only for `block`. With
`fail-on: warn`, both `warn` and `block` fail the workflow. With
`fail-on: none`, PkgSafe reports findings without failing the workflow.

SARIF upload requires `permissions.security-events: write` and
`upload-sarif: true`. If your repository does not use GitHub Code Scanning, set
`upload-sarif: false`; the Action still writes JSON and Markdown outputs.

## Scheduled OSV Cache Warmup

The composite Action does not expose a generic `command` input, so use the CLI
directly for scheduled vulnerability database refreshes. This keeps offline PR
scans useful by warming `~/.pkgsafe` on a schedule.

```yaml
name: PkgSafe OSV Cache Warmup

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  pkgsafe-cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Cache PkgSafe DB
        uses: actions/cache@v4
        with:
          path: ~/.pkgsafe
          key: pkgsafe-${{ runner.os }}-osv-${{ github.run_id }}
          restore-keys: |
            pkgsafe-${{ runner.os }}-osv-
            pkgsafe-${{ runner.os }}-

      - name: Install PkgSafe
        run: |
          curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash

      - name: Warm vulnerability database
        run: |
          pkgsafe update-db --ecosystem all
          pkgsafe db status
```

This scheduled workflow updates the local OSV database cache. It does not change
scanner behavior, and it should be treated as an availability optimization for
offline scans rather than a release verification step.

## Pull Request Commenting

When `comment-pr: true` is configured, PkgSafe will comment on your PR with a clean table of findings. To avoid spam, the action uses a stable hidden marker (`<!-- pkgsafe-pr-comment -->`) to overwrite its previous comment on subsequent workflow runs.
