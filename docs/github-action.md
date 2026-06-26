# PkgSafe GitHub Action

The PkgSafe GitHub Action automatically detects risky npm dependency changes before they are merged into your repository.

It runs policy-driven package risk scans on pull requests, updates a PR summary comment, and uploads SARIF findings to GitHub Code Scanning.

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `lockfile` | Path to `package-lock.json` | No | `package-lock.json` |
| `policy` | Path to PkgSafe policy file | No | `.pkgsafe/policy.yaml` |
| `mode` | PkgSafe mode: `audit`, `warn`, or `block` | No | `warn` |
| `fail-on` | Minimum decision that fails the workflow: `none`, `warn`, `block` | No | `block` |
| `changed-only` | Only scan dependencies changed in the pull request | No | `true` |
| `baseline` | Baseline branch for changed dependency detection | No | `main` |
| `sandbox` | Run lifecycle scripts for heuristic behavior analysis (runs on host, no OS isolation) | No | `false` |
| `offline` | Use offline local vulnerability database only | No | `false` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | No | `true` |
| `comment-pr` | Post or update pull request summary comment | No | `true` |
| `pkgsafe-version` | PkgSafe version to install | No | `latest` |

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

## Example Workflow

Add this workflow file (e.g., `.github/workflows/pkgsafe.yml`) to your repository:

```yaml
name: PkgSafe Dependency Gate

on:
  pull_request:
    branches:
      - main

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
        uses: your-org/pkgsafe-action@v0.1.0
        with:
          lockfile: package-lock.json
          policy: .pkgsafe/policy.yaml
          mode: warn
          fail-on: block
          changed-only: true
          baseline: main
          sandbox: false
          upload-sarif: true
          comment-pr: true
```

## Pull Request Commenting

When `comment-pr: true` is configured, PkgSafe will comment on your PR with a clean table of findings. To avoid spam, the action uses a stable hidden marker (`<!-- pkgsafe-pr-comment -->`) to overwrite its previous comment on subsequent workflow runs.
