# GitHub Action — PR Test Scenarios

These scenarios validate the PkgSafe dependency gate across the three decision
types — **allow**, **warn**, **block** — and the deterministic exit codes the
Action relies on to pass or fail a pull request.

Fixtures live under `testdata/ci-scenarios/`. The commands below run the same
`pkgsafe ci scan` the composite Action invokes via
`scripts/github-action-entrypoint.sh`.

## Exit codes

`pkgsafe ci scan` exit codes are stable and drive the Action's pass/fail:

| Code | Meaning |
|------|---------|
| 0 | Scan completed, `--fail-on` threshold not reached |
| 1 | `--fail-on` threshold reached (warn/block found) |
| 2 | Usage/configuration error |
| 3 | Internal/scanner error |
| 4 | Policy load/validation error |
| 5 | Lockfile/package.json parse error |

## Scenario 1 — Safe dependency (allow)

A clean lockfile. The gate passes; the PR is mergeable.

```sh
pkgsafe ci scan \
  --lockfile testdata/ci-scenarios/safe/package-lock.json \
  --mode block --fail-on block --changed-only=false --offline
# Decision: ALLOW
# exit 0
```

Deterministic offline. No advisory or registry data required.

## Scenario 2 — Medium-risk dependency (warn)

A dependency with a medium-severity advisory (`esbuild@0.19.0`,
GHSA-67mh-4wv8-2f99, fixed in 0.25.0). PkgSafe explains the risk and warns with a
remediation hint rather than blindly blocking. With `--fail-on warn` the gate
fails the PR; with `--fail-on block` it passes but surfaces the warning (and the
PR comment / SARIF still report it).

```sh
# Connected mode — warn requires registry/advisory metadata for the package.
pkgsafe ci scan \
  --lockfile testdata/ci-scenarios/warn/package-lock.json \
  --mode warn --fail-on warn --changed-only=false
# Decision: WARN
# exit 1   (fail-on warn)

pkgsafe ci scan \
  --lockfile testdata/ci-scenarios/warn/package-lock.json \
  --mode warn --fail-on block --changed-only=false
# Decision: WARN
# exit 0   (fail-on block — warn does not fail the gate)
```

> Note: the warn decision depends on package metadata, so this scenario runs in
> connected mode (or with the package cached). Offline with no cached metadata,
> an unknown package is reported as `unknown`/`allow`, never a silent pass that
> masks missing data. See [known-limitations.md](known-limitations.md).

## Scenario 3 — Malicious / typosquat dependency (block)

A lockfile containing `axois` (a typosquat of `axios`) with malware advisories
in the local OSV cache. The gate blocks and fails the PR.

```sh
pkgsafe ci scan \
  --lockfile testdata/ci-scenarios/block/package-lock.json \
  --mode block --fail-on block --changed-only=false --offline
# Decision: BLOCK  (axois@1.0.0 — GHSA-wpfc-3w63-g4hm, MAL-2025-15245)
# exit 1
```

Deterministic offline once the OSV database is synced (`pkgsafe update-db`).

## Changed-only PR scans

In a real PR the Action defaults to `changed-only: true`, scanning only
dependencies added or changed against the baseline branch. The examples above
pass `--changed-only=false` to scan the whole lockfile so they work outside a
git diff. To exercise changed-only locally, commit a baseline lockfile, change a
dependency, and run without the flag.

## Output artifacts

Each scenario can emit machine-readable outputs the Action uploads:

```sh
pkgsafe ci scan --lockfile <path> --changed-only=false \
  --json-output results.json \
  --sarif-output results.sarif \
  --summary-output summary.md
```

- `results.json` — full structured report (stable schema).
- `results.sarif` — uploaded to GitHub Code Scanning.
- `summary.md` — posted as the PR comment.
