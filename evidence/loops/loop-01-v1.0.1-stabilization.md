# Loop 1 - v1.0.1 Post-GA Stabilization Evidence

## Tracking

- Branch: `loop-01-v1.0.1-stabilization`
- Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/18

## Files Changed

- `action.yml`
- `.github/ISSUE_TEMPLATE/false_negative.yml`
- `docs/feedback.md`
- `docs/github-action.md`
- `docs/loop-engineering-roadmap.md`
- `evidence/loops/loop-01-v1.0.1-stabilization.md`

## Already Implemented And Reused

- `README.md` already documents npm-first GA scope, copy-paste Linux install,
  release verification commands, feedback routing, and behavior-analysis limits.
- `docs/install.md` already provides copy-paste macOS arm64, macOS amd64, Linux
  amd64, and Windows install/verification examples.
- `docs/release-verification.md` already covers checksums, SBOM checks, cosign,
  attestations, binary version checks, and `doctor`.
- `docs/github-action.md` already includes minimal and advanced workflows plus a
  scheduled OSV cache warmup example.
- `.github/ISSUE_TEMPLATE/false_positive.yml` and
  `.github/ISSUE_TEMPLATE/scanner_bug.yml` already collect sanitized, actionable
  feedback without requesting secrets.
- `scripts/github-action-entrypoint.sh` already maps documented supported action
  inputs to `pkgsafe ci scan`.

## Newly Implemented

- Removed the unused `pkgsafe-version` action input from `action.yml`; the
  composite action builds from `github.action_path` and did not consume that
  input.
- Removed the matching stale `pkgsafe-version` row from `docs/github-action.md`.
- Corrected the false-negative issue template label from `false_block` to
  `false_negative`.
- Added `false_negative` to the feedback taxonomy and recommended labels.
- Added a local loop-engineering roadmap reference for future loop execution.

## Validation Commands

```text
gofmt -w .                                             PASS
go test ./...                                          PASS
go test -race ./...                                    PASS
go vet ./...                                           PASS
make build                                             PASS
make package                                           PASS
Markdown link audit                                    PASS
YAML parse audit for action/workflows/issue templates  PASS
GitHub Action docs input consistency audit             PASS
Issue-template secrets wording audit                   PASS
```

## Wording Audit

- README links checked: PASS
- Docs do not claim secure sandboxing or secure containment: PASS
- Docs keep PkgSafe v1.0.0 npm-first GA: PASS
- PyPI, Go, and Cargo remain marked preview/not npm-equivalent: PASS
- Issue templates do not request secrets; they explicitly require sanitized
  output and removal of secrets/tokens/private registry credentials: PASS
- GitHub Action docs reference only supported `action.yml` inputs: PASS

## Review Loop

- v1.0.0 remains clearly npm-first GA in `README.md`, `docs/install.md`,
  `docs/release-verification.md`, `docs/github-action.md`, and
  `docs/feedback.md`.
- PyPI, Go, and Cargo remain preview coverage and are not documented as
  npm-equivalent.
- Heuristic behavior analysis remains described as host execution without OS
  isolation and disabled by default.
- User-facing install, verification, GitHub Action, and OSV warmup examples are
  copy-pasteable.
- Feedback templates are safe and actionable.

## Learning Loop

- Most Loop 1 docs already existed; the main gaps were consistency and local
  roadmap tracking rather than missing onboarding content.
- The GitHub Action metadata had a stale unused input, showing that action docs
  should be checked directly against `action.yml` during adoption loops.
- Feedback taxonomy was missing the `false_negative` label even though a
  false-negative template already existed.
- Next adoption work should keep adding automated consistency checks for action
  inputs, output names, and workflow examples.

## Known Limitations

- Loop 1 intentionally added no product features.
- PkgSafe remains npm-first GA; PyPI, Go, and Cargo remain preview.
- Heuristic behavior analysis remains disabled by default and non-isolated.
- `make build` and `make package` used a dirty local version string because the
  validation ran with uncommitted loop edits.
