# Loop 22 — Clean Release Verification

Date: 2026-07-12

## Feature spec

Publish a beta release from a branch that passes every CI gate, then verify the
downloaded release bytes from a clean directory. A release is not trusted merely
because its workflow or upload step succeeded.

## Build loop

Release attempts exposed and closed the following defects:

- `v1.7.0-beta.1`: release validation failed because the committed tree did not
  pass fresh lint, Windows line-ending, and clean-cache MCP test gates.
- Restored pinned lint compliance and LF normalization across supported runners.
- Added failure annotations that preserve race-test and GoReleaser context while
  retaining the original non-zero status.
- Corrected the clean-cache MCP guidance test so structured offline errors are
  not decoded as zero-valued success objects.
- Committed Go 1.25 tidy metadata and changed the GoReleaser hook from mutating
  `go mod tidy` to validating `go mod tidy -diff`.
- `v1.7.0-beta.6`: builds, SBOMs, checksums, Cosign signing, and draft asset
  upload succeeded; Homebrew publication failed closed with HTTP 403 because the
  tap token lacks write access.
- Configured `skip_upload: auto` for Homebrew so beta/RC tags do not update the
  stable package-manager channel. Stable tags still require a valid tap token.
- Published beta tags as public prereleases rather than inaccessible drafts.

## Validation loop

### Branch gates

Commit `493b78518d97252aab2d5cadb5809b7123202d90` passed:

- Ubuntu build, vet, and race tests;
- macOS build, vet, and race tests;
- Windows formatting, build, and vet;
- pinned `golangci-lint`;
- PkgSafe dependency self-scan;
- mandatory Linux isolated-behavior E2E.

### Published release

- Tag: `v1.7.0-beta.7`
- Release workflow run: `29189478031`
- Workflow conclusion: `success`
- Release state: public prerelease, not draft
- Published assets: 16
  - six platform archives;
  - six SPDX SBOM documents;
  - `checksums.txt`;
  - `checksums.txt.sig`;
  - `checksums.txt.pem`;
  - `install.sh`.

### Clean-directory verification

Verification directory:

```text
/private/tmp/pkgsafe-release-verify-v1.7.0-beta.7
```

Results:

| Gate | Result |
| --- | --- |
| All 12 checksum-listed archives/SBOMs | PASS |
| Six SBOMs parse as SPDX 2.3 with package inventory | PASS |
| Cosign signature over `checksums.txt` | PASS (`Verified OK`) |
| Certificate workflow identity | PASS (`release.yml@refs/tags/v1.7.0-beta.7`) |
| Certificate OIDC issuer | PASS (`token.actions.githubusercontent.com`) |
| Downloaded macOS ARM64 binary version | PASS (`1.7.0-beta.7`) |
| Downloaded binary commit | PASS (`493b785`) |
| GitHub artifact attestation verification | PASS |
| SLSA subject digest for macOS ARM64 archive | PASS (`9573d60a...a3d8b`) |
| Attested source commit | PASS (`493b78518d...202d90`) |
| Attested workflow/run | PASS (`release.yml`, run `29189478031`) |

Commands executed included:

```text
shasum -a 256 -c checksums.txt
jq -e '<SPDX structural assertions>' *.sbom.json
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '<exact beta.7 release workflow identity>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
gh attestation verify pkgsafe_1.7.0-beta.7_darwin_arm64.tar.gz \
  --repo sairintechnologycom/pkgsafe --format json
./extracted-darwin-arm64/pkgsafe version
```

## Review loop

Release artifact signing and GitHub build provenance are now demonstrated from
downloaded public bytes. This closes the release-verification gaps recorded in
Loops 8 and 9 for beta qualification.

The stable Homebrew publication credential remains mis-scoped. This does not
affect beta artifact integrity because prereleases now skip the stable tap, but
it remains a stable-release blocker and must continue to fail closed.

The combined `test production-readiness` command also reached an interactive
WARN install confirmation during connected benchmark execution. Independent
release gates passed, but the aggregate command is not yet reliable in an
unattended terminal. That behavior is assigned to the next loop; no aggregate
`PRODUCTION_GA_READY` result is claimed here.

## Completion gate

```text
public beta release workflow: PASS
downloaded checksums: PASS
downloaded SBOM validation: PASS
Cosign verification: PASS
GitHub provenance verification: PASS
binary version/commit verification: PASS
stable Homebrew publication: BLOCKED (external token scope; beta skipped)
aggregate unattended readiness command: NEXT LOOP
```
