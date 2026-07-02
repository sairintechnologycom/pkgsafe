# PkgSafe v1.0.1 Release Summary

Date verified: 2026-07-02

## Release

- Repository: `github.com/sairintechnologycom/pkgsafe`
- Tag: `v1.0.1`
- Commit SHA: `c7cde79464f8eb9417fc0f6722419974690e88d2`
- Commit subject: `Align public module path and open-core boundary (#28)`
- PR #28: merged on 2026-07-01 at `c7cde79464f8eb9417fc0f6722419974690e88d2`
- Release workflow run: `https://github.com/sairintechnologycom/pkgsafe/actions/runs/28512052426`
- Release URL: `https://github.com/sairintechnologycom/pkgsafe/releases/tag/v1.0.1`
- Release published: 2026-07-02

## Verification Commands

```bash
git checkout main
git pull --rebase
go test ./...
go test -race ./...
go vet ./...
make build
make package
scripts/check-public-boundary.sh
make check-public-boundary
gh release download v1.0.1 --repo sairintechnologycom/pkgsafe --dir /private/tmp/pkgsafe-release-assets-v1.0.1 --clobber
shasum -a 256 -c checksums.txt
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/sairintechnologycom/pkgsafe/.github/workflows/release.yml@refs/tags/v1.0.1' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
gh attestation verify pkgsafe_1.0.1_linux_amd64.tar.gz --repo sairintechnologycom/pkgsafe
gh attestation verify pkgsafe_1.0.1_linux_arm64.tar.gz --repo sairintechnologycom/pkgsafe
gh attestation verify pkgsafe_1.0.1_darwin_amd64.tar.gz --repo sairintechnologycom/pkgsafe
gh attestation verify pkgsafe_1.0.1_darwin_arm64.tar.gz --repo sairintechnologycom/pkgsafe
gh attestation verify pkgsafe_1.0.1_windows_amd64.zip --repo sairintechnologycom/pkgsafe
gh attestation verify pkgsafe_1.0.1_windows_arm64.zip --repo sairintechnologycom/pkgsafe
```

## Results

| Check | Result |
| --- | --- |
| `git pull --rebase` | PASS |
| PR #28 merged | PASS |
| Local tag `v1.0.1` | PASS |
| Remote tag `v1.0.1` | PASS |
| `go test ./...` | PASS |
| `go test -race ./...` | PASS |
| `go vet ./...` | PASS |
| `make build` | PASS |
| `make package` | PASS |
| `scripts/check-public-boundary.sh` | PASS |
| `make check-public-boundary` | PASS |
| Release asset checksum verification | PASS |
| Cosign checksum signature verification | PASS |
| GitHub artifact attestation verification | PASS |

## Boundary Review

The scripted public-boundary check passed:

```text
Public-boundary check passed: no obvious premium implementation leakage found.
```

Follow-up note: private implementation paths and premium report exporters have been removed from the public repository. Public commands now expose OSS core behavior and return explicit handoff errors for workflows that belong in `github.com/sairintechnologycom/pkgsafe-enterprise`.

## Known Limitations

- PkgSafe v1.0.1 remains npm-first GA. PyPI, Go, and Cargo coverage must not be described as npm-equivalent without separate GA evidence.
- Behavior analysis remains disabled by default. Heuristic mode is not real isolation, and isolated behavior support must fail closed when unavailable.
- The current boundary script is term-based. It caught no disallowed premium terms in implementation paths, but it does not prove semantic absence of premium implementation.
- Enterprise monetization work should continue in `github.com/sairintechnologycom/pkgsafe-enterprise`, not in this public repository.

## Final Classification

```text
v1.0.1_released: true
release_verification_passed: true
scripted_boundary_check_passed: true
manual_boundary_review_required: false
premium_leakage_found_by_script: false
```
