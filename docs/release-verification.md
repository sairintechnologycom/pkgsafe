# Release Verification

Use these checks before trusting a downloaded PkgSafe release artifact.
npm and PyPI are public beta coverage. Go and Cargo coverage remains preview
and is not GA-equivalent yet.

## Download Release Assets

Pick the archive for your platform and download it with the release integrity
files. This Linux amd64 example pins v1.6.0:

```bash
VERSION=1.6.0
OS=linux
ARCH=amd64
ARCHIVE="pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/sairintechnologycom/pkgsafe/releases/download/v${VERSION}"

curl -LO "${BASE_URL}/${ARCHIVE}"
curl -LO "${BASE_URL}/checksums.txt"
curl -LO "${BASE_URL}/checksums.txt.sig"
curl -LO "${BASE_URL}/checksums.txt.pem"
```

For Windows, use `ARCHIVE="pkgsafe_${VERSION}_windows_amd64.zip"`.

## Checksums

Download `checksums.txt` and the archive for your platform into the same
directory.

```bash
# Linux
sha256sum -c checksums.txt

# macOS
shasum -a 256 -c checksums.txt
```

At least the archive you downloaded must report `OK`.

## SBOM

Published releases include SPDX SBOMs. Confirm the file exists and is valid
JSON:

```bash
jq '{spdxVersion, name, packages: (.packages | length)}' *.sbom.json
```

Local `make package` builds may include `dist/sbom.spdx.json`, which is a
minimal deterministic SBOM for local validation rather than a dependency-level
scan SBOM.

Evidence packs generated with `pkgsafe report evidence-pack` now include a
dependency-level SPDX document at `dependency-sbom.spdx.json`. Verify the
package hashes and SBOM integrity with:

```bash
pkgsafe report verify-evidence-pack --input pkgsafe-evidence-pack.zip
```

## Cosign Signature

Download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem`, then run:

```bash
cosign verify-blob --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

The command must print `Verified OK`.

## GitHub Provenance

Verify GitHub Artifact Attestation provenance for the downloaded archive:

```bash
gh attestation verify pkgsafe_<version>_<os>_<arch>.tar.gz --repo sairintechnologycom/pkgsafe
```

The attestation must resolve to the PkgSafe release workflow for the expected
repository.

GitHub-hosted provenance is a GA gate. If the repository is a user-owned private
repository, GitHub may reject attestation persistence with `Feature not available
for user-owned private repositories`; in that state the release can remain beta,
but it must not be promoted to GA.

## Binary Version

After extracting the archive, confirm the binary reports the expected version:

```bash
./pkgsafe version
```

A v1.6.0 release build reports:

```text
pkgsafe v1.6.0 (<commit>)
```

Local development builds may report a `-dev` version or `none` commit instead.

## Doctor

Run `doctor` to check local runtime readiness and connected advisory endpoints:

```bash
./pkgsafe doctor
```

If you are verifying in a restricted or offline environment, use the doctor
output to distinguish local binary readiness from registry or OSV reachability
problems.
