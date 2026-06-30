# Release Verification

Use these checks before trusting a downloaded PkgSafe release artifact.

## Checksums

Download `checksums.txt` and the archive for your platform into the same
directory.

```bash
sha256sum -c checksums.txt
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
minimal deterministic SBOM for local validation rather than the rich per-archive
release SBOM.

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
