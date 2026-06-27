# Release Integrity & Supply-Chain Provenance

Every tagged PkgSafe release is built and signed by the project's GitHub Actions
release workflow (`.github/workflows/release.yml`), not on a maintainer's laptop.
This document explains what each release artifact is and how to verify it before
you trust a binary.

You do **not** need every step. The fastest useful check is the checksum. The
cosign signature and build-provenance attestation give you stronger guarantees
about *who* produced the artifacts.

## What ships in a release

Each release attached to the GitHub Releases page contains:

| Artifact | What it is |
|----------|------------|
| `pkgsafe_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) | Per-platform archive containing the `pkgsafe` binary. Built for linux/darwin/windows on amd64/arm64. |
| `checksums.txt` | SHA-256 checksums of every archive, one per line. |
| `checksums.txt.sig` | Keyless cosign signature over `checksums.txt`. |
| `checksums.txt.pem` | The Fulcio-issued signing certificate (public, short-lived) that produced the signature. |
| `*.sbom.json` (one per archive, SPDX) | Software Bill of Materials describing the contents of each archive. |
| Build-provenance attestation | SLSA provenance for `dist/*`, stored as a GitHub Artifact Attestation (not a file on the release page; queried with `gh attestation verify`). |

Because the signature covers `checksums.txt`, and `checksums.txt` covers every
archive, verifying the signature once transitively protects all the binaries.

Pin a specific version in commands below by exporting it, e.g.:

```bash
export VERSION=0.2.0-beta.1
export OS=linux ARCH=amd64        # or darwin/arm64, windows/amd64, etc.
export ARCHIVE=pkgsafe_${VERSION}_${OS}_${ARCH}.tar.gz
```

## 1. Verify checksums

Download `checksums.txt` and your archive into the same directory, then:

```bash
# Linux
sha256sum -c checksums.txt

# macOS
shasum -a 256 -c checksums.txt
```

`-c` reports `OK` for each file it finds and verifies, and ignores lines for
archives you didn't download. To check just one file:

```bash
grep "  ${ARCHIVE}\$" checksums.txt | sha256sum -c -    # Linux
grep "  ${ARCHIVE}\$" checksums.txt | shasum -a 256 -c -  # macOS
```

A checksum only proves the file matches what `checksums.txt` says. To trust
`checksums.txt` itself, verify its signature (next section).

## 2. Verify the cosign keyless signature

PkgSafe uses **keyless** cosign signing. There is no long-lived private key to
leak. At release time the workflow obtains a short-lived OIDC token from GitHub
Actions, Sigstore's **Fulcio** CA issues an ephemeral certificate bound to the
workflow identity, and the signature is logged in the **Rekor** public
transparency log. Verification checks that the signature is valid, that the
certificate was issued by Fulcio to the expected workflow identity, and that the
entry exists in Rekor.

Install cosign (`brew install cosign`, or see the
[Sigstore docs](https://docs.sigstore.dev/cosign/installation/)), download
`checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem` into one directory,
then run the command verbatim from `.goreleaser.yaml`:

```bash
cosign verify-blob --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

A successful run prints `Verified OK`. The flags assert:

- `--certificate-oidc-issuer https://token.actions.githubusercontent.com` — the
  signing identity came from GitHub Actions' OIDC issuer, not some other source.
- `--certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*'` — the
  certificate's identity (the workflow that signed) matches a pkgsafe release
  workflow.

If `verify-blob` succeeds, you can trust `checksums.txt`, and therefore (via
step 1) every archive it lists.

## 3. Verify build provenance

The release workflow runs `actions/attest-build-provenance@v2` over `dist/*`,
producing a signed **SLSA build provenance** attestation stored as a GitHub
Artifact Attestation. Provenance proves *where and how* an artifact was built:
that this exact binary was produced by the pkgsafe release workflow running in
GitHub Actions against the repository's source — not built locally and uploaded
by hand.

Verify with the GitHub CLI (`gh auth login` first if needed):

```bash
gh attestation verify "${ARCHIVE}" --owner niyam-ai
```

You can also verify against the full repository:

```bash
gh attestation verify "${ARCHIVE}" --repo niyam-ai/pkgsafe
```

`gh` downloads the attestation from GitHub, checks the artifact's digest against
the signed provenance, and confirms the Sigstore signature and identity. A
successful run prints a summary including the workflow and repository that built
the artifact.

Checksums and the cosign signature prove integrity and *who signed*; provenance
proves *how it was built*. Together they cover the supply chain from source to
download.

## 4. SBOM

Each archive ships with an SPDX-format SBOM (`*.sbom.json`), generated per
archive by [Syft](https://github.com/anchore/syft) during the release. The SBOM
enumerates the components and dependencies detected in the archive, so you can
feed it to vulnerability scanners or audit what a release contains.

Inspect it with any JSON tool:

```bash
# List package names + versions
jq '.packages[] | {name, versionInfo}' pkgsafe_<version>_<os>_<arch>.sbom.json

# SPDX version + document name
jq '{spdxVersion, name}' pkgsafe_<version>_<os>_<arch>.sbom.json
```

Or load it into an SBOM-aware scanner, e.g.:

```bash
grype sbom:./pkgsafe_<version>_<os>_<arch>.sbom.json
```

> Note: a local `make package` build emits a minimal placeholder
> `dist/sbom.spdx.json` (a single self-referential package) so the packaging
> pipeline has a deterministic artifact. The rich, per-archive Syft SBOMs are
> produced only by the GoReleaser release pipeline and are what you should rely
> on for published releases.

## 5. Reproducible build notes

PkgSafe builds are configured to be as reproducible as practical, but we do not
yet claim bit-for-bit reproducibility. Here is the honest state.

**What improves reproducibility today:**

- `-trimpath` removes absolute filesystem paths from the binary, so the build
  does not depend on the checkout location.
- `CGO_ENABLED=0` produces a static, pure-Go binary with no C toolchain or
  system library variance.
- `-ldflags "-s -w"` strips the symbol table and DWARF debug info, removing a
  source of environment-dependent bytes.
- Module dependencies are pinned by hash in `go.sum`, so the dependency graph is
  fixed for a given commit.
- The release embeds only the version tag and short commit via `-ldflags -X`,
  both derived from the tagged source — not from the build machine's clock or
  environment.

**What is *not* guaranteed reproducible today:**

- The Go toolchain is installed with `actions/setup-go` at `go-version: 'stable'`,
  which floats to whatever the current stable Go release is. Two builds at
  different times may use different compiler versions and produce different
  bytes. The toolchain version is **not** pinned to an exact patch release.
- Builds run on GitHub-hosted `ubuntu-latest` runners; the runner image is not
  pinned, so OS-level build inputs can change over time.
- We do not currently publish a documented, independently re-runnable
  "rebuild this exact binary" procedure, and we have not verified bit-for-bit
  equality across independent builds.

In short: integrity and provenance are verifiable today (sections 1–3).
Full bit-for-bit reproducibility is a goal, not a current guarantee. If you need
it, pin the Go toolchain to an exact version and the runner image to a fixed tag,
and rebuild from the tagged source with the flags above.
