# PkgSafe <VERSION> Release Notes

> Template. Copy into the GitHub release body and fill in the placeholders.
> For `v0.2.0-beta.1` this is the first **private beta** release candidate.

## Summary

One or two sentences on what this release is and who it is for.

## Stage

- Readiness stage: `<INTERNAL_ALPHA_READY | PRIVATE_BETA_READY | PUBLIC_BETA_READY | PRODUCTION_GA_READY>`
- Run `pkgsafe test production-readiness --json` and paste the `final_status`
  and `private_beta_recommendation` here.

## Highlights

- ...
- ...

## Known limitations

- Lifecycle behavior analysis is heuristic and best-effort — not a sandbox.
- See [docs/known-limitations.md](known-limitations.md) for the full list.

## Install

Download the archive for your platform from the assets below, or:

```sh
curl -fsSL https://github.com/sairintechnologycom/pkgsafe/releases/latest/download/install.sh | bash
pkgsafe version   # should print pkgsafe <VERSION> (<commit>)
```

## Verify release integrity

This release ships signed checksums, SBOMs, and build-provenance attestations.
See [docs/release-integrity.md](release-integrity.md) for full instructions.

```sh
# 1. Checksums
shasum -a 256 -c checksums.txt

# 2. Cosign keyless signature of the checksums file
cosign verify-blob --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.*/pkgsafe/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 3. Build provenance attestation
gh attestation verify <artifact> --owner sairintechnologycom
```

## Feedback

This is a beta. Please report issues using the templates in
[docs/beta-feedback.md](beta-feedback.md). Security vulnerabilities in PkgSafe
itself: follow [SECURITY.md](../SECURITY.md) private disclosure.

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for the full list of changes.
