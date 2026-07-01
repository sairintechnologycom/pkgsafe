# Offline Intelligence Bundles

PkgSafe can export the local SQLite advisory database into a signed ZIP bundle
for regulated or air-gapped environments. This keeps the workflow local-first:
one connected machine updates the database, exports a bundle, and offline
machines verify and import that bundle before running offline scans.

## Connected Export

On a connected machine:

```bash
pkgsafe update-db --ecosystem all
pkgsafe db status
pkgsafe policy pack keygen --out ./pkgsafe-db-bundle
pkgsafe db export-bundle \
  --output ./pkgsafe-offline-intelligence.zip \
  --signing-key ./pkgsafe-db-bundle.key
```

The bundle contains:

- `manifest.json`: schema version, PkgSafe version, generation time, DB
  checksum, advisory counts, ecosystem counts, freshness metadata, and signature
  metadata.
- `db/pkgsafe.db`: the SQLite advisory database snapshot.
- `checksums.txt`: SHA-256 checksums for every signed payload file.
- `signature.sig`: an Ed25519 signature over `checksums.txt` when
  `--signing-key` is supplied.

Keep `pkgsafe-db-bundle.key` private. Distribute `pkgsafe-db-bundle.pub` to
offline verifiers through your normal internal trust process.

## Offline Verify And Import

On the offline machine:

```bash
pkgsafe db verify-bundle \
  --key ./pkgsafe-db-bundle.pub \
  ./pkgsafe-offline-intelligence.zip

pkgsafe db import-bundle \
  --key ./pkgsafe-db-bundle.pub \
  ./pkgsafe-offline-intelligence.zip

pkgsafe db status
pkgsafe scan-npm-package axios --offline
```

Use `--db <path>` when you want to import into a non-default database path:

```bash
pkgsafe db import-bundle \
  --key ./pkgsafe-db-bundle.pub \
  --db /opt/pkgsafe/pkgsafe.db \
  ./pkgsafe-offline-intelligence.zip
```

## Trust Model

`verify-bundle` and `import-bundle` always verify `checksums.txt` against the
bundle contents and check the database SHA-256 recorded in `manifest.json`.

When `--key` is provided, PkgSafe also verifies the detached Ed25519 signature
over `checksums.txt`. A signed bundle with the wrong public key fails
verification. For regulated workflows, provide `--key` during both verification
and import.

## Freshness

Freshness is based on the metadata already present in the exported database.
Run `pkgsafe update-db --ecosystem all` before export when you want a current
bundle. Offline import and verify do not contact OSV or package registries.

If the bundle was exported from an empty or stale database, PkgSafe preserves
that state and reports it in `manifest.json`; it does not silently treat missing
or stale advisory data as clean.
