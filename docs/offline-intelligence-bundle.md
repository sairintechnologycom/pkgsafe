# Offline Intelligence Bundles

PkgSafe OSS can export the local SQLite advisory database into a checksum-
verified ZIP bundle. This keeps the workflow local-first: one connected machine
updates the database, exports a bundle, and offline machines verify and import
that bundle before running offline scans.

## Connected Export

On a connected machine:

```bash
pkgsafe update-db --ecosystem all
pkgsafe db status
pkgsafe db export-bundle --output ./pkgsafe-offline-intelligence.zip
```

The bundle contains:

- `manifest.json`: schema version, PkgSafe version, generation time, DB
  checksum, advisory counts, ecosystem counts, and freshness metadata.
- `db/pkgsafe.db`: the SQLite advisory database snapshot.
- `checksums.txt`: SHA-256 checksums for every payload file.

Signed enterprise intelligence bundles are implemented in the private
`pkgsafe-enterprise` distribution.

## Offline Verify And Import

On the offline machine:

```bash
pkgsafe db verify-bundle ./pkgsafe-offline-intelligence.zip
pkgsafe db import-bundle ./pkgsafe-offline-intelligence.zip
pkgsafe db status
pkgsafe scan-npm-package axios --offline
```

Use `--db <path>` when you want to import into a non-default database path:

```bash
pkgsafe db import-bundle \
  --db /opt/pkgsafe/pkgsafe.db \
  ./pkgsafe-offline-intelligence.zip
```

## Trust Model

`verify-bundle` and `import-bundle` always verify `checksums.txt` against the
bundle contents and check the database SHA-256 recorded in `manifest.json`.

## Freshness

Freshness is based on the metadata already present in the exported database.
Run `pkgsafe update-db --ecosystem all` before export when you want a current
bundle. Offline import and verify do not contact OSV or package registries.

If the bundle was exported from an empty or stale database, PkgSafe preserves
that state and reports it in `manifest.json`; it does not silently treat missing
or stale advisory data as clean.
