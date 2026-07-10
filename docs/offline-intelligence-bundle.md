# Offline intelligence bundles

Keep scans working without the public internet.

1. On a **connected** machine: update the local advisory DB and export a ZIP.
2. On an **offline** machine: verify the ZIP, import it, scan with `--offline`.

Missing advisory data **fails closed** — PkgSafe will not treat unknown packages
as clean.

PkgSafe OSS bundles are checksum-verified ZIPs of the local SQLite DB. Signed
enterprise intelligence feeds live in the private enterprise distribution.

## Connected export

```bash
pkgsafe update-db --ecosystem all
pkgsafe db status
pkgsafe db export-bundle --output ./pkgsafe-offline-intelligence.zip
```

Bundle contents:

- `manifest.json` — version, times, DB checksum, counts, freshness
- `db/pkgsafe.db` — SQLite advisory snapshot
- `checksums.txt` — SHA-256 of payload files

## Offline verify and import

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

Both commands accept `--json` where noted in `pkgsafe --help`; `db status
--json` and `db verify-bundle --json` emit machine-readable reports for CI
and fleet tooling.

## Trust model

`verify-bundle` and `import-bundle` always verify `checksums.txt` against the
bundle contents and check the database SHA-256 recorded in `manifest.json`.
Verification additionally requires the expected bundle kind
(`offline-intelligence`) and a manifest schema version this build understands,
bounds how much data it will read from a bundle archive, and `import-bundle`
refuses payloads that are not SQLite databases.

Ed25519-signed bundles (signature creation, trusted-key verification, and
signature-required import) are implemented in the private `pkgsafe-enterprise`
distribution; the OSS build reports a signature's presence but refuses to
import signed bundles.

## Freshness

Freshness is based on the metadata already present in the exported database.
Run `pkgsafe update-db --ecosystem all` before export when you want a current
bundle. Offline import and verify do not contact OSV or package registries.

Two freshness views are reported:

- `manifest.json` records export-time freshness per sync key.
- `verify-bundle` and `import-bundle` re-evaluate the same timestamps at
  verification time (`freshness_at_verify`, with an overall `stale` flag),
  because a bundle exported fresh two weeks ago is stale today. `db status`
  reports the same per-key freshness for the local database and warns when
  advisory data is stale.

If the bundle was exported from an empty or stale database, PkgSafe preserves
that state and reports it in `manifest.json`; it does not silently treat missing
or stale advisory data as clean.
