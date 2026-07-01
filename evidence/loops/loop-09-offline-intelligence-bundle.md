# Loop 9 Evidence: Offline Intelligence Bundle

Tracking issue: https://github.com/sairintechnologycom/pkgsafe/issues/26

Branch: `loop-09-offline-intelligence-bundle`

## Feature Spec

Add a signed offline intelligence bundle workflow for regulated and air-gapped
environments while keeping PkgSafe local-first and npm-first GA.

Commands added:

```bash
pkgsafe db export-bundle --output <path> [--db <path>] [--signing-key <key.pem>]
pkgsafe db verify-bundle [--key <pubkey.pem>] <path>
pkgsafe db import-bundle [--key <pubkey.pem>] [--db <path>] <path>
```

## Files Changed

Loop 9 files:

- `README.md`
- `cmd/pkgsafe/main.go`
- `docs/offline-intelligence-bundle.md`
- `internal/dbbundle/bundle.go`
- `internal/dbbundle/bundle_test.go`
- `evidence/loops/loop-09-offline-intelligence-bundle.md`

This branch is stacked on earlier loop work, so `git status` also shows files
from Loops 1-8.

## Already Implemented And Reused

- Existing SQLite advisory DB open/migration/store APIs in `internal/db`.
- Existing DB status command through `cli.DBStatus`.
- Existing OSV update command through `cli.UpdateDB`.
- Existing Ed25519 key generation, signing, public-key parsing, and signature
  verification helpers in `internal/enterprise`.
- Existing CLI usage and flag reordering patterns in `cmd/pkgsafe/main.go`.

## Newly Implemented

- `internal/dbbundle` package for exporting, verifying, and importing offline
  intelligence bundles.
- ZIP bundle layout:
  - `manifest.json`
  - `db/pkgsafe.db`
  - `checksums.txt`
  - `signature.sig` when `--signing-key` is supplied
- Manifest fields:
  - schema version
  - bundle kind
  - generated timestamp
  - PkgSafe version
  - DB path and SHA-256
  - vulnerability record count
  - indexed package count
  - ecosystem counts
  - last update metadata
  - freshness status
  - signature metadata
- Checksum verification for bundle contents.
- Ed25519 detached signature verification over `checksums.txt` when a trusted
  public key is provided.
- Import to default DB path or explicit `--db` path.
- Copy-pasteable docs for connected export and offline verify/import.

## Validation Commands Run

```bash
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
make build
make package
./dist/pkgsafe policy pack keygen --out /private/tmp/pkgsafe-loop09/bundle
./dist/pkgsafe db export-bundle --db /private/tmp/pkgsafe-loop09/pkgsafe.db --output /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip --signing-key /private/tmp/pkgsafe-loop09/bundle.key
./dist/pkgsafe db verify-bundle --key /private/tmp/pkgsafe-loop09/bundle.pub /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
./dist/pkgsafe db import-bundle /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip --key /private/tmp/pkgsafe-loop09/bundle.pub --db /private/tmp/pkgsafe-loop09/imported.db
go test ./internal/dbbundle -run TestVerifyBundleDetectsTampering -count=1
unzip -l /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
unzip -p /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip manifest.json
rg -n "secure sandbox|secure containment|full PyPI|PyPI GA|full Go|full Cargo|SaaS|billing|SSO|hosted service|behavior analysis enabled by default" README.md docs/offline-intelligence-bundle.md cmd/pkgsafe/main.go internal/dbbundle
```

## Validation Results

`go test ./...`: pass.

`go test -race ./...`: pass.

`go vet ./...`: pass.

`make build`: pass.

`make package`: pass.

Focused tamper test:

```text
ok  	github.com/sairintechnologycom/pkgsafe/internal/dbbundle	0.287s
```

Signed export:

```text
Offline intelligence bundle exported.
Output: /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
Vulnerability records: 0
Indexed packages: 0
Signed: enabled
```

Signed verify:

```text
Offline intelligence bundle verified.
Bundle: /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
Checksum: enabled
Signature present: enabled
Signature verified: enabled
Vulnerability records: 0
Indexed packages: 0
```

Signed import:

```text
Offline intelligence bundle imported.
Bundle: /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
Checksum: enabled
Signature verified: enabled
Vulnerability records: 0
```

Bundle contents:

```text
Archive:  /private/tmp/pkgsafe-loop09/pkgsafe-offline-bundle.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      160  01-01-1980 05:30   checksums.txt
    32768  01-01-1980 05:30   db/pkgsafe.db
      520  01-01-1980 05:30   manifest.json
       64  01-01-1980 05:30   signature.sig
---------                     -------
    33512                     4 files
```

Sample manifest:

```json
{
  "schema_version": "1.0",
  "bundle_kind": "offline-intelligence",
  "generated_at": "2026-07-01T02:48:04Z",
  "tool": "pkgsafe",
  "pkgsafe_version": "v0.2.0-beta.1-2-g6d0e114-dirty",
  "source": "local-db",
  "db_path": "db/pkgsafe.db",
  "db_sha256": "6b4d732c63413f336ba141e8ff9a8d8dd59fb162754e16b800c8929e52ea6014",
  "vulnerability_count": 0,
  "indexed_package_count": 0,
  "ecosystem_counts": {},
  "last_updates": {},
  "freshness": {},
  "signature": {
    "algorithm": "ed25519",
    "present": true
  }
}
```

## Wording Audit

Scoped audit command over Loop 9 code and docs returned no matches:

```bash
rg -n "secure sandbox|secure containment|full PyPI|PyPI GA|full Go|full Cargo|SaaS|billing|SSO|hosted service|behavior analysis enabled by default" README.md docs/offline-intelligence-bundle.md cmd/pkgsafe/main.go internal/dbbundle
```

Results:

- No secure sandboxing or secure containment claims added.
- No PyPI, Go, or Cargo GA claims added.
- No SaaS, billing, SSO, or hosted-service behavior added.
- No behavior-analysis default behavior changed.

## Review Results

- Useful for offline and regulated teams: pass. The workflow supports connected
  export and offline verify/import.
- Trust model clear: pass. Checksums are always verified; Ed25519 signatures are
  verified when a trusted key is provided.
- Feed freshness visible: pass. Manifest records last-update metadata and
  freshness states available in the local DB.
- Avoids network in offline import/verify: pass. Bundle verify/import operate on
  local ZIP and SQLite files only.
- Preserves npm-first GA: pass. This loop changes advisory DB transport, not
  ecosystem maturity.

## Known Limitations

- The sample bundle was exported from an empty temporary DB, so counts are zero.
  The code path also tests non-empty DB export/import through unit tests.
- `generated_at` reflects export time, so bundle bytes are not identical across
  separate exports. ZIP member timestamps are fixed for stable archive metadata.
- Signature verification is enforced when `--key` is provided. Regulated
  workflows should always pass `--key` to both verify and import.
- Offline scanning quality depends on the advisory data present before export.
  PkgSafe does not treat missing or stale advisory data as clean.

## Learning Loop

- Existing DB primitives and policy-pack signing utilities were sufficient for
  the first offline bundle implementation.
- The missing onboarding piece was a clear connected/export and offline/import
  doc with the key-handling steps spelled out.
- Future enterprise evidence may want a stricter import mode that requires a
  signature and trusted key by default for organization-managed environments.
- Future offline support should include bundle freshness policy thresholds and
  explicit organization trust-store guidance.

## Completion Criteria

- Offline bundle workflow works: complete.
- Tampering is detected: complete.
- All tests pass: complete.
- No SaaS introduced: complete.
