# Loop 7 — GitHub Action and Release Engineering Hardening

Date: 2026-07-12

## Scope

- Pinned CI and release workflow actions to commit SHAs.
- Pinned the Go toolchain to `1.25.0`.
- Added a `make fmt-check` release gate and used it in CI/release validation.
- Made the composite GitHub Action fail fast on formatting drift.
- Removed raw argument logging from the GitHub Action entrypoint.
- Added a real top-level `--help`/`-h`/`help` path that exits successfully.

## Pinned action refs

- `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`
- `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff`
- `golangci/golangci-lint-action@55c2c1448f86e01eaae002a5a3a9624417608d84`
- `sigstore/cosign-installer@f713795cb21599bc4e5c4b58cbad1da852d7eeb9`
- `anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610`
- `goreleaser/goreleaser-action@e435ccd777264be153ace6237001ef4d979d3a7a`
- `actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45`
- `github/codeql-action/upload-sarif@641a925cfafe92d0fdf8b239ba4053e3f8d99d6d`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`

## Validation

Commands executed:

- `make fmt-check`
- `env GOCACHE=/private/tmp/pkgsafe-gocache go run ./cmd/pkgsafe --help >/dev/null`
- `env GOCACHE=/private/tmp/pkgsafe-gocache go test ./...`
- `env GOCACHE=/private/tmp/pkgsafe-gocache go test -race ./...`
- `env GOCACHE=/private/tmp/pkgsafe-gocache go vet ./...`

Results:

- `make fmt-check` — PASS
- `pkgsafe --help` — PASS, exit code 0
- `go test ./...` — PASS
- `go test -race ./...` — PASS
- `go vet ./...` — PASS

## Evidence observed

- CI and release workflows no longer depend on mutable Go/tooling tags.
- The GitHub Action no longer prints raw argument values.
- Formatting drift in the Go tree now fails the release gate.

## Known limitations

- Documentation examples still use short action tags in some places for readability.
- Release workflows are only as deterministic as the GitHub-hosted runner image they execute on.
