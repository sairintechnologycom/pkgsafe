# Auto-Updates & Go/Cargo Ecosystem Expansion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement automated background updates for the threat/vulnerability database and expand PkgSafe coverage to Go Modules (`go.mod`/`go.sum`) and Rust Cargo (`Cargo.toml`/`Cargo.lock`).

**Architecture:** 
1. **Auto-Updater:** Add a helper inside `internal/db` that checks the age of the local SQLite database file (`pkgsafe.db`). If it exceeds a configured age limit (e.g. 7 days), it triggers an asynchronous update from OSV in the background when network connectivity is available.
2. **Go Scanner:** Create `internal/scanner/golang` and `internal/deps/golang` to parse `go.mod` files and query proxy.golang.org for metadata.
3. **Cargo Scanner:** Create `internal/scanner/cargo` and `internal/deps/cargo` to parse `Cargo.toml`/`Cargo.lock` files and query crates.io for metadata.

**Tech Stack:** Go standard library, HTTP client, `golang.org/x/mod/modfile` (or lightweight custom regex modfile parser to keep external dependencies minimal), regex Cargo parser.

---

### Task 1: Background DB Auto-Updater
Check the database age before scans and update it in the background if stale.

**Files:**
- Modify: `internal/db/db.go`
- Modify: `internal/cli/update_db.go`
- Test: `internal/db/db_test.go`

**Step 1: Write the failing test**
Create a test in `internal/db/db_test.go` that verifies `ShouldUpdate` returns true if the database file was modified longer ago than the threshold.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/db/...`
Expected: Fail

**Step 3: Write minimal implementation**
Implement `ShouldUpdate(dbPath string, threshold time.Duration) bool` checking file stats and modification times. Wire a non-blocking background goroutine trigger into CLI scanning flows.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/db/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/db/ internal/cli/
git commit -m "feat(db): implement background threat database auto-updater"
```

---

### Task 2: Go Modules Dependency Parser & Scanner
Implement scanning capability for `go.mod` packages.

**Files:**
- Create: `internal/deps/golang/parser.go`
- Create: `internal/scanner/golang/scanner.go`
- Test: `internal/deps/golang/parser_test.go`
- Test: `internal/scanner/golang/scanner_test.go`

**Step 1: Write modfile parsing tests**
Write unit tests verifying dependency extraction from a standard `go.mod` file contents.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/deps/golang/...`
Expected: Fail (directory/parser does not exist)

**Step 3: Write parser and scanner implementation**
- Implement `ParseGoMod(content []byte)` extracting module import paths and versions.
- Implement scanner querying `https://proxy.golang.org/<module>/@v/<version>.info` for metadata, downloading the module zip from `https://proxy.golang.org/<module>/@v/<version>.zip` to analyze contents, and returning standard `types.ScanResult`.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/deps/golang/...` and `go test ./internal/scanner/golang/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/deps/golang/ internal/scanner/golang/
git commit -m "feat(go): add go.mod parser and proxy.golang.org scanner"
```

---

### Task 3: Rust Cargo Parser & Scanner
Implement scanning capability for Rust crates.

**Files:**
- Create: `internal/deps/cargo/parser.go`
- Create: `internal/scanner/cargo/scanner.go`
- Test: `internal/deps/cargo/parser_test.go`
- Test: `internal/scanner/cargo/scanner_test.go`

**Step 1: Write Cargo dependency parsing tests**
Write unit tests verifying crate parsing from a standard `Cargo.toml` and `Cargo.lock` content.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/deps/cargo/...`
Expected: Fail

**Step 3: Write parser and scanner implementation**
- Implement `ParseCargoLock(content []byte)` extracting crate names and versions.
- Implement scanner querying `https://crates.io/api/v1/crates/<crate>/<version>` for metadata, download zip, and evaluate policy criteria.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/deps/cargo/...` and `go test ./internal/scanner/cargo/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/deps/cargo/ internal/scanner/cargo/
git commit -m "feat(cargo): add Cargo.lock parser and crates.io scanner"
```

---

### Task 4: CLI Integration
Register subcommands and scan targets in the CLI.

**Files:**
- Modify: `cmd/pkgsafe/main.go`

**Step 1: Write CLI command routing test**
Verify command routes like `scan-go-deps` and `scan-cargo-deps` resolve properly.

**Step 2: Run test to verify it fails**
Run: `go test ./cmd/pkgsafe/...`
Expected: Fail

**Step 3: Write minimal implementation**
Wired `scan-go-deps` and `scan-cargo-deps` cases to `run` in `main.go`. Updated usage instructions.

**Step 4: Run test to verify it passes**
Run: `go test ./cmd/pkgsafe/...`
Expected: PASS

**Step 5: Commit**
```bash
git add cmd/pkgsafe/
git commit -m "feat(cli): wire up go and cargo scans in the main CLI entrypoint"
```
