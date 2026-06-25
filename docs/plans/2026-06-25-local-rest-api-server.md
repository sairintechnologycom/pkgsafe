# Local REST API Server Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a secure, local-only HTTP REST API server (`pkgsafe serve-api`) to expose PkgSafe scans, status, and policy verification to IDE extensions and third-party tools.

**Architecture:** Create a new `internal/api` package that hosts the HTTP server, handles API endpoints (`/api/v1/status`, `/api/v1/scan`, `/api/v1/policy`), enforces local-only IP access control and optional bearer token checks, and delegates scanning tasks to standard `snpm` and `spypi` scanner components.

**Tech Stack:** Go standard library (`net/http`, `net/http/httptest`), Go `flag` package, JSON unmarshaling/marshaling.

---

### Task 1: API Server Scaffold & Status Endpoint
Define the server configuration, structure, and implement the `/api/v1/status` endpoint.

**Files:**
- Create: `internal/api/server.go`
- Test: `internal/api/server_test.go`

**Step 1: Write the failing test**
Create a test in `internal/api/server_test.go` verifying that `/api/v1/status` returns the expected JSON containing version information and configuration.

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusEndpoint(t *testing.T) {
	cfg := Config{
		Version: "0.1.0",
		Commit:  "test-commit",
	}
	server := NewServer(cfg)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/status", nil)

	server.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["version"] != "0.1.0" || resp["commit"] != "test-commit" {
		t.Fatalf("unexpected version/commit response: %v", resp)
	}
}
```

**Step 2: Run test to verify it fails**
Run: `go test ./internal/api/...`
Expected: Fail (package api does not exist yet)

**Step 3: Write minimal implementation**
Create `internal/api/server.go` with the Config struct, Server struct, Router setup, and the status handler.

```go
package api

import (
	"encoding/json"
	"net/http"
)

type Config struct {
	Port           string
	Token          string
	DefaultPolicy  string
	DefaultMode    string
	Offline        bool
	Version        string
	Commit         string
}

type Server struct {
	cfg    Config
	mux    *http.ServeMux
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Router() *http.ServeMux {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
		"commit":  s.cfg.Commit,
	})
}
```

**Step 4: Run test to verify it passes**
Run: `go test ./internal/api/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/api/
git commit -m "feat(api): scaffold REST API server and status endpoint"
```

---

### Task 2: Implement Scan Package Endpoint
Implement the `/api/v1/scan` POST endpoint, routing checks to `npm` or `pypi` scanners.

**Files:**
- Modify: `internal/api/server.go`
- Test: `internal/api/server_test.go`

**Step 1: Write the failing test**
Create a test in `internal/api/server_test.go` verifying that `POST /api/v1/scan` resolves the requested package (using offline/cached mock parameters to avoid hits to live registries).

**Step 2: Run test to verify it fails**
Run: `go test ./internal/api/...`
Expected: Fail (no route for `/api/v1/scan`)

**Step 3: Write minimal implementation**
In `internal/api/server.go`, add route `/api/v1/scan`, scan request structures, and delegate to scanner packages `snpm` and `spypi`. Support checking if package is offline, and return `types.ScanResult`.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/api/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/api/
git commit -m "feat(api): add v1 scan endpoint delegating to npm/pypi scanners"
```

---

### Task 3: Implement Policy Endpoint & Local Token Auth middleware
Implement `/api/v1/policy` endpoint and middleware for local loopback restriction and Bearer token security.

**Files:**
- Modify: `internal/api/server.go`
- Test: `internal/api/server_test.go`

**Step 1: Write the failing test**
Add tests verifying:
1. Non-localhost requests are rejected if we filter remote IPs (mocking RemoteAddr).
2. Requests fail with HTTP 401 when the server starts with a token but the request has no/invalid Bearer token.
3. `/api/v1/policy` returns resolved policy JSON.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/api/...`
Expected: Fail

**Step 3: Write minimal implementation**
Implement Middleware functions:
- `localhostOnly(next http.Handler) http.Handler`: verifies RemoteAddr is local.
- `tokenAuth(token string, next http.Handler) http.Handler`: verifies Authorization header.
Wired into handlers. Implement `handlePolicy` parsing policy config and returning resolved policy.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/api/...`
Expected: PASS

**Step 5: Commit**
```bash
git add internal/api/
git commit -m "feat(api): add policy endpoint and request authorization security middleware"
```

---

### Task 4: CLI Integration
Wire up the `serve-api` subcommand inside the main Go CLI binary.

**Files:**
- Modify: `cmd/pkgsafe/main.go`
- Modify: `cmd/pkgsafe/main_test.go`

**Step 1: Write the failing test**
Add command parsing tests to `cmd/pkgsafe/main_test.go` checking that `serve-api` subcommand parsing parses `--port` and `--token` flags correctly.

**Step 2: Run test to verify it fails**
Run: `go test ./cmd/pkgsafe/...`
Expected: Fail (serve-api command not parsed/implemented)

**Step 3: Write minimal implementation**
Add `serve-api` case in `run` and implement `cmdServeAPI` parsing flags and invoking `api.Serve`.

```go
func cmdServeAPI(args []string) error {
    // parse --port, --token, --policy, --mode, --offline
    // start server using api.Serve
}
```

**Step 4: Run test to verify it passes**
Run: `go test ./cmd/pkgsafe/...`
Expected: PASS

**Step 5: Commit**
```bash
git add cmd/pkgsafe/
git commit -m "feat(cli): wire up serve-api command flag parsing and routing"
```
