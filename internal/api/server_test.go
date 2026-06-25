package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/types"
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

func TestScanEndpoint(t *testing.T) {
	// Seed a temporary home directory for cache loading
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Pre-create cache dir structure to avoid any write issues
	err := os.MkdirAll(filepath.Join(tmpHome, ".pkgsafe"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Prepare cache store
	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}

	// Seed npm package cached result
	npmResult := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "test-npm-pkg",
			Version:   "1.0.0",
		},
		Score:    0,
		Decision: types.DecisionAllow,
		Sandbox: types.SandboxSummary{
			Enabled:   true,
			Available: true,
		},
	}
	if err := store.Put(npmResult); err != nil {
		t.Fatalf("failed to seed npm cache: %v", err)
	}

	// Seed PyPI package cached result
	pypiResult := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "pypi",
			Name:      "test-pypi-pkg",
			Version:   "2.0.0",
		},
		Score:    10,
		Decision: types.DecisionWarn,
		Sandbox: types.SandboxSummary{
			Enabled:   false,
			Available: false,
		},
	}
	if err := store.Put(pypiResult); err != nil {
		t.Fatalf("failed to seed pypi cache: %v", err)
	}

	cfg := Config{
		Offline: true,
	}
	server := NewServer(cfg)

	t.Run("Scan NPM Package Successfully", func(t *testing.T) {
		reqBody, _ := json.Marshal(ScanRequest{
			Ecosystem: "npm",
			Name:      "test-npm-pkg",
			Version:   "1.0.0",
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/scan", bytes.NewReader(reqBody))

		server.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		var resp types.ScanResult
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}

		if resp.Package.Name != "test-npm-pkg" || resp.Package.Version != "1.0.0" || resp.Package.Ecosystem != "npm" {
			t.Fatalf("unexpected scanned package response: %+v", resp)
		}
	})

	t.Run("Scan PyPI Package Successfully", func(t *testing.T) {
		reqBody, _ := json.Marshal(ScanRequest{
			Ecosystem: "pypi",
			Name:      "test-pypi-pkg",
			Version:   "2.0.0",
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/scan", bytes.NewReader(reqBody))

		server.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		var resp types.ScanResult
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}

		if resp.Package.Name != "test-pypi-pkg" || resp.Package.Version != "2.0.0" || resp.Package.Ecosystem != "pypi" {
			t.Fatalf("unexpected scanned package response: %+v", resp)
		}
	})

	t.Run("Missing Name Validation", func(t *testing.T) {
		reqBody, _ := json.Marshal(ScanRequest{
			Ecosystem: "npm",
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/scan", bytes.NewReader(reqBody))

		server.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", rec.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}

		if resp["error"] != "name is required" {
			t.Fatalf("expected error 'name is required', got '%s'", resp["error"])
		}
	})

	t.Run("Invalid Ecosystem Validation", func(t *testing.T) {
		reqBody, _ := json.Marshal(ScanRequest{
			Ecosystem: "invalid-eco",
			Name:      "somepkg",
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/scan", bytes.NewReader(reqBody))

		server.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", rec.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}

		if resp["error"] != "invalid ecosystem: must be npm or pypi" {
			t.Fatalf("expected invalid ecosystem error, got '%s'", resp["error"])
		}
	})

	t.Run("Method Not Allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/scan", nil)

		server.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", rec.Code)
		}
	})
}
