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
