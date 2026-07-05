package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(baseURL string, maxRetries int) *Client {
	return &Client{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		BaseURL:      baseURL,
		MaxRetries:   maxRetries,
		RetryBackoff: time.Millisecond, // keep tests fast
	}
}

func TestQueryRetriesThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			http.Error(w, "boom", http.StatusInternalServerError) // transient 5xx
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-xxxx"}]}`))
	}))
	defer srv.Close()

	vulns, err := testClient(srv.URL, 2).Query(context.Background(), QueryRequest{})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-xxxx" {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestQueryRateLimitedExhaustsAndFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "slow down", http.StatusTooManyRequests) // 429, always
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, 1).Query(context.Background(), QueryRequest{})
	if err == nil {
		t.Fatal("expected error when OSV stays rate-limited")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 attempts (1 retry), got %d", got)
	}
}

func TestQueryNotFoundIsCleanNoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer srv.Close()

	vulns, err := testClient(srv.URL, 3).Query(context.Background(), QueryRequest{})
	if err != nil || vulns != nil {
		t.Fatalf("expected nil,nil for 404, got %v / %v", vulns, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("404 must not retry, got %d attempts", got)
	}
}

func TestQueryClientErrorNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad", http.StatusBadRequest) // 400, non-retryable
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, 3).Query(context.Background(), QueryRequest{})
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("400 must not retry, got %d attempts", got)
	}
}
