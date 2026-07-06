package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestQueryMalformedJSONIsRetryable verifies a 200 response with an undecodable
// body is treated as transient (retryable), then fails after exhausting
// retries rather than silently returning no vulnerabilities.
func TestQueryMalformedJSONIsRetryable(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns": [ this is not json`))
	}))
	defer srv.Close()

	_, err := testClient(srv.URL, 2).Query(context.Background(), QueryRequest{})
	if err == nil {
		t.Fatal("expected error for undecodable OSV response")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("decode failure should retry to exhaustion (3 attempts), got %d", got)
	}
}

// TestQueryTransportErrorRetryable points the client at a closed server so the
// transport fails immediately; the error must be retried and then surfaced.
func TestQueryTransportErrorRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	_, err := testClient(url, 1).Query(context.Background(), QueryRequest{})
	if err == nil {
		t.Fatal("expected transport error when server is down")
	}
}

// TestQueryContextCancelledDuringBackoff ensures a cancelled context aborts the
// retry wait promptly instead of sleeping through the backoff.
func TestQueryContextCancelledDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError) // always transient
	}))
	defer srv.Close()

	c := &Client{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		BaseURL:      srv.URL,
		MaxRetries:   5,
		RetryBackoff: time.Hour, // would hang for an hour if cancellation is ignored
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() { _, err := c.Query(ctx, QueryRequest{}); done <- err }()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Query did not honor context cancellation during backoff")
	}
}
