package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	// MaxRetries is the number of additional attempts after the first on a
	// transient failure (network error, 429, or 5xx). Defaults to 2.
	MaxRetries int
	// RetryBackoff is the base delay between attempts; it grows linearly with
	// the attempt number. Defaults to 500ms.
	RetryBackoff time.Duration
}

// OSVBaseURLEnv overrides the OSV API base URL (e.g. for a private OSV mirror
// or for testing). When unset, the public OSV API is used.
const OSVBaseURLEnv = "PKGSAFE_OSV_BASEURL"

var NewClient = func() *Client {
	baseURL := "https://api.osv.dev/v1"
	if v := os.Getenv(OSVBaseURLEnv); v != "" {
		baseURL = v
	}
	return &Client{
		HTTPClient:   &http.Client{Timeout: 15 * time.Second},
		BaseURL:      baseURL,
		MaxRetries:   2,
		RetryBackoff: 500 * time.Millisecond,
	}
}

func (c *Client) Query(ctx context.Context, req QueryRequest) ([]Vulnerability, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	backoff := c.RetryBackoff
	if backoff == 0 {
		backoff = 500 * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retrying, but honor context cancellation.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff * time.Duration(attempt)):
			}
		}

		vulns, retryable, err := c.queryOnce(ctx, b)
		if err == nil {
			return vulns, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, fmt.Errorf("osv api unavailable after %d attempts: %w", c.MaxRetries+1, lastErr)
}

// queryOnce performs a single OSV query. The retryable flag reports whether the
// error is transient (network failure, 429 rate limit, or 5xx) and worth a retry.
func (c *Client) queryOnce(ctx context.Context, body []byte) (vulns []Vulnerability, retryable bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		// Transport-level failures (DNS, connection refused, timeout) are transient.
		return nil, true, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, true, fmt.Errorf("osv api rate limited: status 429")
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("osv api server error: status %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("osv api error: status %d", resp.StatusCode)
	}

	var qresp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&qresp); err != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, true, fmt.Errorf("decode osv response: %w", err)
	}
	return qresp.Vulns, false, nil
}
