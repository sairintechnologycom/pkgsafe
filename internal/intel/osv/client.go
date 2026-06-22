package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	HTTPClient *http.Client
	BaseURL    string
}

var NewClient = func() *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		BaseURL:    "https://api.osv.dev/v1",
	}
}

func (c *Client) Query(ctx context.Context, req QueryRequest) ([]Vulnerability, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/query", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api error: status %d", resp.StatusCode)
	}

	var qresp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&qresp); err != nil {
		return nil, err
	}
	return qresp.Vulns, nil
}
