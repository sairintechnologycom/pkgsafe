package registry

import (
	"net/http"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

type AuthRoundTripper struct {
	Transport http.RoundTripper
	Config    policy.RegistryConfig
}

func (art *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := art.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	// Add authorization header
	if err := AddAuthHeader(req, art.Config); err != nil {
		return nil, err
	}
	return transport.RoundTrip(req)
}

func NewAuthenticatedHTTPClient(cfg policy.RegistryConfig) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &AuthRoundTripper{
			Transport: http.DefaultTransport,
			Config:    cfg,
		},
	}
}
