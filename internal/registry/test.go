package registry

import (
	"fmt"
	"net/http"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/policy"
)

type TestResult struct {
	Name       string
	Type       string
	URL        string
	AuthMethod string
	TokenEnv   string
	Status     string // OK, FAILED
	Latency    time.Duration
	Reason     string
}

func TestRegistry(name string, pol policy.Policy) (TestResult, error) {
	var regCfg policy.RegistryConfig
	var regType string
	found := false

	// Search npm registries
	if pol.Registries.Registries != nil {
		if npmRegs, ok := pol.Registries.Registries["npm"]; ok {
			if cfg, ok := npmRegs[name]; ok {
				regCfg = cfg
				regType = "npm"
				found = true
			}
		}
		if !found {
			if pypiRegs, ok := pol.Registries.Registries["pypi"]; ok {
				if cfg, ok := pypiRegs[name]; ok {
					regCfg = cfg
					regType = "pypi"
					found = true
				}
			}
		}
	}

	if !found {
		return TestResult{}, fmt.Errorf("registry %q not found in policy configuration", name)
	}

	res := TestResult{
		Name:       name,
		Type:       regType,
		URL:        RedactURL(regCfg.URL),
		AuthMethod: regCfg.Auth.Method,
		TokenEnv:   regCfg.Auth.TokenEnv,
		Status:     "OK",
	}

	start := time.Now()
	req, err := http.NewRequest("GET", regCfg.URL, nil)
	if err != nil {
		res.Status = "FAILED"
		res.Reason = err.Error()
		return res, nil
	}

	// Apply authentication if method is configured
	if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
		if err := AddAuthHeader(req, regCfg); err != nil {
			res.Status = "FAILED"
			res.Reason = err.Error()
			return res, nil
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	res.Latency = time.Since(start)

	if err != nil {
		res.Status = "FAILED"
		res.Reason = fmt.Sprintf("Registry unreachable: %v", err)
		return res, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.Status = "FAILED"
		res.Reason = fmt.Sprintf("Authentication failed (HTTP %d)", resp.StatusCode)
		return res, nil
	}

	// Many registries return 404 for GET / or 400. That's fine as long as we're authenticated.
	if resp.StatusCode >= 500 {
		res.Status = "FAILED"
		res.Reason = fmt.Sprintf("Registry returned server error (HTTP %d)", resp.StatusCode)
		return res, nil
	}

	return res, nil
}
