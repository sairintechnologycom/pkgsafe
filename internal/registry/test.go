package registry

import (
	"fmt"
	"net/http"
	"strings"
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

type RoutingResult struct {
	Ecosystem       string
	Package         string
	NormalizedName  string
	RegistryName    string
	RegistryType    string
	RegistryURL     string
	PrivateMatch    bool
	PrivateRegistry string
	PublicFallback  bool
	Status          string
	Reason          string
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
		res.Reason = RedactSecrets(err.Error())
		return res, nil
	}

	// Apply authentication if method is configured
	if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
		if err := AddAuthHeader(req, regCfg); err != nil {
			res.Status = "FAILED"
			res.Reason = RedactSecrets(err.Error())
			return res, nil
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	res.Latency = time.Since(start)

	if err != nil {
		res.Status = "FAILED"
		res.Reason = RedactSecrets(fmt.Sprintf("Registry unreachable: %v", err))
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

func TestPackageRouting(ecosystem, packageName string, pol policy.Policy) (RoutingResult, error) {
	eco := normalizeEcosystem(ecosystem)
	if eco != "npm" && eco != "pypi" {
		return RoutingResult{}, fmt.Errorf("ecosystem must be npm or pypi")
	}
	if packageName == "" {
		return RoutingResult{}, fmt.Errorf("package name is required")
	}

	regName, regCfg := ResolveRegistry(eco, packageName, pol)
	res := RoutingResult{
		Ecosystem:    eco,
		Package:      packageName,
		RegistryName: regName,
		RegistryType: regCfg.Type,
		RegistryURL:  RedactURL(regCfg.URL),
		Status:       "OK",
	}
	if eco == "pypi" {
		res.NormalizedName = NormalizePyPIName(packageName)
	}

	if privateName, matched := matchingPrivateRegistry(eco, packageName, pol); matched {
		res.PrivateMatch = true
		res.PrivateRegistry = privateName
	}
	res.PublicFallback = res.PrivateMatch && (regCfg.Type == "public" || regName == "default")

	switch {
	case !regCfg.Enabled && regCfg.Type != "unknown":
		res.Status = "BLOCK"
		res.Reason = "registry is disabled by policy; public fallback is not allowed"
	case res.PublicFallback:
		res.Status = "BLOCK"
		res.Reason = fmt.Sprintf("private package must resolve from approved private registry %s; public fallback is not allowed", res.PrivateRegistry)
	case res.PrivateMatch && regCfg.Type != "private":
		res.Status = "BLOCK"
		res.Reason = fmt.Sprintf("private package matched %s but resolved to %s registry", res.PrivateRegistry, regCfg.Type)
	case regCfg.Type == "unknown":
		res.Status = "BLOCK"
		res.Reason = "registry is unknown by policy"
	}

	return res, nil
}

func normalizeEcosystem(ecosystem string) string {
	switch ecosystem {
	case "PyPI", "Pypi", "python":
		return "pypi"
	default:
		return ecosystem
	}
}

func matchingPrivateRegistry(ecosystem, packageName string, pol policy.Policy) (string, bool) {
	regs := pol.Registries.Registries[ecosystem]
	for name, cfg := range regs {
		if cfg.Type != "private" {
			continue
		}
		switch ecosystem {
		case "npm":
			scope := GetNPMScope(packageName)
			for _, sc := range cfg.Scopes {
				if strings.EqualFold(sc, scope) {
					return name, true
				}
			}
		case "pypi":
			if MatchPyPIPrefix(packageName, cfg.PackagePrefixes) {
				return name, true
			}
		}
	}
	return "", false
}
