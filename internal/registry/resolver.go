package registry

import (
	"regexp"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// NormalizePyPIName normalizes PyPI package names according to Python package normalization rules:
// - lowercase
// - runs of -, _, . normalize to a single -
func NormalizePyPIName(name string) string {
	name = strings.ToLower(name)
	reg := regexp.MustCompile(`[-_.]+`)
	return reg.ReplaceAllString(name, "-")
}

func GetNPMScope(pkgName string) string {
	if strings.HasPrefix(pkgName, "@") && strings.Contains(pkgName, "/") {
		parts := strings.SplitN(pkgName, "/", 2)
		return parts[0]
	}
	return ""
}

func MatchPyPIPrefix(pkgName string, prefixes []string) bool {
	normName := NormalizePyPIName(pkgName)
	for _, pref := range prefixes {
		normPref := NormalizePyPIName(pref)
		if strings.HasPrefix(normName, normPref) {
			return true
		}
	}
	return false
}

func ResolveRegistry(ecosystem string, pkgName string, pol policy.Policy) (string, policy.RegistryConfig) {
	eco := strings.ToLower(ecosystem)
	configs, exists := pol.Registries.Registries[eco]
	if !exists {
		// return default fallback
		return "default", DefaultRegistryConfig(eco)
	}

	// 1. Check private registries with scope/prefix match
	for name, cfg := range configs {
		if name == "default" {
			continue
		}
		if eco == "npm" {
			scope := GetNPMScope(pkgName)
			if scope != "" {
				for _, sc := range cfg.Scopes {
					if strings.EqualFold(sc, scope) {
						return name, cfg
					}
				}
			}
		} else if eco == "pypi" {
			if MatchPyPIPrefix(pkgName, cfg.PackagePrefixes) {
				return name, cfg
			}
		}
	}

	// 2. Fallback to default (even if disabled)
	if defCfg, exists := configs["default"]; exists {
		return "default", defCfg
	}

	return "default", DefaultRegistryConfig(eco)
}

func DefaultRegistryConfig(ecosystem string) policy.RegistryConfig {
	if strings.ToLower(ecosystem) == "npm" {
		return policy.RegistryConfig{
			URL:     "https://registry.npmjs.org/",
			Type:    "public",
			Enabled: true,
		}
	}
	return policy.RegistryConfig{
		URL:       "https://pypi.org/pypi/",
		SimpleURL: "https://pypi.org/simple/",
		Type:      "public",
		Enabled:   true,
	}
}
