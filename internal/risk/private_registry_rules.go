package risk

import (
	"fmt"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func CheckPrivateRegistryRules(pkg types.PackageIdentity, regName string, regCfg policy.RegistryConfig, pol policy.Policy) []types.Reason {
	var findings []types.Reason

	// 1. HTTP registry URL warning/block
	if strings.HasPrefix(regCfg.URL, "http://") {
		// HTTP is insecure, warn or block
		findings = append(findings, types.Reason{
			ID:          "http_registry_warning",
			Severity:    "high",
			Description: fmt.Sprintf("Registry URL %s uses insecure HTTP protocol", regCfg.URL),
			Evidence:    regCfg.URL,
			ScoreImpact: 40,
		})
	}

	// 2. Public registry use for internal scope/prefix
	isPublic := regCfg.Type == "public" || regName == "default"
	
	// Check scope for NPM
	if pkg.Ecosystem == "npm" {
		scope := getScope(pkg.Name)
		if scope != "" {
			// Find if this scope belongs to any private registry
			for otherName, otherCfg := range pol.Registries.Registries["npm"] {
				if otherCfg.Type == "private" {
					for _, s := range otherCfg.Scopes {
						if strings.EqualFold(s, scope) {
							// Confirmed: scope maps to a private registry
							if isPublic {
								findings = append(findings, types.Reason{
									ID:          "private_scope_public_registry",
									Severity:    "critical",
									Description: fmt.Sprintf("Package scope %s must resolve from approved private registry %s", scope, otherName),
									Evidence:    scope,
									ScoreImpact: 100,
								})
								
								// Also triggers dependency confusion
								findings = append(findings, types.Reason{
									ID:          "dependency_confusion_candidate",
									Severity:    "critical",
									Description: "Package matching internal scope resolved from public registry",
									Evidence:    pkg.Name,
									ScoreImpact: 100,
								})
							}
						}
					}
				}
			}
		}
	}

	// Check prefix for PyPI
	if pkg.Ecosystem == "pypi" {
		// Find if this name matches any private registry prefix
		for otherName, otherCfg := range pol.Registries.Registries["pypi"] {
			if otherCfg.Type == "private" {
				for _, pref := range otherCfg.PackagePrefixes {
					if strings.HasPrefix(pkg.Name, pref) {
						if isPublic {
							findings = append(findings, types.Reason{
								ID:          "private_scope_public_registry",
								Severity:    "critical",
								Description: fmt.Sprintf("Package prefix %s must resolve from approved private registry %s", pref, otherName),
								Evidence:    pref,
								ScoreImpact: 100,
							})

							findings = append(findings, types.Reason{
								ID:          "dependency_confusion_candidate",
								Severity:    "critical",
								Description: "Package matching internal prefix resolved from public registry",
								Evidence:    pkg.Name,
								ScoreImpact: 100,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

func getScope(name string) string {
	if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		return strings.SplitN(name, "/", 2)[0]
	}
	return ""
}
