package policy

import (
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

func MatchScopedRule(rule ScopedRule, pkg types.PackageIdentity, regName string, requestedBy string) bool {
	if rule.Match.Ecosystem != "" && !strings.EqualFold(rule.Match.Ecosystem, pkg.Ecosystem) {
		return false
	}
	if rule.Match.Registry != "" && !strings.EqualFold(rule.Match.Registry, regName) {
		return false
	}
	if rule.Match.RequestedBy != "" && !strings.EqualFold(rule.Match.RequestedBy, requestedBy) {
		return false
	}
	if rule.Match.Package != "" {
		if !MatchPackagePattern(rule.Match.Package, pkg.Name) {
			return false
		}
	}
	return true
}

func MatchPackagePattern(pattern, name string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if pattern == name {
		return true
	}
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(name) >= len(prefix) && name[:len(prefix)] == prefix
	}
	return false
}
