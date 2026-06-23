package policy

import (
	"strings"
	"time"
)

func FindBlockedPackageRule(pol Policy, ecosystem string, pkgName string, version string, regName string) (BlockedPackageRule, bool) {
	for _, rule := range pol.BlockedPackageRules {
		// Verify name pattern matching
		if !MatchPackagePattern(rule.Name, pkgName) {
			continue
		}
		// Verify version range matching
		if rule.VersionRange != "" && rule.VersionRange != "*" && version != "" {
			if !matchVersionRange(version, rule.VersionRange) {
				continue
			}
		}
		// Verify registry matching
		if rule.Registry != "" && !strings.EqualFold(rule.Registry, regName) {
			continue
		}
		// Verify expiration
		if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
			continue
		}
		return rule, true
	}
	return BlockedPackageRule{}, false
}
