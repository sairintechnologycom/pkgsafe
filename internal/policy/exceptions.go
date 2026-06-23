package policy

import (
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func (e Exception) IsExpired() bool {
	if e.AllowedUntil.IsZero() {
		return true
	}
	return time.Now().After(e.AllowedUntil)
}

func FindActiveException(pol Policy, pkg types.PackageIdentity, env string) (Exception, bool) {
	for _, exc := range pol.Exceptions {
		if exc.IsExpired() {
			continue
		}
		if exc.Ecosystem != "" && !strings.EqualFold(exc.Ecosystem, pkg.Ecosystem) {
			continue
		}
		if !MatchPackagePattern(exc.Package, pkg.Name) {
			continue
		}
		if exc.VersionRange != "" && exc.VersionRange != "*" && pkg.Version != "" {
			if !matchVersionRange(pkg.Version, exc.VersionRange) {
				continue
			}
		}
		if len(exc.AppliesTo.Environments) > 0 && env != "" {
			envMatched := false
			for _, e := range exc.AppliesTo.Environments {
				if strings.EqualFold(e, env) {
					envMatched = true
					break
				}
			}
			if !envMatched {
				continue
			}
		}
		return exc, true
	}
	return Exception{}, false
}

func matchVersionRange(version, constraintStr string) bool {
	c, err := semver.NewConstraint(constraintStr)
	if err != nil {
		return false
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return c.Check(v)
}
