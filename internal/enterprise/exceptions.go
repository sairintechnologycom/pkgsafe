package enterprise

import (
	"fmt"
	"time"
	
	"github.com/Masterminds/semver/v3"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"gopkg.in/yaml.v3"
)

type AppliesTo = policy.AppliesTo
type Exception = policy.Exception
type ExceptionsConfig = policy.ExceptionsConfig

func ParseExceptions(data []byte) (ExceptionsConfig, error) {
	var cfg ExceptionsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// try unmarshaling directly as array of exceptions
		var list []Exception
		if err2 := yaml.Unmarshal(data, &list); err2 == nil {
			return ExceptionsConfig{Exceptions: list}, nil
		}
		return cfg, fmt.Errorf("unmarshal exceptions: %w", err)
	}
	return cfg, nil
}

func ValidateExceptions(cfg ExceptionsConfig) error {
	for i, exc := range cfg.Exceptions {
		if exc.ID == "" {
			return fmt.Errorf("exception %d: id is required", i)
		}
		if exc.AllowedUntil.IsZero() {
			return fmt.Errorf("exception %s: allowed_until (expiry) is required", exc.ID)
		}
		if exc.ApprovedBy == "" {
			return fmt.Errorf("exception %s: approved_by (approver) is required", exc.ID)
		}
		if exc.Reason == "" {
			return fmt.Errorf("exception %s: reason is required", exc.ID)
		}
		if exc.Package == "" {
			return fmt.Errorf("exception %s: package coordinates are required", exc.ID)
		}
	}
	return nil
}

func IsExceptionExpired(exc Exception) bool {
	if exc.AllowedUntil.IsZero() {
		return true
	}
	return time.Now().After(exc.AllowedUntil)
}

func MatchException(exc Exception, ecosystem, pkgName, version string) bool {
	if IsExceptionExpired(exc) {
		return false
	}
	if exc.Ecosystem != "" && exc.Ecosystem != ecosystem {
		return false
	}
	// Support exact name matching or wildcards (e.g. "@company/*", "company-*")
	if !MatchPackageName(exc.Package, pkgName) {
		return false
	}
	if exc.VersionRange != "" && exc.VersionRange != "*" && version != "" {
		if !MatchVersionRange(version, exc.VersionRange) {
			return false
		}
	}
	return true
}

func MatchPackageName(pattern, name string) bool {
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

// Masterminds/semver version matching helper
func MatchVersionRange(version, constraintStr string) bool {
	if constraintStr == "" || constraintStr == "*" {
		return true
	}
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
