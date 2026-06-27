package enterprise

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/version"
)

type Compatibility struct {
	MinPkgSafeVersion string `json:"min_pkgsafe_version"`
}

type Signing struct {
	Required  bool   `json:"required"`
	Algorithm string `json:"algorithm"`
}

type Metadata struct {
	SchemaVersion string        `json:"schema_version"`
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Description   string        `json:"description"`
	Owner         string        `json:"owner"`
	CreatedAt     time.Time     `json:"created_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Compatibility Compatibility `json:"compatibility"`
	DefaultMode   string        `json:"default_mode"`
	Environments  []string      `json:"environments"`
	Signing       Signing       `json:"signing"`
}

func ParseMetadata(data []byte) (Metadata, error) {
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return Metadata{}, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return meta, nil
}

func ValidateMetadata(meta Metadata) error {
	if meta.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if meta.Name == "" {
		return fmt.Errorf("pack name is required")
	}
	if meta.Version == "" {
		return fmt.Errorf("version is required")
	}
	// Enforce min pkgsafe version against the real build version. Dev builds
	// (unversioned "dev") can't be meaningfully compared, so the gate is
	// skipped for them rather than failing every pack.
	if meta.Compatibility.MinPkgSafeVersion != "" && !version.IsDev() {
		currentVersion := version.Version
		if compareVersions(currentVersion, meta.Compatibility.MinPkgSafeVersion) < 0 {
			return fmt.Errorf("PkgSafe version %s is below the minimum required version %s", currentVersion, meta.Compatibility.MinPkgSafeVersion)
		}
	}
	return nil
}

func compareVersions(v1, v2 string) int {
	// Simple version comparison for standard semver format
	var major1, minor1, patch1 int
	var major2, minor2, patch2 int
	fmt.Sscanf(v1, "%d.%d.%d", &major1, &minor1, &patch1)
	fmt.Sscanf(v2, "%d.%d.%d", &major2, &minor2, &patch2)
	if major1 != major2 {
		return major1 - major2
	}
	if minor1 != minor2 {
		return minor1 - minor2
	}
	return patch1 - patch2
}

func (m Metadata) IsExpired() bool {
	if m.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(m.ExpiresAt)
}
