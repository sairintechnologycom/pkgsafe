package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

func ResolvePolicy(packName string, repoPolicyPath string, cliPolicyPath string, cliMode string) (Policy, error) {
	pol := Default()

	// 1. Load installed policy pack if specified
	if packName != "" {
		packPol, err := loadPolicyPack(packName)
		if err != nil {
			return Policy{}, fmt.Errorf("load policy pack %q: %w", packName, err)
		}
		pol = Merge(pol, packPol)
	}

	// 2. Repo-level policy: .pkgsafe/policy.yaml (if it exists)
	if repoPolicyPath == "" {
		if _, err := os.Stat(".pkgsafe/policy.yaml"); err == nil {
			repoPolicyPath = ".pkgsafe/policy.yaml"
		}
	}
	if repoPolicyPath != "" {
		repoPol, err := Load(repoPolicyPath)
		if err == nil {
			pol = Merge(pol, repoPol)
		}
	}

	// 3. CLI --policy file
	if cliPolicyPath != "" {
		cliPol, err := Load(cliPolicyPath)
		if err != nil {
			return Policy{}, fmt.Errorf("load CLI policy %q: %w", cliPolicyPath, err)
		}
		pol = Merge(pol, cliPol)
	}

	// 4. CLI flags (like mode)
	if cliMode != "" {
		var err error
		pol, err = ApplyMode(pol, cliMode)
		if err != nil {
			return Policy{}, err
		}
	}

	return pol, nil
}

func Merge(base, override Policy) Policy {
	if override.Mode != "" {
		base.Mode = override.Mode
	}
	if override.Thresholds.BlockMinScore > 0 {
		base.Thresholds = override.Thresholds
	}
	if len(override.ProtectedPaths) > 0 {
		base.ProtectedPaths = override.ProtectedPaths
		base.BlockPatterns = override.BlockPatterns
	}
	if len(override.TrustedPackages.NPM) > 0 || len(override.TrustedPackages.PyPI) > 0 {
		base.TrustedPackages = override.TrustedPackages
	}
	if len(override.BlockedPackages.NPM) > 0 || len(override.BlockedPackages.PyPI) > 0 {
		base.BlockedPackages = override.BlockedPackages
	}
	if len(override.Rules) > 0 {
		for k, v := range override.Rules {
			base.Rules[k] = v
		}
	}
	if len(override.BlockPatterns) > 0 {
		base.BlockPatterns = override.BlockPatterns
	}
	if len(override.WarnPatterns) > 0 {
		base.WarnPatterns = override.WarnPatterns
	}
	if override.MCP.DefaultMode != "" {
		base.MCP = override.MCP
	}
	if override.Sandbox.DefaultTimeoutSeconds > 0 {
		base.Sandbox = override.Sandbox
	}
	if override.CI.FailOn != "" {
		base.CI = override.CI
	}
	if override.InstallInterception.DefaultMode != "" {
		base.InstallInterception = override.InstallInterception
	}
	if override.PackageManagers.NPM.RealBinary != "" {
		base.PackageManagers = override.PackageManagers
	}

	// Copy enterprise fields
	if override.PolicyPackName != "" {
		base.PolicyPackName = override.PolicyPackName
		base.PolicyPackVersion = override.PolicyPackVersion
		base.PolicyPackOwner = override.PolicyPackOwner
		base.PolicyPackSource = override.PolicyPackSource
	}
	if len(override.Registries.Registries) > 0 {
		base.Registries = override.Registries
	}
	if len(override.TrustedPackageRules) > 0 {
		base.TrustedPackageRules = override.TrustedPackageRules
	}
	if len(override.BlockedPackageRules) > 0 {
		base.BlockedPackageRules = override.BlockedPackageRules
	}
	if len(override.Exceptions) > 0 {
		base.Exceptions = override.Exceptions
	}
	if len(override.ScopedRules) > 0 {
		base.ScopedRules = override.ScopedRules
	}
	return base
}

func loadPolicyPack(name string) (Policy, error) {
	home := os.Getenv("HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		home = "."
	}
	packsDir := filepath.Join(home, ".pkgsafe", "policy-packs", name)
	if _, err := os.Stat(packsDir); os.IsNotExist(err) {
		// Try relative to workspace
		packsDir = filepath.Join(".pkgsafe", "policy-packs", name)
		if _, err := os.Stat(packsDir); os.IsNotExist(err) {
			return Policy{}, fmt.Errorf("policy pack not found in home or local workspace")
		}
	}

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		return Policy{}, err
	}

	var versions []*semver.Version
	verMap := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			v, err := semver.NewVersion(entry.Name())
			if err == nil {
				versions = append(versions, v)
				verMap[v.String()] = entry.Name()
			} else {
				verMap[entry.Name()] = entry.Name()
			}
		}
	}

	var selectedVerDir string
	if len(versions) > 0 {
		sort.Sort(semver.Collection(versions))
		selectedVerDir = verMap[versions[len(versions)-1].String()]
	} else {
		var rawNames []string
		for k := range verMap {
			rawNames = append(rawNames, k)
		}
		if len(rawNames) == 0 {
			return Policy{}, fmt.Errorf("no version directories found in %s", packsDir)
		}
		sort.Strings(rawNames)
		selectedVerDir = verMap[rawNames[len(rawNames)-1]]
	}

	dir := filepath.Join(packsDir, selectedVerDir)
	pol := Default()

	// 1. metadata.json
	metaBytes, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return Policy{}, err
	}
	var meta struct {
		Name          string    `json:"name"`
		Version       string    `json:"version"`
		Owner         string    `json:"owner"`
		ExpiresAt     time.Time `json:"expires_at"`
		Compatibility struct {
			MinPkgSafeVersion string `json:"min_pkgsafe_version"`
		} `json:"compatibility"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return Policy{}, fmt.Errorf("invalid metadata.json: %w", err)
	}
	pol.PolicyPackName = meta.Name
	pol.PolicyPackVersion = meta.Version
	pol.PolicyPackOwner = meta.Owner
	pol.PolicyPackSource = "policy-pack"
	// Expiry warning
	if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
		fmt.Fprintf(os.Stderr, "Warning: policy pack %s is expired\n", meta.Name)
	}
	// Min version check
	if meta.Compatibility.MinPkgSafeVersion != "" {
		// Check if version is below (Hardcode current version to 0.1.0)
		if meta.Compatibility.MinPkgSafeVersion > "0.1.0" {
			return Policy{}, fmt.Errorf("PkgSafe version 0.1.0 is below the minimum required version %s", meta.Compatibility.MinPkgSafeVersion)
		}
	}

	// 2. policy.yaml
	policyPath := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(policyPath); err == nil {
		if packPol, err := Load(policyPath); err == nil {
			pol = Merge(pol, packPol)
		}
	}

	// 3. registries.yaml
	regPath := filepath.Join(dir, "registries.yaml")
	if _, err := os.Stat(regPath); err == nil {
		if regBytes, err := os.ReadFile(regPath); err == nil {
			var regCfg RegistriesConfig
			if err := yaml.Unmarshal(regBytes, &regCfg); err == nil {
				pol.Registries = regCfg
			}
		}
	}

	// 4. trusted-packages.yaml
	trustedPath := filepath.Join(dir, "trusted-packages.yaml")
	if _, err := os.Stat(trustedPath); err == nil {
		if tBytes, err := os.ReadFile(trustedPath); err == nil {
			var tc TrustedPackagesConfig
			if err := yaml.Unmarshal(tBytes, &tc); err == nil {
				pol.TrustedPackageRules = tc.TrustedPackages[string(pol.Mode)] // Wait, map ecosystem -> rules, let's load all of them
				// Actually the format is trusted_packages: {npm: [...], pypi: [...]}. Let's load the map
				var raw struct {
					TrustedPackages map[string][]TrustedPackageRule `yaml:"trusted_packages"`
				}
				if err := yaml.Unmarshal(tBytes, &raw); err == nil {
					for _, rules := range raw.TrustedPackages {
						pol.TrustedPackageRules = append(pol.TrustedPackageRules, rules...)
					}
				}
			}
		}
	}

	// 5. blocked-packages.yaml
	blockedPath := filepath.Join(dir, "blocked-packages.yaml")
	if _, err := os.Stat(blockedPath); err == nil {
		if bBytes, err := os.ReadFile(blockedPath); err == nil {
			var raw struct {
				BlockedPackages map[string][]BlockedPackageRule `yaml:"blocked_packages"`
			}
			if err := yaml.Unmarshal(bBytes, &raw); err == nil {
				for _, rules := range raw.BlockedPackages {
					pol.BlockedPackageRules = append(pol.BlockedPackageRules, rules...)
				}
			}
		}
	}

	// 6. exceptions.yaml
	excPath := filepath.Join(dir, "exceptions.yaml")
	if _, err := os.Stat(excPath); err == nil {
		if excBytes, err := os.ReadFile(excPath); err == nil {
			var raw struct {
				Exceptions []Exception `yaml:"exceptions"`
			}
			if err := yaml.Unmarshal(excBytes, &raw); err == nil {
				pol.Exceptions = raw.Exceptions
			} else {
				// try list
				var list []Exception
				if err := yaml.Unmarshal(excBytes, &list); err == nil {
					pol.Exceptions = list
				}
			}
		}
	}

	// 7. scopes.yaml
	scopesPath := filepath.Join(dir, "scopes.yaml")
	if _, err := os.Stat(scopesPath); err == nil {
		if scopesBytes, err := os.ReadFile(scopesPath); err == nil {
			var raw struct {
				ScopedRules []ScopedRule `yaml:"scoped_rules"`
			}
			if err := yaml.Unmarshal(scopesBytes, &raw); err == nil {
				pol.ScopedRules = raw.ScopedRules
			} else {
				var list []ScopedRule
				if err := yaml.Unmarshal(scopesBytes, &list); err == nil {
					pol.ScopedRules = list
				}
			}
		}
	}

	return pol, nil
}
