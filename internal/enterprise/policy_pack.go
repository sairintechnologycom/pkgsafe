package enterprise

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	"gopkg.in/yaml.v3"
)

type TrustedPackageRule = policy.TrustedPackageRule
type BlockedPackageRule = policy.BlockedPackageRule
type TrustedPackagesConfig = policy.TrustedPackagesConfig
type BlockedPackagesConfig = policy.BlockedPackagesConfig
type ScopedRuleMatch = policy.ScopedRuleMatch
type ScopedRuleApply = policy.ScopedRuleApply
type ScopedRule = policy.ScopedRule
type ScopesConfig = policy.ScopesConfig

type PolicyPack struct {
	Metadata        Metadata
	Policy          policy.Policy
	Registries      registry.RegistriesConfig
	TrustedPackages TrustedPackagesConfig
	BlockedPackages BlockedPackagesConfig
	Exceptions      ExceptionsConfig
	Scopes          ScopesConfig
	Path            string
}

func GetPolicyPacksDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		return filepath.Join(".pkgsafe", "policy-packs")
	}
	return filepath.Join(home, ".pkgsafe", "policy-packs")
}

func LoadPolicyPack(name string) (*PolicyPack, error) {
	packsDir := GetPolicyPacksDir()
	packDir := filepath.Join(packsDir, name)
	if _, err := os.Stat(packDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("policy pack %q not found", name)
	}

	// List subdirectories to find versions
	entries, err := os.ReadDir(packDir)
	if err != nil {
		return nil, fmt.Errorf("read pack dir: %w", err)
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
				// fallback to lexicographical
				verMap[entry.Name()] = entry.Name()
			}
		}
	}

	var selectedVerDir string
	if len(versions) > 0 {
		sort.Sort(semver.Collection(versions))
		selectedVerDir = verMap[versions[len(versions)-1].String()]
	} else {
		// fallback to sorting alphabetically
		var rawNames []string
		for k := range verMap {
			rawNames = append(rawNames, k)
		}
		if len(rawNames) == 0 {
			return nil, fmt.Errorf("no versions found for policy pack %s", name)
		}
		sort.Strings(rawNames)
		selectedVerDir = verMap[rawNames[len(rawNames)-1]]
	}

	versionPath := filepath.Join(packDir, selectedVerDir)
	return LoadPolicyPackFromDir(versionPath)
}

func LoadPolicyPackFromDir(dir string) (*PolicyPack, error) {
	pack := &PolicyPack{Path: dir}

	// 1. metadata.json
	metaBytes, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil, fmt.Errorf("read metadata.json: %w", err)
	}
	meta, err := ParseMetadata(metaBytes)
	if err != nil {
		return nil, err
	}
	if err := ValidateMetadata(meta); err != nil {
		return nil, err
	}
	pack.Metadata = meta

	// 2. policy.yaml
	policyPath := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(policyPath); err == nil {
		pol, err := policy.Load(policyPath)
		if err != nil {
			return nil, fmt.Errorf("load policy.yaml: %w", err)
		}
		pack.Policy = pol
	} else {
		pack.Policy = policy.Default()
	}

	// 3. registries.yaml
	regPath := filepath.Join(dir, "registries.yaml")
	if _, err := os.Stat(regPath); err == nil {
		regBytes, err := os.ReadFile(regPath)
		if err != nil {
			return nil, err
		}
		regs, err := registry.ParseRegistries(regBytes)
		if err != nil {
			return nil, err
		}
		pack.Registries = regs
	}

	// 4. trusted-packages.yaml
	trustedPath := filepath.Join(dir, "trusted-packages.yaml")
	if _, err := os.Stat(trustedPath); err == nil {
		tBytes, err := os.ReadFile(trustedPath)
		if err != nil {
			return nil, err
		}
		var tc TrustedPackagesConfig
		if err := yaml.Unmarshal(tBytes, &tc); err != nil {
			return nil, fmt.Errorf("parse trusted packages: %w", err)
		}
		pack.TrustedPackages = tc
	}

	// 5. blocked-packages.yaml
	blockedPath := filepath.Join(dir, "blocked-packages.yaml")
	if _, err := os.Stat(blockedPath); err == nil {
		bBytes, err := os.ReadFile(blockedPath)
		if err != nil {
			return nil, err
		}
		var bc BlockedPackagesConfig
		if err := yaml.Unmarshal(bBytes, &bc); err != nil {
			return nil, fmt.Errorf("parse blocked packages: %w", err)
		}
		pack.BlockedPackages = bc
	}

	// 6. exceptions.yaml
	excPath := filepath.Join(dir, "exceptions.yaml")
	if _, err := os.Stat(excPath); err == nil {
		excBytes, err := os.ReadFile(excPath)
		if err != nil {
			return nil, err
		}
		excs, err := ParseExceptions(excBytes)
		if err != nil {
			return nil, err
		}
		pack.Exceptions = excs
	}

	// 7. scopes.yaml
	scopesPath := filepath.Join(dir, "scopes.yaml")
	if _, err := os.Stat(scopesPath); err == nil {
		scopesBytes, err := os.ReadFile(scopesPath)
		if err != nil {
			return nil, err
		}
		var sc ScopesConfig
		if err := yaml.Unmarshal(scopesBytes, &sc); err != nil {
			// check if it's direct list
			var list []ScopedRule
			if err2 := yaml.Unmarshal(scopesBytes, &list); err2 == nil {
				sc.ScopedRules = list
			} else {
				return nil, fmt.Errorf("parse scopes: %w", err)
			}
		}
		pack.Scopes = sc
	}

	return pack, nil
}
