package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func ResolvePolicy(packName string, repoPolicyPath string, cliPolicyPath string, cliMode string, registryConfigPath string) (Policy, error) {
	if packName != "" {
		return Policy{}, fmt.Errorf("signed policy archives are private-enterprise functionality; use pkgsafe-enterprise")
	}

	pol := Default()

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

	if cliPolicyPath != "" {
		cliPol, err := Load(cliPolicyPath)
		if err != nil {
			return Policy{}, fmt.Errorf("load CLI policy %q: %w", cliPolicyPath, err)
		}
		pol = Merge(pol, cliPol)
	}

	if cliMode != "" {
		var err error
		pol, err = ApplyMode(pol, cliMode)
		if err != nil {
			return Policy{}, err
		}
	}

	if registryConfigPath != "" {
		regBytes, err := os.ReadFile(registryConfigPath)
		if err != nil {
			return Policy{}, fmt.Errorf("read registry config %q: %w", registryConfigPath, err)
		}
		var regCfg RegistriesConfig
		if err := yaml.Unmarshal(regBytes, &regCfg); err != nil {
			return Policy{}, fmt.Errorf("parse registry config %q: %w", registryConfigPath, err)
		}
		pol.Registries = regCfg
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
	if override.AgentPolicy.Mode != "" {
		base.AgentPolicy = override.AgentPolicy
	}
	return base
}
