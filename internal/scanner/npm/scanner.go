package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/agent"
	anpm "github.com/niyam-ai/pkgsafe/internal/analyzer/npm"
	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/db"
	npminventory "github.com/niyam-ai/pkgsafe/internal/deps/npm"
	"github.com/niyam-ai/pkgsafe/internal/intel"
	"github.com/niyam-ai/pkgsafe/internal/intel/osv"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	rnpm "github.com/niyam-ai/pkgsafe/internal/registry/npm"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/sandbox"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Scanner struct {
	Registry       rnpm.Client
	Policy         policy.Policy
	CacheDir       string
	Offline        bool
	DBPath         string
	SandboxEnabled bool
	BehaviorMode   types.BehaviorMode
	SandboxTimeout time.Duration
	NetworkMode    string
	KeepSandbox    bool
	RequestedBy    string
	Environment    string
	RegistryName   string
}

func New() Scanner {
	return Scanner{
		Registry:    rnpm.NewClient(""),
		Policy:      policy.Default(),
		RequestedBy: "human",
		Environment: "developer",
	}
}

func (s Scanner) ScanPackage(name, version string) (types.ScanResult, error) {
	if name == "" {
		return types.ScanResult{}, fmt.Errorf("package name is required")
	}
	pol := s.Policy
	if pol.Mode == "" {
		pol = policy.Default()
	}
	ctx := context.Background()

	var regName string
	var regCfg policy.RegistryConfig
	if s.RegistryName != "" {
		if cfg, ok := pol.Registries.Registries["npm"][s.RegistryName]; ok {
			regName = s.RegistryName
			regCfg = cfg
		} else {
			regName = ""
			regCfg = policy.RegistryConfig{
				URL:     "",
				Type:    "unknown",
				Enabled: false,
			}
		}
	} else {
		regName, regCfg = registry.ResolveRegistry("npm", name, pol)
	}

	if !regCfg.Enabled && regCfg.Type != "unknown" {
		return types.ScanResult{}, fmt.Errorf("registry for package %s is disabled by policy", name)
	}

	// Block private scope resolving to public
	if regCfg.Type == "public" && registry.GetNPMScope(name) != "" {
		for otherName, otherCfg := range pol.Registries.Registries["npm"] {
			if otherCfg.Type == "private" {
				for _, sc := range otherCfg.Scopes {
					if strings.EqualFold(sc, registry.GetNPMScope(name)) {
						return types.ScanResult{}, fmt.Errorf("private scope %s must resolve from approved private registry %s, but resolved to public registry", registry.GetNPMScope(name), otherName)
					}
				}
			}
		}
	}

	if s.Offline {
		store, err := cache.Load("")
		if err != nil {
			return types.ScanResult{}, err
		}
		res, ok := store.Get("npm", name, version)
		if !ok {
			return types.ScanResult{}, fmt.Errorf("offline scan failed: package %s@%s not cached locally (run online scan first)", name, version)
		}

		d, err := db.Open(s.DBPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: vulnerability DB is stale or missing")
			return risk.ApplyEnterpriseControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
		}
		defer d.Close()

		vulns, err := d.GetVulnerabilitiesForPackage(ctx, "npm", res.Package.Name)
		if err != nil {
			return risk.ApplyEnterpriseControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
		}

		var affectedVulns []types.Vulnerability
		var findings []types.Reason

		for _, v := range vulns {
			if intel.IsVersionAffected(res.Package.Version, v) {
				affectedVulns = append(affectedVulns, typeVuln(v))

				if intel.IsMalware(v) {
					findings = append(findings, types.Reason{
						ID:          "known_malware_indicator",
						Description: "Package contains malware or malicious code",
						Evidence:    v.ID,
					})
				} else {
					findings = append(findings, types.Reason{
						ID:          "known_vulnerability_" + v.Severity,
						Description: fmt.Sprintf("Package version has a %s severity advisory", v.Severity),
						Evidence:    v.ID,
					})
				}
			}
		}

		baseReasons := stripPolicyGeneratedReasons(res.Reasons)
		findings = append(baseReasons, findings...)

		evalRes := risk.Evaluate(res.Package, findings, res.Lifecycle, res.Suspicious, res.SafeAlternates, pol)
		evalRes.Vulnerabilities = affectedVulns
		evalRes.Sandbox = res.Sandbox
		return risk.ApplyEnterpriseControls(evalRes, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
	}

	regURL := regCfg.URL
	if regURL == "" || regURL == "https://registry.npmjs.org/" || regURL == "https://registry.npmjs.org" {
		if s.Registry.BaseURL != "" && s.Registry.BaseURL != "https://registry.npmjs.org" && s.Registry.BaseURL != "https://registry.npmjs.org/" {
			regURL = s.Registry.BaseURL
		}
	}
	regClient := rnpm.NewClient(regURL)
	if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
		regClient.HTTPClient = registry.NewAuthenticatedHTTPClient(regCfg)
	}

	md, err := regClient.FetchMetadata(name)
	if err != nil {
		return types.ScanResult{}, err
	}
	vm, err := rnpm.ResolveVersion(md, version)
	if err != nil {
		return types.ScanResult{}, err
	}
	if vm.Dist.Tarball == "" {
		return types.ScanResult{}, fmt.Errorf("missing tarball URL for %s@%s", name, vm.Version)
	}

	tarballPath, err := regClient.DownloadTarball(vm.Dist.Tarball, s.CacheDir)
	if err != nil {
		return types.ScanResult{}, err
	}
	if err := rnpm.VerifyTarballIntegrity(tarballPath, vm.Dist.Integrity, vm.Dist.Shasum); err != nil {
		return types.ScanResult{}, err
	}
	tmp, err := os.MkdirTemp("", "pkgsafe-npm-*")
	if err != nil {
		return types.ScanResult{}, err
	}
	defer os.RemoveAll(tmp)

	if err := rnpm.ExtractTarball(tarballPath, tmp); err != nil {
		return types.ScanResult{}, err
	}
	pkgJSON, err := rnpm.LocatePackageJSON(tmp)
	if err != nil {
		return types.ScanResult{}, err
	}
	res, err := anpm.AnalyzePackageDir(filepath.Dir(pkgJSON), pol)
	if err != nil {
		return types.ScanResult{}, err
	}

	pkgJSONData, err := os.ReadFile(pkgJSON)
	if err != nil {
		return types.ScanResult{}, err
	}
	var pj struct {
		Scripts map[string]string `json:"scripts"`
	}
	_ = json.Unmarshal(pkgJSONData, &pj)

	behaviorMode := types.NormalizeBehaviorMode(string(s.BehaviorMode), s.SandboxEnabled)
	behaviorEnabled := behaviorMode != types.BehaviorDisabled
	sandboxAvailable := behaviorMode == types.BehaviorHeuristic && sandbox.IsAvailable(ctx)
	res.Sandbox = types.SandboxSummary{
		Enabled:        behaviorEnabled,
		Available:      sandboxAvailable,
		BehaviorMode:   behaviorMode,
		Isolated:       false,
		NetworkMode:    s.NetworkMode,
		TimeoutSeconds: int(s.SandboxTimeout.Seconds()),
	}
	if behaviorMode == types.BehaviorHeuristic {
		res.Sandbox.Runner = "fake-home-process"
		res.Sandbox.Warning = "Heuristic behavior analysis runs lifecycle scripts on the host without OS isolation; it is not a security sandbox. Use only in disposable environments."
	}

	var sandboxFindings []types.Reason
	if behaviorEnabled {
		if behaviorMode == types.BehaviorIsolated {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "isolated behavior analysis backend is not implemented or unavailable"
		} else if res.Decision == types.DecisionBlock {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "behavior analysis skipped because static analysis already blocked the package"
		} else if !sandboxAvailable {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "No supported heuristic behavior-analysis runner available on this platform"
		} else {
			runner := &sandbox.ProcessRunner{}
			var scriptsExecuted []types.SandboxScriptResult
			for _, scriptName := range []string{"preinstall", "install", "postinstall", "prepare"} {
				scriptCmd, ok := pj.Scripts[scriptName]
				if !ok {
					continue
				}
				req := sandbox.SandboxRequest{
					Ecosystem:     "npm",
					PackageName:   res.Package.Name,
					Version:       res.Package.Version,
					PackagePath:   filepath.Dir(pkgJSON),
					ScriptName:    scriptName,
					ScriptCommand: scriptCmd,
					Timeout:       s.SandboxTimeout,
					NetworkMode:   s.NetworkMode,
					KeepSandbox:   s.KeepSandbox,
					Policy:        pol,
				}
				sres, err := runner.RunLifecycleScript(ctx, req)
				if err != nil {
					continue
				}

				var typesFindings []types.SandboxFinding
				for _, f := range sres.Findings {
					typesFindings = append(typesFindings, types.SandboxFinding{
						RuleID:      f.RuleID,
						Severity:    f.Severity,
						Score:       f.Score,
						Description: f.Description,
					})
					sandboxFindings = append(sandboxFindings, types.Reason{
						ID:          f.RuleID,
						Description: f.Description,
						Evidence:    fmt.Sprintf("Script: %s", scriptName),
						ScoreImpact: f.Score,
					})
				}

				scriptsExecuted = append(scriptsExecuted, types.SandboxScriptResult{
					Name:       sres.ScriptName,
					ExitCode:   sres.ExitCode,
					TimedOut:   sres.TimedOut,
					DurationMs: sres.DurationMs,
					Findings:   typesFindings,
				})
			}
			res.Sandbox.ScriptsExecuted = scriptsExecuted
		}
	}

	if res.Package.Name == "" || res.Package.Name == "unknown" {
		res.Package.Name = name
	}
	if vm.Version != "" {
		res.Package.Version = vm.Version
	}

	var baseFindings []types.Reason
	baseFindings = append(baseFindings, res.Reasons...)
	baseFindings = append(baseFindings, sandboxFindings...)
	ageDays := -1
	if !vm.Time.IsZero() {
		ageDays = int(time.Since(vm.Time).Hours() / 24)
		if rule, ok := policy.RuleFor(pol, "new_package"); ok && rule.MaxAgeDays > 0 {
			if ageDays >= 0 && ageDays <= rule.MaxAgeDays {
				baseFindings = append(baseFindings, risk.NewPackageFinding(ageDays))
			}
		}
	}
	hasScripts := len(res.Lifecycle) > 0
	if agent.CheckAISquatting(res.Package.Name, vm.Description, vm.Repository, hasScripts, ageDays) {
		baseFindings = append(baseFindings, types.Reason{
			ID:          "ai_package_squatting_candidate",
			Description: "Package name resembles an AI-generated package name with low ecosystem reputation",
			Evidence:    res.Package.Name,
		})
	}

	osvClient := osv.NewClient()
	rawVulns, err := osvClient.Query(ctx, osv.QueryRequest{
		Package: &osv.Package{Name: res.Package.Name, Ecosystem: "npm"},
		Version: res.Package.Version,
	})

	var typesVulns []types.Vulnerability
	var vulnFindings []types.Reason

	d, dbErr := db.Open(s.DBPath)

	if err != nil {
		// Fail closed: the OSV lookup did not complete, so this package was not
		// checked for known vulnerabilities. Surface it instead of scoring clean.
		fmt.Fprintf(os.Stderr, "Warning: OSV vulnerability lookup failed for npm/%s@%s: %v; failing closed (advisory data unavailable)\n", res.Package.Name, res.Package.Version, err)
		vulnFindings = append(vulnFindings, risk.VulnDataUnavailableReason(err))
		if dbErr == nil {
			d.Close()
		}
	} else if len(rawVulns) > 0 {
		var dbVulns []db.Vulnerability
		for _, v := range rawVulns {
			dbV := osv.MapVulnerability(v, res.Package.Name, "npm")
			dbVulns = append(dbVulns, dbV)

			typesVulns = append(typesVulns, typeVuln(dbV))

			if intel.IsMalware(dbV) {
				vulnFindings = append(vulnFindings, types.Reason{
					ID:          "known_malware_indicator",
					Description: "Package contains malware or malicious code",
					Evidence:    dbV.ID,
				})
			} else {
				vulnFindings = append(vulnFindings, types.Reason{
					ID:          "known_vulnerability_" + dbV.Severity,
					Description: fmt.Sprintf("Package version has a %s severity advisory", dbV.Severity),
					Evidence:    dbV.ID,
				})
			}
		}

		if dbErr == nil {
			defer d.Close()
			_ = d.SaveVulnerabilities(ctx, dbVulns)
			for _, dbV := range dbVulns {
				_ = d.SaveVulnerabilityIndex(ctx, "npm", res.Package.Name, res.Package.Version, dbV.ID)
			}
		}
	} else if dbErr == nil {
		d.Close()
	}

	baseFindings = stripPolicyGeneratedReasons(baseFindings)
	allFindings := append(baseFindings, vulnFindings...)

	finalRes := risk.Evaluate(res.Package, allFindings, res.Lifecycle, res.Suspicious, res.SafeAlternates, pol)
	finalRes.Vulnerabilities = typesVulns
	finalRes.Sandbox = res.Sandbox
	return risk.ApplyEnterpriseControls(finalRes, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
}

func ScanPackage(name, version string) (types.ScanResult, error) {
	return New().ScanPackage(name, version)
}

func typeVuln(v db.Vulnerability) types.Vulnerability {
	return types.Vulnerability{
		ID:            v.ID,
		Source:        v.Source,
		Ecosystem:     v.Ecosystem,
		PackageName:   v.PackageName,
		Version:       v.Version,
		Aliases:       v.Aliases,
		Severity:      v.Severity,
		Summary:       v.Summary,
		Details:       v.Details,
		FixedVersions: v.FixedVersions,
		References:    v.References,
		PublishedAt:   formatVulnTime(v.PublishedAt),
		ModifiedAt:    formatVulnTime(v.ModifiedAt),
		FetchedAt:     formatVulnTime(v.FetchedAt),
	}
}

func formatVulnTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s Scanner) ScanLocalPackage(dir string) (types.ScanResult, error) {
	pol := s.Policy
	if pol.Mode == "" {
		pol = policy.Default()
	}
	ctx := context.Background()

	res, err := anpm.AnalyzePackageDir(dir, pol)
	if err != nil {
		return types.ScanResult{}, err
	}

	pkgJSON := filepath.Join(dir, "package.json")
	pkgJSONData, err := os.ReadFile(pkgJSON)
	if err != nil {
		return types.ScanResult{}, err
	}
	var pj struct {
		Scripts map[string]string `json:"scripts"`
	}
	_ = json.Unmarshal(pkgJSONData, &pj)

	behaviorMode := types.NormalizeBehaviorMode(string(s.BehaviorMode), s.SandboxEnabled)
	behaviorEnabled := behaviorMode != types.BehaviorDisabled
	sandboxAvailable := behaviorMode == types.BehaviorHeuristic && sandbox.IsAvailable(ctx)
	res.Sandbox = types.SandboxSummary{
		Enabled:        behaviorEnabled,
		Available:      sandboxAvailable,
		BehaviorMode:   behaviorMode,
		Isolated:       false,
		NetworkMode:    s.NetworkMode,
		TimeoutSeconds: int(s.SandboxTimeout.Seconds()),
	}
	if behaviorMode == types.BehaviorHeuristic {
		res.Sandbox.Runner = "fake-home-process"
		res.Sandbox.Warning = "Heuristic behavior analysis runs lifecycle scripts on the host without OS isolation; it is not a security sandbox. Use only in disposable environments."
	}

	var sandboxFindings []types.Reason
	var scriptsExecuted []types.SandboxScriptResult
	if behaviorEnabled {
		if behaviorMode == types.BehaviorIsolated {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "isolated behavior analysis backend is not implemented or unavailable"
		} else if res.Decision == types.DecisionBlock {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "behavior analysis skipped because static analysis already blocked the package"
		} else if !sandboxAvailable {
			res.Sandbox.NotPerformed = true
			res.Sandbox.NotPerfReason = "No supported heuristic behavior-analysis runner available on this platform"
		} else {
			runner := &sandbox.ProcessRunner{}
			for _, scriptName := range []string{"preinstall", "install", "postinstall", "prepare"} {
				scriptCmd, ok := pj.Scripts[scriptName]
				if !ok {
					continue
				}
				req := sandbox.SandboxRequest{
					Ecosystem:     "npm",
					PackageName:   res.Package.Name,
					Version:       res.Package.Version,
					PackagePath:   dir,
					ScriptName:    scriptName,
					ScriptCommand: scriptCmd,
					Timeout:       s.SandboxTimeout,
					NetworkMode:   s.NetworkMode,
					KeepSandbox:   s.KeepSandbox,
					Policy:        pol,
				}
				sres, err := runner.RunLifecycleScript(ctx, req)
				if err != nil {
					continue
				}

				var typesFindings []types.SandboxFinding
				for _, f := range sres.Findings {
					typesFindings = append(typesFindings, types.SandboxFinding{
						RuleID:      f.RuleID,
						Severity:    f.Severity,
						Score:       f.Score,
						Description: f.Description,
					})
					sandboxFindings = append(sandboxFindings, types.Reason{
						ID:          f.RuleID,
						Description: f.Description,
						Evidence:    fmt.Sprintf("Script: %s", scriptName),
						ScoreImpact: f.Score,
					})
				}

				scriptsExecuted = append(scriptsExecuted, types.SandboxScriptResult{
					Name:       sres.ScriptName,
					ExitCode:   sres.ExitCode,
					TimedOut:   sres.TimedOut,
					DurationMs: sres.DurationMs,
					Findings:   typesFindings,
				})
			}
			res.Sandbox.ScriptsExecuted = scriptsExecuted
		}
	}

	baseFindings := stripPolicyGeneratedReasons(res.Reasons)
	allFindings := append(baseFindings, sandboxFindings...)

	if deps, scanErr := npminventory.ScanInventory(dir); scanErr == nil {
		mismatches := npminventory.CheckMismatches(deps)
		allFindings = append(allFindings, mismatches...)
	}

	finalRes := risk.Evaluate(res.Package, allFindings, res.Lifecycle, res.Suspicious, res.SafeAlternates, pol)
	finalRes.Sandbox = res.Sandbox
	return risk.ApplyEnterpriseControls(finalRes, pol, "local", policy.RegistryConfig{}, s.RequestedBy, s.Environment), nil
}

func stripPolicyGeneratedReasons(reasons []types.Reason) []types.Reason {
	out := make([]types.Reason, 0, len(reasons))
	for _, reason := range reasons {
		switch reason.ID {
		case "trusted_package_reduction", "blocked_package",
			"known_vulnerability_critical", "known_vulnerability_high",
			"known_vulnerability_medium", "known_vulnerability_low",
			"known_malware_indicator":
			continue
		default:
			out = append(out, types.Reason{ID: reason.ID, Description: reason.Description, Evidence: reason.Evidence})
		}
	}
	return out
}
