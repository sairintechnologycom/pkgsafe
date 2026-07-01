package pypi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	apypi "github.com/sairintechnologycom/pkgsafe/internal/analyzer/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel"
	"github.com/sairintechnologycom/pkgsafe/internal/intel/osv"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
	"github.com/sairintechnologycom/pkgsafe/internal/typosquat"
)

type Scanner struct {
	Registry       rpypi.Client
	Policy         policy.Policy
	CacheDir       string
	Offline        bool
	DBPath         string
	SandboxEnabled bool
	BehaviorMode   types.BehaviorMode
	RequestedBy    string
	Environment    string
	RegistryName   string
}

func New() Scanner {
	return Scanner{
		Registry:    rpypi.NewClient(""),
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
		if cfg, ok := pol.Registries.Registries["pypi"][s.RegistryName]; ok {
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
		regName, regCfg = registry.ResolveRegistry("pypi", name, pol)
	}

	if !regCfg.Enabled && regCfg.Type != "unknown" {
		return types.ScanResult{}, fmt.Errorf("registry for package %s is disabled by policy", name)
	}

	// Block private scope/prefix resolving to public
	if regCfg.Type == "public" {
		for otherName, otherCfg := range pol.Registries.Registries["pypi"] {
			if otherCfg.Type == "private" {
				if registry.MatchPyPIPrefix(name, otherCfg.PackagePrefixes) {
					return types.ScanResult{}, fmt.Errorf("private package prefix must resolve from approved private registry %s, but resolved to public registry", otherName)
				}
			}
		}
	}

	if s.Offline {
		res, err := s.scanOffline(ctx, name, version, pol)
		if err != nil {
			return types.ScanResult{}, err
		}
		return risk.ApplyEnterpriseControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
	}

	regURL := regCfg.URL
	if regURL == "" || regURL == "https://pypi.org/pypi/" || regURL == "https://pypi.org/pypi" || regURL == "https://pypi.org/simple/" || regURL == "https://pypi.org/simple" {
		if s.Registry.BaseURL != "" && s.Registry.BaseURL != "https://pypi.org/pypi" && s.Registry.BaseURL != "https://pypi.org/pypi/" {
			regURL = s.Registry.BaseURL
		}
	}
	regClient := rpypi.NewClient(regURL)
	if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
		regClient.HTTPClient = registry.NewAuthenticatedHTTPClient(regCfg)
	}

	md, err := regClient.FetchMetadata(name)
	if err != nil {
		return types.ScanResult{}, err
	}
	vm, err := rpypi.ResolveVersion(md, version)
	if err != nil {
		return types.ScanResult{}, err
	}

	tmp, err := os.MkdirTemp("", "pkgsafe-pypi-*")
	if err != nil {
		return types.ScanResult{}, err
	}
	defer os.RemoveAll(tmp)

	filesToAnalyze := selectArtifacts(vm)
	for i, file := range filesToAnalyze {
		artifactPath, err := regClient.DownloadArtifact(file.URL, s.CacheDir)
		if err != nil {
			return types.ScanResult{}, err
		}
		if err := rpypi.VerifyArtifactHash(artifactPath, file.Digests); err != nil {
			return types.ScanResult{}, err
		}
		extractDir := filepath.Join(tmp, fmt.Sprintf("artifact-%d", i))
		if err := os.MkdirAll(extractDir, 0o755); err != nil {
			return types.ScanResult{}, err
		}
		if err := rpypi.ExtractArtifact(artifactPath, extractDir); err != nil {
			return types.ScanResult{}, err
		}
	}

	analysis, err := apypi.AnalyzeDir(tmp, apypi.Metadata{
		Name:        firstNonEmpty(vm.Name, name),
		Version:     vm.Version,
		Summary:     vm.Summary,
		Description: vm.Description,
		Repository:  vm.Repository,
		License:     vm.License,
		Yanked:      vm.Yanked,
		Wheel:       len(vm.WheelFiles) > 0,
		Source:      len(vm.SourceFiles) > 0,
	}, pol)
	if err != nil {
		return types.ScanResult{}, err
	}

	findings := append([]types.Reason{}, analysis.Findings...)
	alts := typosquat.CheckEcosystem("pypi", analysis.Result.Package.Name)
	if len(alts) > 0 {
		findings = risk.AddReason(findings, "typosquat_candidate", "Package name resembles a popular package", fmt.Sprint(alts))
	}
	ageDays := -1
	if !vm.Time.IsZero() {
		ageDays = int(time.Since(vm.Time).Hours() / 24)
		if rule, ok := policy.RuleFor(pol, "new_package"); ok && rule.MaxAgeDays > 0 && ageDays >= 0 && ageDays <= rule.MaxAgeDays {
			findings = append(findings, risk.NewPackageFinding(ageDays))
		}
	}
	if agent.CheckAISquattingEcosystem("pypi", analysis.Result.Package.Name, vm.Summary, vm.Repository, analysis.Artifact.SetupPyPresent, ageDays, len(vm.SourceFiles) > 0 && len(vm.WheelFiles) == 0) {
		findings = risk.AddReason(findings, "pypi_ai_package_squatting_candidate", "Package name resembles AI-generated package naming pattern", analysis.Result.Package.Name)
	}

	vulns, vulnFindings := s.lookupOnlineVulnerabilities(ctx, analysis.Result.Package.Name, vm.Version)
	findings = append(stripPolicyGeneratedReasons(findings), vulnFindings...)
	res := risk.Evaluate(analysis.Result.Package, findings, nil, analysis.Result.Suspicious, alts, pol)
	res.Vulnerabilities = vulns
	res.Artifact = analysis.Artifact
	behaviorMode := types.NormalizeBehaviorMode(string(s.BehaviorMode), s.SandboxEnabled)
	if behaviorMode != types.BehaviorDisabled {
		res.Sandbox = types.SandboxSummary{
			Enabled:      true,
			Available:    false,
			BehaviorMode: behaviorMode,
			Isolated:     false,
			NotPerformed: true,
		}
		if behaviorMode == types.BehaviorIsolated {
			res.Sandbox.NotPerfReason = "PyPI isolated behavior analysis is unavailable for this package flow. Static analysis completed only."
		} else {
			res.Sandbox.Warning = "PyPI heuristic behavior analysis is disabled; setup/build hooks are not executed without isolated backend."
			res.Sandbox.NotPerfReason = "PyPI behavior analysis is not implemented yet. Static analysis completed only."
		}
		res.Artifact.SandboxNote = res.Sandbox.NotPerfReason
	}
	return risk.ApplyEnterpriseControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
}

func (s Scanner) scanOffline(ctx context.Context, name, version string, pol policy.Policy) (types.ScanResult, error) {
	store, err := cache.Load("")
	if err != nil {
		return types.ScanResult{}, err
	}
	res, ok := store.Get("pypi", name, version)
	if !ok {
		return types.ScanResult{}, fmt.Errorf("offline scan failed: package %s@%s not cached locally (run online scan first)", name, version)
	}
	d, err := db.Open(s.DBPath)
	if err != nil {
		return res, nil
	}
	defer d.Close()
	dbVulns, err := d.GetVulnerabilitiesForPackage(ctx, "PyPI", res.Package.Name)
	if err != nil {
		return res, nil
	}
	var vulns []types.Vulnerability
	var findings []types.Reason
	for _, v := range dbVulns {
		if intel.IsVersionAffected(res.Package.Version, v) {
			vulns = append(vulns, typeVuln(v))
			findings = append(findings, vulnFinding(v))
		}
	}
	baseReasons := stripPolicyGeneratedReasons(res.Reasons)
	eval := risk.Evaluate(res.Package, append(baseReasons, findings...), nil, res.Suspicious, res.SafeAlternates, pol)
	eval.Vulnerabilities = vulns
	eval.Artifact = res.Artifact
	eval.Sandbox = res.Sandbox
	return eval, nil
}

func (s Scanner) lookupOnlineVulnerabilities(ctx context.Context, name, version string) ([]types.Vulnerability, []types.Reason) {
	rawVulns, err := osv.NewClient().Query(ctx, osv.QueryRequest{
		Package: &osv.Package{Name: name, Ecosystem: "PyPI"},
		Version: version,
	})
	var out []types.Vulnerability
	var findings []types.Reason
	if err != nil {
		// Fail closed: the OSV lookup did not complete, so this package was not
		// checked for known vulnerabilities. Surface it instead of scoring clean.
		fmt.Fprintf(os.Stderr, "Warning: OSV vulnerability lookup failed for PyPI/%s@%s: %v; failing closed (advisory data unavailable)\n", name, version, err)
		findings = append(findings, risk.VulnDataUnavailableReason(err))
		return out, findings
	}
	if len(rawVulns) == 0 {
		return out, findings
	}
	d, dbErr := db.Open(s.DBPath)
	if dbErr == nil {
		defer d.Close()
	}
	var dbVulns []db.Vulnerability
	for _, v := range rawVulns {
		dbV := osv.MapVulnerability(v, name, "PyPI")
		dbVulns = append(dbVulns, dbV)
		out = append(out, typeVuln(dbV))
		findings = append(findings, vulnFinding(dbV))
	}
	if dbErr == nil {
		_ = d.SaveVulnerabilities(ctx, dbVulns)
		for _, v := range dbVulns {
			_ = d.SaveVulnerabilityIndex(ctx, "PyPI", name, version, v.ID)
		}
	}
	return out, findings
}

func selectArtifacts(vm rpypi.VersionMetadata) []rpypi.File {
	var files []rpypi.File
	if len(vm.WheelFiles) > 0 {
		files = append(files, vm.WheelFiles[0])
	}
	if len(vm.SourceFiles) > 0 {
		files = append(files, vm.SourceFiles[0])
	}
	return files
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

func vulnFinding(v db.Vulnerability) types.Reason {
	if intel.IsMalware(v) {
		return types.Reason{ID: "known_malware_indicator", Description: "Package contains malware or malicious code", Evidence: v.ID}
	}
	return types.Reason{ID: "known_vulnerability_" + v.Severity, Description: fmt.Sprintf("Package version has a %s severity advisory", v.Severity), Evidence: v.ID}
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "unknown"
}
