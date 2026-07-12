package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	pydeps "github.com/sairintechnologycom/pkgsafe/internal/deps/python"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ScanError is a helper struct containing an error message and a recommended exit code.
type ScanError struct {
	Err      error
	ExitCode int
}

func (e ScanError) Error() string {
	return e.Err.Error()
}

func RunScan(opts ScanOptions) (*ScanResult, error) {
	// 1. Load Policy
	pol, err := policy.ResolvePolicy(opts.PolicyPack, "", opts.PolicyPath, opts.Mode, opts.RegistryConfigPath)
	if err != nil {
		return nil, ScanError{Err: fmt.Errorf("load policy: %w", err), ExitCode: ExitPolicyError}
	}

	// Determine active fail-on setting
	failOn := pol.CI.FailOn
	if opts.FailOn != "" {
		failOn = opts.FailOn
	}
	if failOn != "none" && failOn != "warn" && failOn != "block" {
		return nil, ScanError{Err: fmt.Errorf("invalid fail-on value: %q. Must be one of none, warn, block", failOn), ExitCode: ExitUsageError}
	}
	ecosystem := strings.ToLower(strings.TrimSpace(opts.Ecosystem))
	if ecosystem == "" {
		ecosystem = detectEcosystem(opts)
	}
	if ecosystem == "pypi" {
		return runPyPIScan(opts, pol, failOn)
	}

	// 2. Locate and load lockfile
	lockfile := opts.LockfilePath
	if lockfile == "" {
		lockfile = "package-lock.json"
	}
	currentBytes, err := os.ReadFile(lockfile)
	if err != nil {
		return nil, ScanError{Err: fmt.Errorf("read lockfile %q: %w", lockfile, err), ExitCode: ExitLockfileError}
	}

	// Check package.json dependencies type
	depTypes, hasDepTypes := loadPackageJSONInfo(lockfile)

	// Determine changed-only flag: default from policy, but overridden by flag
	changedOnly := pol.CI.ChangedOnly
	if opts.ChangedOnlySpecified {
		changedOnly = opts.ChangedOnly
	}

	var depsToScan []Dependency
	var changedPkgs []ChangedPackage
	isChangedOnlyScan := false
	baselineType := ""

	if changedOnly {
		if baselineBytes, ok, err := baselineFileContent(opts.Baseline); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: baseline file %s could not be read: %v. Falling back to full scan.\n", opts.Baseline, err)
		} else if ok {
			deps, details, err := DiffLockfilesDetailed(currentBytes, baselineBytes)
			if err == nil {
				depsToScan = deps
				changedPkgs = details
				isChangedOnlyScan = true
				baselineType = "file"
			} else {
				fmt.Fprintf(os.Stderr, "Warning: failed to diff baseline file %s: %v. Falling back to full scan.\n", opts.Baseline, err)
			}
		} else if dir := filepath.Dir(lockfile); IsGitRepo(dir) {
			gitRoot, err := GetGitRoot(dir)
			if err == nil {
				// Get relative path of lockfile with respect to git root
				absLockfile, _ := filepath.Abs(lockfile)
				relPath, err := filepath.Rel(gitRoot, absLockfile)
				if err == nil {
					relPathSlash := filepath.ToSlash(relPath)
					baselineContent, err := GetFileFromBranch(gitRoot, opts.Baseline, relPathSlash)
					if err == nil {
						deps, details, err := DiffLockfilesDetailed(currentBytes, baselineContent)
						if err == nil {
							depsToScan = deps
							changedPkgs = details
							isChangedOnlyScan = true
							baselineType = "git_ref"
						} else {
							fmt.Fprintf(os.Stderr, "Warning: failed to diff lockfiles: %v. Falling back to full scan.\n", err)
						}
					} else {
						fmt.Fprintf(os.Stderr, "Warning: baseline lockfile not found in %s branch: %v. Falling back to full scan.\n", opts.Baseline, err)
					}
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "Warning: changed-only scan enabled but directory is not inside a Git repository. Falling back to full scan.")
		}
	}

	// If not changed-only or diff failed/fell back, parse all dependencies in lockfile
	if !isChangedOnlyScan {
		lfDeps, err := parseLockfileDeps(currentBytes)
		if err != nil {
			return nil, ScanError{Err: fmt.Errorf("parse current lockfile: %w", err), ExitCode: ExitLockfileError}
		}
		for name, versions := range lfDeps {
			for ver := range versions {
				depsToScan = append(depsToScan, Dependency{Name: name, Version: ver})
			}
		}
	}

	// 3. Scan dependencies using scanner
	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = opts.Offline
	scanner.RequestedBy = "human"
	scanner.Environment = "ci"
	behaviorMode := types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, pol.Sandbox.Enabled)
	if opts.BehaviorMode != "" {
		switch types.BehaviorMode(opts.BehaviorMode) {
		case types.BehaviorDisabled, types.BehaviorHeuristic, types.BehaviorIsolated:
			behaviorMode = types.BehaviorMode(opts.BehaviorMode)
		default:
			return nil, ScanError{ExitCode: ExitUsageError, Err: fmt.Errorf("--behavior must be disabled, heuristic, or isolated")}
		}
	} else if opts.SandboxSpecified {
		behaviorMode = types.BehaviorDisabled
		if opts.Sandbox {
			behaviorMode = types.BehaviorHeuristic
		}
	}
	sandboxEnabled := behaviorMode != types.BehaviorDisabled
	scanner.SandboxEnabled = sandboxEnabled
	scanner.BehaviorMode = behaviorMode
	if opts.Timeout > 0 {
		scanner.SandboxTimeout = opts.Timeout
	}

	var findings []Finding
	summary := Summary{
		PackagesScanned: len(depsToScan),
	}

	// Scan dependencies concurrently (bounded). A per-dependency failure is
	// surfaced as DecisionUnknown rather than aborting the entire scan.
	scanned := parallelScan(depsToScan,
		func(d Dependency) (string, string) { return d.Name, d.Version },
		func(name, version string) (types.ScanResult, error) {
			sc := scanner // copy per call so concurrent scans don't share mutable state
			return sc.ScanPackage(name, version)
		})

	for i, dep := range depsToScan {
		res := scanned[i]

		// Save the result to cache so explain / other commands can access it
		_ = saveResult(res)

		// Determine direct/dependency_type properties
		isDirect := false
		depType := "transitive"
		if hasDepTypes {
			if t, ok := depTypes[dep.Name]; ok {
				isDirect = true
				depType = t
			}
		}

		// Count critical sandbox findings
		critSandboxFindings := 0
		for _, script := range res.Sandbox.ScriptsExecuted {
			for _, f := range script.Findings {
				if f.Severity == "critical" {
					critSandboxFindings++
				}
			}
		}

		// Increment counts
		switch res.Decision {
		case types.DecisionBlock:
			summary.Block++
		case types.DecisionReviewRequired:
			summary.ReviewRequired++
		case types.DecisionWarn:
			summary.Warn++
		case types.DecisionUnknown:
			summary.Unknown++
		default:
			summary.Allow++
		}

		// Convert reasons
		var reasons []types.Reason
		for _, r := range res.Reasons {
			reasons = append(reasons, types.Reason{
				ID:          r.ID,
				Severity:    r.Severity,
				Description: r.Description,
				Evidence:    r.Evidence,
				ScoreImpact: r.ScoreImpact,
			})
		}

		// Convert vulnerabilities
		var vulnerabilities []types.Vulnerability
		for _, v := range res.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
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
				PublishedAt:   v.PublishedAt,
				ModifiedAt:    v.ModifiedAt,
				FetchedAt:     v.FetchedAt,
			})
		}

		findings = append(findings, Finding{
			Ecosystem:       "npm",
			Package:         dep.Name,
			Version:         dep.Version,
			Decision:        string(res.Decision),
			RiskScore:       res.Score,
			Direct:          isDirect,
			DependencyType:  depType,
			Reasons:         reasons,
			Vulnerabilities: vulnerabilities,
			BehaviorAnalysis: BehaviorAnalysisSummary{
				Enabled:               res.Sandbox.Enabled,
				Available:             res.Sandbox.Available,
				CriticalFindingsCount: critSandboxFindings,
			},
			PackageProfile:    res.Profile,
			RecommendedAction: recommendedActionForFinding(res),
			Policy:            res.PolicyInfo,
			Registry:          res.RegistryInfo,
			Trust:             res.TrustInfo,
			Exception:         res.ExceptionInfo,
		})
	}

	// 4. Determine overall repository decision
	overallDecision := "allow"
	if summary.Block > 0 {
		overallDecision = "block"
	} else if summary.ReviewRequired > 0 {
		overallDecision = "review_required"
	} else if summary.Warn > 0 {
		overallDecision = "warn"
	}

	// Print changed-only summary to stdout (if in terminal / action)
	if isChangedOnlyScan {
		fmt.Println("Changed dependency scan enabled.")
		fmt.Printf("Baseline: %s\n", opts.Baseline)
		if baselineType != "" {
			fmt.Printf("Baseline Type: %s\n", baselineType)
		}
		fmt.Printf("Changed packages found: %d\n\n", len(changedPkgs))
		for _, cp := range changedPkgs {
			if cp.FromVersion == "added" {
				fmt.Printf("- %s: added %s\n", cp.Name, cp.ToVersion)
			} else {
				fmt.Printf("- %s: %s -> %s\n", cp.Name, cp.FromVersion, cp.ToVersion)
			}
		}
		if len(changedPkgs) > 0 {
			fmt.Println()
		}
	}

	policyPack, policyPackVersion := pol.PolicyPackName, pol.PolicyPackVersion
	var exceptionsUsed []string
	for _, f := range findings {
		if f.Exception != nil && f.Exception.Matched {
			exceptionsUsed = append(exceptionsUsed, f.Exception.RuleID)
		}
	}
	exceptionsUsed = uniqueStrings(exceptionsUsed)
	enrichVulnerabilitySummary(&summary, findings)

	return &ScanResult{
		SchemaVersion:     "1.0",
		Tool:              "pkgsafe",
		Command:           "ci scan",
		Mode:              string(pol.Mode),
		FailOn:            failOn,
		Decision:          overallDecision,
		Lockfile:          lockfile,
		Ecosystem:         "npm",
		ChangedOnly:       isChangedOnlyScan,
		Baseline:          opts.Baseline,
		BaselineType:      baselineType,
		Summary:           summary,
		Findings:          findings,
		PolicyPack:        policyPack,
		PolicyPackVersion: policyPackVersion,
		ExceptionsUsed:    exceptionsUsed,
	}, nil
}

func baselineFileContent(path string) ([]byte, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if info.IsDir() {
		return nil, true, fmt.Errorf("baseline path is a directory")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	return content, true, nil
}

func runPyPIScan(opts ScanOptions, pol policy.Policy, failOn string) (*ScanResult, error) {
	files := pythonDependencyFiles(opts)
	if len(files) == 0 {
		return nil, ScanError{Err: fmt.Errorf("no Python dependency files found"), ExitCode: ExitLockfileError}
	}
	var deps []pydeps.Dependency
	for _, file := range files {
		parsed, err := pydeps.ParseFile(file)
		if err != nil {
			return nil, ScanError{Err: fmt.Errorf("parse Python dependency file %q: %w", file, err), ExitCode: ExitLockfileError}
		}
		deps = append(deps, parsed...)
	}
	// One scan target per name@version even when several manifests/lockfiles
	// list the same dependency; the project's own lock entry and local path
	// sources are not registry packages.
	deps = pydeps.Dedupe(deps)
	filtered := deps[:0]
	for _, dep := range deps {
		if dep.LocalSource {
			fmt.Fprintf(os.Stderr, "Note: skipping %s (local project or path source in %s)\n", dep.Name, dep.SourceFile)
			continue
		}
		filtered = append(filtered, dep)
	}
	deps = filtered
	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = opts.Offline
	scanner.SandboxEnabled = opts.SandboxSpecified && opts.Sandbox
	scanner.RequestedBy = "human"
	scanner.Environment = "ci"

	var findings []Finding
	summary := Summary{PackagesScanned: len(deps)}
	for _, dep := range deps {
		if !dep.Pinned {
			fmt.Fprintf(os.Stderr, "Warning: %s is unpinned in %s\n", dep.Name, dep.SourceFile)
		}
	}

	// Scan concurrently (bounded); a per-dependency failure becomes
	// DecisionUnknown instead of aborting the whole scan. Direct URL/VCS
	// dependencies never touch the index — scanning the same name on PyPI
	// would inspect a different artifact — so they surface as UNKNOWN.
	scanned := make([]types.ScanResult, len(deps))
	var registryIdx []int
	var registryDeps []pydeps.Dependency
	for i, dep := range deps {
		if dep.DirectURL != "" {
			scanned[i] = directURLScanResult(dep)
			continue
		}
		registryIdx = append(registryIdx, i)
		registryDeps = append(registryDeps, dep)
	}
	for j, res := range parallelScan(registryDeps,
		func(d pydeps.Dependency) (string, string) { return d.Name, d.Version },
		func(name, version string) (types.ScanResult, error) {
			sc := scanner // copy per call to avoid shared mutable state
			return sc.ScanPackage(name, version)
		}) {
		scanned[registryIdx[j]] = res
	}

	for i := range deps {
		res := scanned[i]
		_ = saveResult(res)
		switch res.Decision {
		case types.DecisionBlock:
			summary.Block++
		case types.DecisionReviewRequired:
			summary.ReviewRequired++
		case types.DecisionWarn:
			summary.Warn++
		case types.DecisionUnknown:
			summary.Unknown++
		default:
			summary.Allow++
		}
		findings = append(findings, Finding{
			Ecosystem:         "pypi",
			Package:           res.Package.Name,
			Version:           res.Package.Version,
			Decision:          string(res.Decision),
			RiskScore:         res.Score,
			Direct:            !deps[i].FromLockfile,
			DependencyType:    "python",
			Reasons:           res.Reasons,
			Vulnerabilities:   res.Vulnerabilities,
			BehaviorAnalysis:  BehaviorAnalysisSummary{Enabled: res.Sandbox.Enabled, Available: res.Sandbox.Available},
			PackageProfile:    res.Profile,
			RecommendedAction: recommendedActionForFinding(res),
			Policy:            res.PolicyInfo,
			Registry:          res.RegistryInfo,
			Trust:             res.TrustInfo,
			Exception:         res.ExceptionInfo,
		})
	}
	overallDecision := "allow"
	if summary.Block > 0 {
		overallDecision = "block"
	} else if summary.ReviewRequired > 0 {
		overallDecision = "review_required"
	} else if summary.Warn > 0 {
		overallDecision = "warn"
	}
	policyPack, policyPackVersion := pol.PolicyPackName, pol.PolicyPackVersion
	var exceptionsUsed []string
	for _, f := range findings {
		if f.Exception != nil && f.Exception.Matched {
			exceptionsUsed = append(exceptionsUsed, f.Exception.RuleID)
		}
	}
	exceptionsUsed = uniqueStrings(exceptionsUsed)
	enrichVulnerabilitySummary(&summary, findings)

	return &ScanResult{
		SchemaVersion:     "1.0",
		Tool:              "pkgsafe",
		Command:           "ci scan",
		Mode:              string(pol.Mode),
		FailOn:            failOn,
		Decision:          overallDecision,
		Lockfile:          firstFile(files),
		DependencyFiles:   files,
		Ecosystem:         "pypi",
		ChangedOnly:       false,
		Baseline:          opts.Baseline,
		Summary:           summary,
		Findings:          findings,
		PolicyPack:        policyPack,
		PolicyPackVersion: policyPackVersion,
		ExceptionsUsed:    exceptionsUsed,
	}, nil
}

func detectEcosystem(opts ScanOptions) string {
	file := firstNonEmpty(opts.DependencyFile, opts.LockfilePath)
	base := strings.ToLower(filepath.Base(file))
	switch base {
	case "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock":
		return "pypi"
	case "package-lock.json":
		return "npm"
	}
	for _, name := range []string{"package-lock.json", "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock"} {
		if _, err := os.Stat(name); err == nil {
			if name == "package-lock.json" {
				return "npm"
			}
			return "pypi"
		}
	}
	return "npm"
}

func pythonDependencyFiles(opts ScanOptions) []string {
	if opts.DependencyFile != "" {
		return []string{opts.DependencyFile}
	}
	if opts.LockfilePath != "" && filepath.Base(opts.LockfilePath) != "package-lock.json" {
		return []string{opts.LockfilePath}
	}
	var files []string
	for _, name := range []string{"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock"} {
		if _, err := os.Stat(name); err == nil {
			files = append(files, name)
		}
	}
	return files
}

// directURLScanResult marks a direct URL/VCS dependency as not scanned. It is
// explicitly DecisionUnknown — never a clean ALLOW.
func directURLScanResult(dep pydeps.Dependency) types.ScanResult {
	return types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "pypi", Name: dep.Name, Version: dep.Version},
		Decision: types.DecisionUnknown,
		Reasons: []types.Reason{{
			ID:          "direct_url_dependency_not_scanned",
			Severity:    "medium",
			Description: "Dependency resolves from a direct URL/VCS source, not the package index; the artifact was not scanned.",
			Evidence:    dep.DirectURL,
		}},
	}
}

func firstFile(files []string) string {
	if len(files) == 0 {
		return ""
	}
	return files[0]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func loadPackageJSONInfo(lockfilePath string) (map[string]string, bool) {
	dir := filepath.Dir(lockfilePath)
	pkgJSONPath := filepath.Join(dir, "package.json")
	b, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil, false
	}
	type pkgJSONStruct struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var pj pkgJSONStruct
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil, false
	}
	depTypes := make(map[string]string)
	for name := range pj.Dependencies {
		depTypes[name] = "production"
	}
	for name := range pj.DevDependencies {
		depTypes[name] = "dev"
	}
	return depTypes, true
}

func saveResult(res types.ScanResult) error {
	store, err := cache.Load("")
	if err != nil {
		return err
	}
	return store.Put(res)
}

func recommendedActionForFinding(res types.ScanResult) string {
	if res.Recommended != "" {
		return res.Recommended
	}
	var fixedVersions []string
	for _, v := range res.Vulnerabilities {
		if len(v.FixedVersions) > 0 {
			fixedVersions = append(fixedVersions, v.FixedVersions...)
		}
	}
	if len(fixedVersions) > 0 {
		return fmt.Sprintf("Upgrade to %s@%s or later.", res.Package.Name, strings.Join(uniqueStrings(fixedVersions), ", "))
	}
	switch res.Decision {
	case types.DecisionBlock:
		return "Remove or replace this dependency."
	case types.DecisionWarn:
		return "Review package before installing."
	default:
		return "Package appears safe to install."
	}
}

func enrichVulnerabilitySummary(summary *Summary, findings []Finding) {
	bySeverity := map[string]int{}
	var recommendations []string
	for _, f := range findings {
		for _, v := range f.Vulnerabilities {
			summary.VulnerabilityCount++
			if v.Severity != "" {
				bySeverity[v.Severity]++
			}
			if len(v.FixedVersions) > 0 {
				recommendations = append(recommendations, fmt.Sprintf("%s@%s -> %s", f.Package, f.Version, strings.Join(uniqueStrings(v.FixedVersions), ", ")))
			}
		}
	}
	if len(bySeverity) > 0 {
		summary.VulnerabilitiesBySeverity = bySeverity
	}
	if len(recommendations) > 0 {
		summary.FixedVersionRecommendations = uniqueStrings(recommendations)
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
