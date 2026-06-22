package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	pydeps "github.com/niyam-ai/pkgsafe/internal/deps/python"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
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
	pol, err := policy.Load(opts.PolicyPath)
	if err != nil {
		return nil, ScanError{Err: fmt.Errorf("load policy: %w", err), ExitCode: ExitPolicyError}
	}

	// Override policy settings with CLI arguments if specified
	if opts.Mode != "" {
		pMode, err := policy.ApplyMode(pol, opts.Mode)
		if err != nil {
			return nil, ScanError{Err: fmt.Errorf("invalid mode: %w", err), ExitCode: ExitUsageError}
		}
		pol = pMode
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

	if changedOnly {
		dir := filepath.Dir(lockfile)
		if IsGitRepo(dir) {
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
	sandboxEnabled := pol.Sandbox.Enabled
	if opts.SandboxSpecified {
		sandboxEnabled = opts.Sandbox
	}
	scanner.SandboxEnabled = sandboxEnabled
	if opts.Timeout > 0 {
		scanner.SandboxTimeout = opts.Timeout
	}

	var findings []Finding
	summary := Summary{
		PackagesScanned: len(depsToScan),
	}

	for _, dep := range depsToScan {
		res, err := scanner.ScanPackage(dep.Name, dep.Version)
		if err != nil {
			return nil, ScanError{Err: fmt.Errorf("scan package %s@%s: %w", dep.Name, dep.Version, err), ExitCode: ExitInternalError}
		}

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
		case types.DecisionWarn:
			summary.Warn++
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
				Aliases:       v.Aliases,
				Severity:      v.Severity,
				Summary:       v.Summary,
				FixedVersions: v.FixedVersions,
				References:    v.References,
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
			Sandbox: SandboxSummary{
				Enabled:               res.Sandbox.Enabled,
				Available:             res.Sandbox.Available,
				CriticalFindingsCount: critSandboxFindings,
			},
			RecommendedAction: recommendedActionForFinding(res),
		})
	}

	// 4. Determine overall repository decision
	overallDecision := "allow"
	if summary.Block > 0 {
		overallDecision = "block"
	} else if summary.Warn > 0 {
		overallDecision = "warn"
	}

	// Print changed-only summary to stdout (if in terminal / action)
	if isChangedOnlyScan {
		fmt.Println("Changed dependency scan enabled.")
		fmt.Printf("Baseline: %s\n", opts.Baseline)
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

	return &ScanResult{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		Command:       "ci scan",
		Mode:          string(pol.Mode),
		FailOn:        failOn,
		Decision:      overallDecision,
		Lockfile:      lockfile,
		Ecosystem:     "npm",
		ChangedOnly:   isChangedOnlyScan,
		Baseline:      opts.Baseline,
		Summary:       summary,
		Findings:      findings,
	}, nil
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
	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = opts.Offline
	scanner.SandboxEnabled = opts.SandboxSpecified && opts.Sandbox

	var findings []Finding
	summary := Summary{PackagesScanned: len(deps)}
	for _, dep := range deps {
		if !dep.Pinned {
			fmt.Fprintf(os.Stderr, "Warning: %s is unpinned in %s\n", dep.Name, dep.SourceFile)
		}
		res, err := scanner.ScanPackage(dep.Name, dep.Version)
		if err != nil {
			return nil, ScanError{Err: fmt.Errorf("scan package %s@%s: %w", dep.Name, dep.Version, err), ExitCode: ExitInternalError}
		}
		_ = saveResult(res)
		switch res.Decision {
		case types.DecisionBlock:
			summary.Block++
		case types.DecisionWarn:
			summary.Warn++
		default:
			summary.Allow++
		}
		findings = append(findings, Finding{
			Ecosystem:         "pypi",
			Package:           res.Package.Name,
			Version:           res.Package.Version,
			Decision:          string(res.Decision),
			RiskScore:         res.Score,
			Direct:            true,
			DependencyType:    "python",
			Reasons:           res.Reasons,
			Vulnerabilities:   res.Vulnerabilities,
			Sandbox:           SandboxSummary{Enabled: res.Sandbox.Enabled, Available: res.Sandbox.Available},
			RecommendedAction: recommendedActionForFinding(res),
		})
	}
	overallDecision := "allow"
	if summary.Block > 0 {
		overallDecision = "block"
	} else if summary.Warn > 0 {
		overallDecision = "warn"
	}
	return &ScanResult{
		SchemaVersion:   "1.0",
		Tool:            "pkgsafe",
		Command:         "ci scan",
		Mode:            string(pol.Mode),
		FailOn:          failOn,
		Decision:        overallDecision,
		Lockfile:        firstFile(files),
		DependencyFiles: files,
		Ecosystem:       "pypi",
		ChangedOnly:     false,
		Baseline:        opts.Baseline,
		Summary:         summary,
		Findings:        findings,
	}, nil
}

func detectEcosystem(opts ScanOptions) string {
	file := firstNonEmpty(opts.DependencyFile, opts.LockfilePath)
	base := strings.ToLower(filepath.Base(file))
	switch base {
	case "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock":
		return "pypi"
	case "package-lock.json":
		return "npm"
	}
	for _, name := range []string{"package-lock.json", "requirements.txt", "pyproject.toml"} {
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
	for _, name := range []string{"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"} {
		if _, err := os.Stat(name); err == nil {
			files = append(files, name)
		}
	}
	return files
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
