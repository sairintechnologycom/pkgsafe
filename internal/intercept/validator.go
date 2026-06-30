package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	pydeps "github.com/niyam-ai/pkgsafe/internal/deps/python"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type packageLock struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Dependencies map[string]dependency  `json:"dependencies"`
	Packages     map[string]lockPackage `json:"packages"`
}

type dependency struct {
	Version string `json:"version"`
}

type lockPackage struct {
	Version string `json:"version"`
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func parseLockfileDeps(content []byte) (map[string]string, error) {
	var lf packageLock
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, err
	}
	deps := make(map[string]string)
	addDep := func(name, ver string) {
		if name == "" || ver == "" {
			return
		}
		deps[name] = ver
	}

	for path, pkg := range lf.Packages {
		if path == "" || path == "node_modules" {
			continue
		}
		name := extractModuleName(path)
		if name != "" && pkg.Version != "" {
			addDep(name, pkg.Version)
		}
	}
	for name, dep := range lf.Dependencies {
		if name != "" && dep.Version != "" {
			addDep(name, dep.Version)
		}
	}
	return deps, nil
}

func extractModuleName(path string) string {
	if strings.HasPrefix(path, "node_modules/") {
		return strings.TrimPrefix(path, "node_modules/")
	}
	return path
}

func parsePackageJSONDeps(content []byte) (map[string]string, error) {
	var pj packageJSON
	if err := json.Unmarshal(content, &pj); err != nil {
		return nil, err
	}
	deps := make(map[string]string)
	for name, ver := range pj.Dependencies {
		deps[name] = ver
	}
	for name, ver := range pj.DevDependencies {
		deps[name] = ver
	}
	return deps, nil
}

func cleanVersionSpecifier(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<")
	if strings.ContainsAny(v, " ,") {
		return ""
	}
	return v
}

func Validate(ctx context.Context, cmd *InstallCommand, sf SafetyFlags, pol policy.Policy, cwd string) ([]types.ScanResult, types.Decision, error) {
	var packagesToScan []PackageRequest

	// 1. Resolve packages to scan from project or files or direct arguments
	if cmd.IsProjectInstall {
		if cmd.Ecosystem == "npm" {
			lockfile := filepath.Join(cwd, "package-lock.json")
			if content, err := os.ReadFile(lockfile); err == nil {
				deps, err := parseLockfileDeps(content)
				if err != nil {
					return nil, types.DecisionBlock, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("parse package-lock.json: %w", err)}
				}
				for name, ver := range deps {
					packagesToScan = append(packagesToScan, PackageRequest{
						Name:             name,
						VersionSpecifier: ver,
						IsDirect:         true,
						Source:           "lockfile",
					})
				}
			} else {
				// Fallback to package.json
				pkgJSONPath := filepath.Join(cwd, "package.json")
				content, err := os.ReadFile(pkgJSONPath)
				if err != nil {
					return nil, types.DecisionBlock, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("package-lock.json or package.json not found in %s", cwd)}
				}
				deps, err := parsePackageJSONDeps(content)
				if err != nil {
					return nil, types.DecisionBlock, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("parse package.json: %w", err)}
				}
				for name, ver := range deps {
					packagesToScan = append(packagesToScan, PackageRequest{
						Name:             name,
						VersionSpecifier: ver,
						IsDirect:         true,
						Source:           "package.json",
					})
				}
			}
		}
	}

	if len(cmd.DependencyFiles) > 0 {
		for _, file := range cmd.DependencyFiles {
			path := file
			if !filepath.IsAbs(path) {
				path = filepath.Join(cwd, path)
			}
			deps, err := pydeps.ParseFile(path)
			if err != nil {
				return nil, types.DecisionBlock, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("parse python dependency file %s: %w", file, err)}
			}
			for _, dep := range deps {
				if !dep.Pinned {
					fmt.Fprintf(os.Stderr, "Warning: %s is unpinned in %s\n", dep.Name, file)
				}
				packagesToScan = append(packagesToScan, PackageRequest{
					Name:             dep.Name,
					VersionSpecifier: dep.Specifier,
					IsDirect:         true,
					Source:           file,
				})
			}
		}
	}

	for _, pkg := range cmd.Packages {
		packagesToScan = append(packagesToScan, pkg)
	}

	// 2. Initialize appropriate scanners
	var scannerNPM snpm.Scanner
	var scannerPyPI spypi.Scanner

	reqBy := sf.RequestedBy
	if reqBy == "" {
		reqBy = "human"
	}
	env := sf.Environment
	if env == "" {
		env = "developer"
	}

	if cmd.Ecosystem == "npm" {
		scannerNPM = snpm.New()
		scannerNPM.Policy = pol
		scannerNPM.Offline = sf.Offline
		scannerNPM.SandboxEnabled = sf.Sandbox || pol.Sandbox.Enabled
		scannerNPM.BehaviorMode = types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, scannerNPM.SandboxEnabled)
		if pol.Sandbox.DefaultTimeoutSeconds > 0 {
			scannerNPM.SandboxTimeout = time.Duration(pol.Sandbox.DefaultTimeoutSeconds) * time.Second
		}
		scannerNPM.NetworkMode = pol.Sandbox.NetworkMode
		scannerNPM.KeepSandbox = pol.Sandbox.KeepSandbox
		scannerNPM.RequestedBy = reqBy
		scannerNPM.Environment = env
	} else {
		scannerPyPI = spypi.New()
		scannerPyPI.Policy = pol
		scannerPyPI.Offline = sf.Offline
		scannerPyPI.SandboxEnabled = sf.Sandbox || pol.Sandbox.Enabled
		scannerPyPI.BehaviorMode = types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, scannerPyPI.SandboxEnabled)
		scannerPyPI.RequestedBy = reqBy
		scannerPyPI.Environment = env
	}

	// 3. Scan each resolved package
	var results []types.ScanResult
	overallDecision := types.DecisionAllow

	for _, pkg := range packagesToScan {
		// Pre-check blocklist to avoid remote registry queries (e.g. 404s in E2E tests)
		if policy.IsBlocked(pol, cmd.Ecosystem, pkg.Name) {
			res := types.ScanResult{
				Package: types.PackageIdentity{
					Ecosystem: cmd.Ecosystem,
					Name:      pkg.Name,
					Version:   pkg.VersionSpecifier,
				},
				Score:    100,
				Decision: types.DecisionBlock,
				Reasons: []types.Reason{
					{
						ID:          "blocked_package",
						Severity:    "critical",
						Description: "Package is blocked by configuration policy",
						ScoreImpact: 100,
					},
				},
			}
			_ = saveResult(res)
			results = append(results, res)
			overallDecision = types.DecisionBlock
			continue
		}

		var res types.ScanResult
		var err error
		if cmd.Ecosystem == "npm" {
			res, err = scannerNPM.ScanPackage(pkg.Name, cleanVersionSpecifier(pkg.VersionSpecifier))
		} else {
			res, err = scannerPyPI.ScanPackage(pkg.Name, cleanVersionSpecifier(pkg.VersionSpecifier))
		}
		if err != nil {
			return nil, types.DecisionBlock, InterceptError{Code: ExitInternalError, Err: fmt.Errorf("scan package %s: %w", pkg.Name, err)}
		}

		_ = saveResult(res)
		results = append(results, res)

		// Decision precedence: block > warn > allow
		if res.Decision == types.DecisionBlock {
			overallDecision = types.DecisionBlock
		} else if res.Decision == types.DecisionWarn && overallDecision != types.DecisionBlock {
			overallDecision = types.DecisionWarn
		}
	}

	return results, overallDecision, nil
}

func saveResult(res types.ScanResult) error {
	store, err := cache.Load("")
	if err != nil {
		return err
	}
	return store.Put(res)
}
