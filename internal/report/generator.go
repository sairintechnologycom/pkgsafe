package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/audit"
	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	pydeps "github.com/sairintechnologycom/pkgsafe/internal/deps/python"
	"github.com/sairintechnologycom/pkgsafe/internal/git"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type packageLock struct {
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

func parseNPMLockfile(path string) ([]types.PackageIdentity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pl packageLock
	if err := json.Unmarshal(b, &pl); err != nil {
		return nil, err
	}
	var pkgs []types.PackageIdentity

	for pkgPath, info := range pl.Packages {
		if pkgPath == "" {
			continue
		}
		parts := strings.Split(pkgPath, "node_modules/")
		name := parts[len(parts)-1]
		if name != "" {
			pkgs = append(pkgs, types.PackageIdentity{
				Ecosystem: "npm",
				Name:      name,
				Version:   info.Version,
			})
		}
	}

	if len(pkgs) == 0 {
		for name, info := range pl.Dependencies {
			pkgs = append(pkgs, types.PackageIdentity{
				Ecosystem: "npm",
				Name:      name,
				Version:   info.Version,
			})
		}
	}
	return pkgs, nil
}

// GenerateReport compiles the full repository risk report.
func GenerateReport(repoPath string, pol policy.Policy, offline bool) (*RepositoryRiskReport, error) {
	report := &RepositoryRiskReport{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		ReportType:    "repository-risk-report",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// 1. Git Metadata
	gitMeta, err := git.DetectMetadata(repoPath)
	if err == nil {
		report.Repository = RepositoryMetadata{
			Path:      gitMeta.Root,
			Name:      filepath.Base(gitMeta.Root),
			RemoteURL: gitMeta.RemoteURL,
			Branch:    gitMeta.Branch,
			Commit:    gitMeta.Commit,
			Dirty:     gitMeta.Dirty,
			LatestTag: gitMeta.LatestTag,
		}
	} else {
		report.Repository = RepositoryMetadata{
			Path: repoPath,
			Name: filepath.Base(repoPath),
		}
	}

	// 2. Policy details
	report.Policy = PolicyMetadata{
		Source:      nonEmpty(pol.PolicyPackSource, "local"),
		PackName:    nonEmpty(pol.PolicyPackName, "default-policy"),
		PackVersion: nonEmpty(pol.PolicyPackVersion, "1"),
		Owner:       nonEmpty(pol.PolicyPackOwner, "local"),
	}

	// 3. Scan Dependency Files
	store, _ := cache.Load("")
	var detectedFiles []string
	var allPkgs []types.PackageIdentity

	// NPM
	npmLockPath := filepath.Join(repoPath, "package-lock.json")
	if _, err := os.Stat(npmLockPath); err == nil {
		detectedFiles = append(detectedFiles, "package-lock.json")
		pkgs, err := parseNPMLockfile(npmLockPath)
		if err == nil {
			allPkgs = append(allPkgs, pkgs...)
		}
	}

	// Python
	pypiFiles := []string{
		"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock",
		"Pipfile", "Pipfile.lock", "environment.yml", "environment.yaml",
	}
	for _, f := range pypiFiles {
		pPath := filepath.Join(repoPath, f)
		if _, err := os.Stat(pPath); err == nil {
			detectedFiles = append(detectedFiles, f)
			parsed, err := pydeps.ParseFile(pPath)
			if err == nil {
				for _, dep := range parsed {
					allPkgs = append(allPkgs, types.PackageIdentity{
						Ecosystem: "pypi",
						Name:      dep.Name,
						Version:   dep.Version,
					})
				}
			}
		}
	}

	// 4. Retrieve Scan Results
	var findings []ReportFinding
	findingIdx := 1
	var critVuln, highVuln, activeExceptions, privateRegistryViolations, dependencyConfusionFindings int

	for _, pkg := range allPkgs {
		res, hasCached := store.Get(pkg.Ecosystem, pkg.Name, pkg.Version)
		if !hasCached && !offline {
			// Scan package in real-time if not cached
			if pkg.Ecosystem == "npm" {
				scanner := snpm.New()
				scanner.Policy = pol
				scanner.Offline = offline
				if r, err := scanner.ScanPackage(pkg.Name, pkg.Version); err == nil {
					res = r
					_ = store.Put(res)
					hasCached = true
				}
			} else if pkg.Ecosystem == "pypi" {
				scanner := spypi.New()
				scanner.Policy = pol
				scanner.Offline = offline
				if r, err := scanner.ScanPackage(pkg.Name, pkg.Version); err == nil {
					res = r
					_ = store.Put(res)
					hasCached = true
				}
			}
		}

		if !hasCached {
			// The package could not be scanned (offline with no cached result,
			// or a scan error). Mark it UNKNOWN rather than silently passing it
			// as ALLOW/0 — an un-scanned package is not a clean package.
			res = types.ScanResult{
				Package:  pkg,
				Decision: types.DecisionUnknown,
				Score:    0,
				Reasons: []types.Reason{{
					ID:          "package_not_scanned",
					Severity:    "medium",
					Description: "Package could not be scanned (no cached result and scan unavailable); risk is unknown.",
				}},
			}
		}

		// Calculate vulnerabilities
		for _, v := range res.Vulnerabilities {
			if strings.EqualFold(v.Severity, "critical") {
				critVuln++
			} else if strings.EqualFold(v.Severity, "high") {
				highVuln++
			}
		}

		// Calculate exception/registry flags
		excMatched := false
		excID := ""
		excReason := ""
		if res.ExceptionInfo != nil && res.ExceptionInfo.Matched {
			excMatched = true
			excID = res.ExceptionInfo.RuleID
			excReason = res.ExceptionInfo.Reason
			activeExceptions++
		}

		// Check for dependency confusion or registry policy violations
		regName := ""
		regType := ""
		if res.RegistryInfo != nil {
			regName = res.RegistryInfo.Name
			regType = res.RegistryInfo.Type
		}

		isConfusion := false
		isViolation := false
		for _, reason := range res.Reasons {
			if reason.ID == "dependency_confusion_candidate" {
				isConfusion = true
				dependencyConfusionFindings++
			}
			if reason.ID == "private_scope_public_registry" || reason.ID == "unapproved_registry_url" {
				isViolation = true
				privateRegistryViolations++
			}
		}

		// Map to finding schema
		findingID := fmt.Sprintf("PKGSAFE-FINDING-%04d", findingIdx)
		findingIdx++

		var topRule, topMessage, topSeverity string
		topScore := -1000
		for _, reason := range res.Reasons {
			if reason.ScoreImpact > topScore {
				topScore = reason.ScoreImpact
				topRule = reason.ID
				topMessage = reason.Description
				topSeverity = reason.Severity
			}
		}
		if topRule == "" {
			topRule = "default_allow"
			topMessage = "No issues detected"
			topSeverity = "informational"
		}

		findings = append(findings, ReportFinding{
			FindingID: findingID,
			Ecosystem: pkg.Ecosystem,
			Package:   pkg.Name,
			Version:   pkg.Version,
			Decision:  string(res.Decision),
			RiskScore: res.Score,
			Severity:  topSeverity,
			RuleID:    topRule,
			Message:   topMessage,
			Policy: FindingPolicy{
				Pack:       report.Policy.PackName,
				Version:    report.Policy.PackVersion,
				RuleSource: "default-policy.yaml",
			},
			Registry: FindingRegistry{
				Name: regName,
				Type: regType,
			},
			Exception: FindingException{
				Matched: excMatched,
				ID:      excID,
				Reason:  excReason,
			},
			Override: FindingOverride{
				Used: false,
			},
			RecommendedAction: recommendedActionForFinding(res, isConfusion, isViolation),
		})
	}

	report.Findings = findings

	// 5. Parse Audit Log for Overrides
	auditEntries, _ := audit.ReadAuditLog("")
	var overrides []OverrideRecord
	overridesCount := 0

	for _, entry := range auditEntries {
		if entry.OverrideUsed {
			overridesCount++
			user := os.Getenv("USER")
			if user == "" {
				user = "unknown"
			}
			for _, p := range entry.Packages {
				// Mark matching findings as overridden
				for idx, f := range report.Findings {
					if f.Package == p.Name && f.Version == p.Version {
						report.Findings[idx].Override.Used = true
						report.Findings[idx].Override.Reason = entry.Reason
					}
				}

				overrides = append(overrides, OverrideRecord{
					Timestamp:        entry.Timestamp,
					User:             user,
					Repository:       report.Repository.Name,
					Command:          entry.Command,
					Package:          p.Name,
					Ecosystem:        entry.Ecosystem,
					Version:          p.Version,
					Decision:         p.Decision,
					RiskScore:        p.RiskScore,
					OverrideReason:   entry.Reason,
					PolicyPack:       report.Policy.PackName,
					AllowedByPolicy:  pol.InstallInterception.AllowForceRiskAccept,
					MalwareAttempted: p.Decision == "block" && strings.Contains(strings.ToLower(entry.Reason), "malware"),
				})
			}
		}
	}
	report.Overrides = overrides

	// 6. Exceptions Summary
	var exceptions []ExceptionRecord
	for _, exc := range pol.Exceptions {
		daysUntil := int(exc.AllowedUntil.Sub(time.Now()).Hours() / 24)
		status := "Active"
		if exc.IsExpired() {
			status = "Expired"
		}
		used := false
		for _, f := range report.Findings {
			if f.Exception.Matched && f.Exception.ID == exc.ID {
				used = true
				break
			}
		}
		exceptions = append(exceptions, ExceptionRecord{
			ID:                exc.ID,
			Package:           exc.Package,
			Ecosystem:         exc.Ecosystem,
			VersionRange:      exc.VersionRange,
			Reason:            exc.Reason,
			ApprovedBy:        exc.ApprovedBy,
			AllowedUntil:      exc.AllowedUntil,
			DaysUntilExpiry:   daysUntil,
			Environments:      exc.AppliesTo.Environments,
			UsedInRecentScans: used,
			Status:            status,
		})
	}
	report.Exceptions = exceptions

	// 7. Registries Configuration
	var registries []RegistryRecord
	for _, regs := range pol.Registries.Registries {
		for name, cfg := range regs {
			resCount := 0
			blockCount := 0
			for _, f := range report.Findings {
				if f.Registry.Name == name {
					resCount++
				}
				if f.Decision == "block" && f.Registry.Name == name && (f.RuleID == "private_scope_public_registry" || f.RuleID == "dependency_confusion_candidate") {
					blockCount++
				}
			}
			registries = append(registries, RegistryRecord{
				Name:            name,
				URL:             redactURL(cfg.URL),
				Type:            cfg.Type,
				Enabled:         cfg.Enabled,
				Scopes:          cfg.Scopes,
				Prefixes:        cfg.PackagePrefixes,
				AuthMethod:      cfg.Auth.Method,
				ResolutionCount: resCount,
				MismatchBlocks:  blockCount,
			})
		}
	}
	report.Registries = registries

	// 8. Summary Stats
	allowedCount := 0
	warnCount := 0
	blockCount := 0
	unknownCount := 0
	for _, f := range report.Findings {
		switch f.Decision {
		case "block":
			blockCount++
		case "warn":
			warnCount++
		case "unknown":
			unknownCount++
		default:
			allowedCount++
		}
	}

	report.Summary = RiskSummary{
		PackagesScanned:             len(report.Findings),
		Allowed:                     allowedCount,
		Warnings:                    warnCount,
		Blocked:                     blockCount,
		Unknown:                     unknownCount,
		CriticalVulnerabilities:     critVuln,
		HighVulnerabilities:         highVuln,
		ActiveExceptions:            activeExceptions,
		DeveloperOverrides:          overridesCount,
		PrivateRegistryViolations:   privateRegistryViolations,
		DependencyConfusionFindings: dependencyConfusionFindings,
	}

	// 9. Recommendations
	var recommendations []RecommendationRecord
	for _, f := range report.Findings {
		if f.Decision == "block" {
			recommendations = append(recommendations, RecommendationRecord{
				FindingID: f.FindingID,
				Package:   f.Package,
				Version:   f.Version,
				Type:      "block",
				Message:   fmt.Sprintf("Remove or replace blocked package %s@%s: %s", f.Package, f.Version, f.Message),
			})
		}
		if f.Decision == "warn" {
			recommendations = append(recommendations, RecommendationRecord{
				FindingID: f.FindingID,
				Package:   f.Package,
				Version:   f.Version,
				Type:      "warn",
				Message:   fmt.Sprintf("Review warning for package %s@%s: %s", f.Package, f.Version, f.Message),
			})
		}
	}

	for _, exc := range report.Exceptions {
		if exc.Status == "Active" && exc.DaysUntilExpiry <= 30 {
			recommendations = append(recommendations, RecommendationRecord{
				Type:    "exception_expiry",
				Message: fmt.Sprintf("Exception %s for package %s expires soon in %d days. Renew or remediate.", exc.ID, exc.Package, exc.DaysUntilExpiry),
			})
		}
	}

	report.Recommendations = recommendations

	return report, nil
}

func recommendedActionForFinding(res types.ScanResult, isConfusion, isViolation bool) string {
	if res.Decision == types.DecisionBlock {
		return "Remove or replace this dependency."
	}
	if isConfusion {
		return "Configure approved private registry for scope."
	}
	if isViolation {
		return "Fix registry configuration mismatch."
	}
	if len(res.Vulnerabilities) > 0 {
		return "Upgrade to fixed version."
	}
	return "No action required."
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func redactURL(url string) string {
	urlAuthRegex := regexp.MustCompile(`(?i)(https?://)([^/ \t\n\r]+:[^/ \t\n\r]+@)`)
	if urlAuthRegex.MatchString(url) {
		return urlAuthRegex.ReplaceAllString(url, "$1[REDACTED]@")
	}
	return url
}
