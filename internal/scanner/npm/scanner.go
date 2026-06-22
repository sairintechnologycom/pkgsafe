package npm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	anpm "github.com/niyam-ai/pkgsafe/internal/analyzer/npm"
	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/intel"
	"github.com/niyam-ai/pkgsafe/internal/intel/osv"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	rnpm "github.com/niyam-ai/pkgsafe/internal/registry/npm"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Scanner struct {
	Registry rnpm.Client
	Policy   policy.Policy
	CacheDir string
	Offline  bool
	DBPath   string
}

func New() Scanner {
	return Scanner{
		Registry: rnpm.NewClient(""),
		Policy:   policy.Default(),
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
			return res, nil
		}
		defer d.Close()

		vulns, err := d.GetVulnerabilitiesForPackage(ctx, "npm", res.Package.Name)
		if err != nil {
			return res, nil
		}

		var affectedVulns []types.Vulnerability
		var findings []types.Reason

		for _, v := range vulns {
			if intel.IsVersionAffected(res.Package.Version, v) {
				affectedVulns = append(affectedVulns, types.Vulnerability{
					ID:            v.ID,
					Aliases:       v.Aliases,
					Severity:      v.Severity,
					Summary:       v.Summary,
					FixedVersions: v.FixedVersions,
					References:    v.References,
				})

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
		return evalRes, nil
	}

	md, err := s.Registry.FetchMetadata(name)
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

	tarballPath, err := s.Registry.DownloadTarball(vm.Dist.Tarball, s.CacheDir)
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
	if res.Package.Name == "" || res.Package.Name == "unknown" {
		res.Package.Name = name
	}
	if vm.Version != "" {
		res.Package.Version = vm.Version
	}

	var baseFindings []types.Reason
	baseFindings = append(baseFindings, res.Reasons...)
	if !vm.Time.IsZero() {
		if rule, ok := policy.RuleFor(pol, "new_package"); ok && rule.MaxAgeDays > 0 {
			ageDays := int(time.Since(vm.Time).Hours() / 24)
			if ageDays >= 0 && ageDays <= rule.MaxAgeDays {
				baseFindings = append(baseFindings, risk.NewPackageFinding(ageDays))
			}
		}
	}

	osvClient := osv.NewClient()
	rawVulns, err := osvClient.Query(ctx, osv.QueryRequest{
		Package: &osv.Package{Name: res.Package.Name, Ecosystem: "npm"},
		Version: res.Package.Version,
	})

	var typesVulns []types.Vulnerability
	var vulnFindings []types.Reason

	d, dbErr := db.Open(s.DBPath)

	if err == nil && len(rawVulns) > 0 {
		var dbVulns []db.Vulnerability
		for _, v := range rawVulns {
			dbV := osv.MapVulnerability(v, res.Package.Name, "npm")
			dbVulns = append(dbVulns, dbV)

			typesVulns = append(typesVulns, types.Vulnerability{
				ID:            dbV.ID,
				Aliases:       dbV.Aliases,
				Severity:      dbV.Severity,
				Summary:       dbV.Summary,
				FixedVersions: dbV.FixedVersions,
				References:    dbV.References,
			})

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
	return finalRes, nil
}

func ScanPackage(name, version string) (types.ScanResult, error) {
	return New().ScanPackage(name, version)
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
