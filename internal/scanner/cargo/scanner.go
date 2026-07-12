package cargo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	acargo "github.com/sairintechnologycom/pkgsafe/internal/analyzer/cargo"
	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel"
	"github.com/sairintechnologycom/pkgsafe/internal/intel/osv"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	"github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// Scanner handles scanning Rust crates using crates.io or the local DB.
type Scanner struct {
	BaseURL      string // defaults to https://crates.io if empty
	Policy       policy.Policy
	Offline      bool
	DBPath       string
	RequestedBy  string
	Environment  string
	RegistryName string
}

type crateVersion struct {
	Num       string    `json:"num"`
	CreatedAt time.Time `json:"created_at"`
	Yanked    bool      `json:"yanked"`
}

type crateResponse struct {
	Version crateVersion `json:"version"`
}

// New returns a new Cargo Scanner with default configuration.
func New() Scanner {
	return Scanner{
		BaseURL:     "https://crates.io",
		Policy:      policy.Default(),
		RequestedBy: "human",
		Environment: "developer",
	}
}

// ScanPackage scans a crate name and version.
func (s Scanner) ScanPackage(name, version string) (types.ScanResult, error) {
	if name == "" {
		return types.ScanResult{}, fmt.Errorf("package name is required")
	}
	pol := s.Policy
	if pol.Mode == "" {
		pol = policy.Default()
	}

	var regName string
	var regCfg policy.RegistryConfig
	if s.RegistryName != "" {
		if cfg, ok := pol.Registries.Registries["cargo"][s.RegistryName]; ok {
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
		regName, regCfg = registry.ResolveRegistry("cargo", name, pol)
	}

	if !regCfg.Enabled && regCfg.Type != "unknown" {
		return types.ScanResult{}, fmt.Errorf("registry for package %s is disabled by policy", name)
	}

	// 1. Check cache first
	store, err := cache.Load("")
	if err == nil {
		if res, ok := store.Get("cargo", name, version); ok {
			return res, nil
		}
	}

	// 2. If running offline
	if s.Offline {
		pkg := types.PackageIdentity{
			Ecosystem: "cargo",
			Name:      name,
			Version:   version,
		}
		var findings []types.Reason
		var affectedVulns []types.Vulnerability

		if s.DBPath != "" {
			ctx := context.Background()
			if d, err := db.Open(s.DBPath); err == nil {
				defer d.Close()
				vulns, err := d.GetVulnerabilitiesForPackage(ctx, "crates.io", name)
				if err == nil {
					for _, v := range vulns {
						if intel.IsVersionAffected(version, v) {
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
				}
			}
		}

		res := risk.Evaluate(pkg, findings, nil, nil, nil, pol)
		res.Vulnerabilities = affectedVulns
		return risk.ApplyPolicyControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
	}

	// 3. Online scanning
	baseURL := s.BaseURL
	if baseURL == "" {
		baseURL = "https://crates.io"
	}

	url := fmt.Sprintf("%s/api/v1/crates/%s/%s", baseURL, name, version)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "pkgsafe/0.1.0 (contact: info@pkgsafe.dev)")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to fetch crate info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.ScanResult{}, fmt.Errorf("crate info request failed with status: %d", resp.StatusCode)
	}

	var info crateResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to decode crate info: %w", err)
	}

	pkgVersion := info.Version.Num
	if pkgVersion == "" {
		pkgVersion = version
	}

	// Download and extract Cargo crate tarball (.crate)
	downloadBase := "https://static.crates.io"
	if s.BaseURL != "" && !strings.Contains(s.BaseURL, "crates.io") {
		downloadBase = s.BaseURL
	}
	crateURL := fmt.Sprintf("%s/crates/%s/%s-%s.crate", downloadBase, name, name, pkgVersion)
	tmpCrate, err := os.CreateTemp("", "pkgsafe-cargo-*.crate")
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to create temp crate file: %w", err)
	}
	defer os.Remove(tmpCrate.Name())
	defer tmpCrate.Close()

	crateReq, err := http.NewRequestWithContext(ctx, "GET", crateURL, nil)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to create crate request: %w", err)
	}
	crateReq.Header.Set("User-Agent", "pkgsafe/0.1.0 (contact: info@pkgsafe.dev)")

	crateResp, err := httpClient.Do(crateReq)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to download crate: %w", err)
	}
	defer crateResp.Body.Close()
	if crateResp.StatusCode != http.StatusOK {
		return types.ScanResult{}, fmt.Errorf("failed to download crate, status: %d", crateResp.StatusCode)
	}

	if _, err := io.Copy(tmpCrate, crateResp.Body); err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to save crate tarball: %w", err)
	}
	_ = tmpCrate.Close()

	extractDir, err := os.MkdirTemp("", "pkgsafe-cargo-extracted-*")
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to create extraction dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := pypi.ExtractTarGz(tmpCrate.Name(), extractDir); err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to extract crate tarball: %w", err)
	}

	var suspicious []string
	var findings []types.Reason

	analysis, err := acargo.AnalyzeDir(extractDir, name, pkgVersion, pol)
	if err == nil {
		findings = append(findings, analysis.Findings...)
		suspicious = append(suspicious, analysis.Result.Suspicious...)
	}

	pkg := types.PackageIdentity{
		Ecosystem: "cargo",
		Name:      name,
		Version:   pkgVersion,
	}
	if !info.Version.CreatedAt.IsZero() {
		ageDays := int(time.Since(info.Version.CreatedAt).Hours() / 24)
		if rule, ok := policy.RuleFor(pol, "new_package"); ok && rule.MaxAgeDays > 0 {
			if ageDays >= 0 && ageDays <= rule.MaxAgeDays {
				findings = append(findings, risk.NewPackageFinding(ageDays))
			}
		}
	}

	var affectedVulns []types.Vulnerability
	osvClient := osv.NewClient()
	rawVulns, err := osvClient.Query(ctx, osv.QueryRequest{
		Package: &osv.Package{Name: name, Ecosystem: "crates.io"},
		Version: pkgVersion,
	})
	if err != nil {
		// Fail closed: the OSV lookup did not complete, so this package was not
		// checked for known vulnerabilities. Surface it instead of scoring clean.
		fmt.Fprintf(os.Stderr, "Warning: OSV vulnerability lookup failed for crates.io/%s@%s: %v; failing closed (advisory data unavailable)\n", name, pkgVersion, err)
		findings = append(findings, risk.VulnDataUnavailableReason(err))
	} else if len(rawVulns) > 0 {
		var dbVulns []db.Vulnerability
		for _, v := range rawVulns {
			dbV := osv.MapVulnerability(v, name, "crates.io")
			dbVulns = append(dbVulns, dbV)

			affectedVulns = append(affectedVulns, types.Vulnerability{
				ID:            dbV.ID,
				Aliases:       dbV.Aliases,
				Severity:      dbV.Severity,
				Summary:       dbV.Summary,
				FixedVersions: dbV.FixedVersions,
				References:    dbV.References,
			})

			if intel.IsMalware(dbV) {
				findings = append(findings, types.Reason{
					ID:          "known_malware_indicator",
					Description: "Package contains malware or malicious code",
					Evidence:    dbV.ID,
				})
			} else {
				findings = append(findings, types.Reason{
					ID:          "known_vulnerability_" + dbV.Severity,
					Description: fmt.Sprintf("Package version has a %s severity advisory", dbV.Severity),
					Evidence:    dbV.ID,
				})
			}
		}

		if s.DBPath != "" {
			if d, dbErr := db.Open(s.DBPath); dbErr == nil {
				defer d.Close()
				_ = d.SaveVulnerabilities(ctx, dbVulns)
				for _, dbV := range dbVulns {
					_ = d.SaveVulnerabilityIndex(ctx, "crates.io", name, pkgVersion, dbV.ID)
				}
			}
		}
	}

	res := risk.Evaluate(pkg, findings, nil, suspicious, nil, pol)
	res.Vulnerabilities = affectedVulns
	res.Artifact.Yanked = info.Version.Yanked

	return risk.ApplyPolicyControls(res, pol, regName, regCfg, s.RequestedBy, s.Environment), nil
}
