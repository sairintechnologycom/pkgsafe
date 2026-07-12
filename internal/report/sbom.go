package report

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

// ExportDependencySPDX emits a dependency-level SPDX 2.3 document derived from
// the repository risk report. Each unique scanned package becomes one package
// entry with a purl external reference and evidence-oriented comment.
func ExportDependencySPDX(r *RepositoryRiskReport) (string, error) {
	if r == nil {
		return "", fmt.Errorf("report is required")
	}

	seen := map[string]bool{}
	pkgs := make([]SPDXPackage, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Package == "" {
			continue
		}
		key := strings.ToLower(f.Ecosystem) + ":" + f.Package + "@" + f.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		spdxID := "SPDXRef-Package-" + sanitizeSPDXID(f.Ecosystem+"-"+f.Package+"-"+f.Version)
		purl := packageURL(f.Ecosystem, f.Package, f.Version)
		comment := fmt.Sprintf("decision=%s risk=%d rule=%s registry=%s", strings.ToUpper(f.Decision), f.RiskScore, f.RuleID, f.Registry.Name)
		if f.Registry.Type != "" {
			comment += " registry_type=" + f.Registry.Type
		}
		pkgs = append(pkgs, SPDXPackage{
			Name:             f.Package,
			SPDXID:           spdxID,
			VersionInfo:      f.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			ExternalRefs: []SPDXExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}},
			PackageComment: comment,
		})
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].VersionInfo < pkgs[j].VersionInfo
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	doc := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "pkgsafe-dependency-sbom",
		DocumentNamespace: "https://github.com/sairintechnologycom/pkgsafe/sbom/dependency/" + sanitizeSPDXID(r.Repository.Commit+"-"+firstNonEmpty(r.GeneratedAt, time.Now().UTC().Format(time.RFC3339))),
		CreationInfo: SPDXCreationInfo{
			Creators: []string{"Tool: PkgSafe"},
			Created:  firstNonEmpty(r.GeneratedAt, time.Now().UTC().Format(time.RFC3339)),
		},
		Packages: pkgs,
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return registry.RedactSecrets(string(b)), nil
}

func packageURL(ecosystem, name, version string) string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if eco == "" || name == "" {
		return "pkg:generic/unknown"
	}
	if version == "" {
		return "pkg:" + eco + "/" + path.Clean(name)
	}
	return "pkg:" + eco + "/" + path.Clean(name) + "@" + version
}

func sanitizeSPDXID(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
