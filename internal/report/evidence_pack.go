package report

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          string         `json:"tool"`
	GeneratedAt   string         `json:"generated_at"`
	Repository    string         `json:"repository"`
	PolicyPack    string         `json:"policy_pack"`
	Files         []ManifestFile `json:"files"`
}

func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CreateEvidencePack bundles reports into a ZIP archive with a manifest.json.
func CreateEvidencePack(outputPath string, r *RepositoryRiskReport, pol policy.Policy) error {
	// 1. Prepare files in memory
	filesMap := make(map[string][]byte)

	mdRep, _ := ExportMarkdown(r)
	filesMap["repository-risk-report.md"] = []byte(mdRep)

	jsonRep, _ := ExportJSON(r)
	filesMap["repository-risk-report.json"] = []byte(jsonRep)

	filesMap["policy-evidence.md"] = []byte(ExportPolicyEvidence(pol))
	filesMap["exceptions.md"] = []byte(ExportExceptionsReport(r))

	overridesCSV, _ := ExportCSV(r, "overrides")
	filesMap["overrides.csv"] = []byte(overridesCSV)

	filesMap["registry-evidence.md"] = []byte(ExportRegistryEvidence(r))
	filesMap["dependency-confusion.md"] = []byte(ExportDependencyConfusionReport(r))
	filesMap["ai-agent-activity.md"] = []byte(ExportAIAgentActivityReport(r))

	siem, _ := ExportSIEM(r)
	filesMap["siem-events.jsonl"] = []byte(siem)

	sNow, _ := ExportServiceNow(r)
	filesMap["servicenow-evidence.json"] = []byte(sNow)

	azDev, _ := ExportAzureDevOps(r)
	filesMap["azure-devops-evidence.md"] = []byte(azDev)

	sarif, _ := ExportSarif(r)
	filesMap["sarif/pkgsafe-results.sarif"] = []byte(sarif)

	findingsRaw, _ := json.MarshalIndent(r.Findings, "", "  ")
	filesMap["raw/scan-results.json"] = findingsRaw

	policyCopy := pol
	if policyCopy.Registries.Registries != nil {
		// Deep copy registries map to avoid mutability side-effects
		regsCopy := make(map[string]map[string]policy.RegistryConfig)
		for eco, configs := range policyCopy.Registries.Registries {
			regsCopy[eco] = make(map[string]policy.RegistryConfig)
			for name, cfg := range configs {
				cfg.URL = redactURL(cfg.URL)
				cfg.SimpleURL = redactURL(cfg.SimpleURL)
				regsCopy[eco][name] = cfg
			}
		}
		policyCopy.Registries.Registries = regsCopy
	}

	policyRaw, _ := json.MarshalIndent(policyCopy, "", "  ")
	filesMap["raw/policy-effective.json"] = policyRaw

	// Redact all reports and raw files to prevent credentials leakage
	for k, content := range filesMap {
		filesMap[k] = []byte(registry.RedactSecrets(string(content)))
	}

	// 2. Build Manifest
	var manifestFiles []ManifestFile
	for path, content := range filesMap {
		manifestFiles = append(manifestFiles, ManifestFile{
			Path:   "pkgsafe-evidence-pack/" + path,
			SHA256: calculateSHA256(content),
		})
	}

	manifest := Manifest{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repository:    registry.RedactSecrets(r.Repository.Name),
		PolicyPack:    registry.RedactSecrets(r.Policy.PackName + "@" + r.Policy.PackVersion),
		Files:         manifestFiles,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest.json: %w", err)
	}

	// 3. Write ZIP
	absPath := outputPath
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		return fmt.Errorf("create output parent dir: %w", err)
	}

	zipFile, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("create zip file: %w", err)
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	// Write manifest.json
	fWriter, err := archive.Create("pkgsafe-evidence-pack/manifest.json")
	if err != nil {
		return err
	}
	if _, err := fWriter.Write(manifestBytes); err != nil {
		return err
	}

	// Write other files
	for path, content := range filesMap {
		fWriter, err := archive.Create("pkgsafe-evidence-pack/" + path)
		if err != nil {
			return err
		}
		if _, err := fWriter.Write(content); err != nil {
			return err
		}
	}

	return nil
}
