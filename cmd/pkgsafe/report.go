package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	"github.com/sairintechnologycom/pkgsafe/internal/report"
	"github.com/sairintechnologycom/pkgsafe/internal/validation"
	versionpkg "github.com/sairintechnologycom/pkgsafe/internal/version"
)

func cmdReport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe report [generate|evidence-pack|beta-evidence|ga-evidence|team-evidence|exceptions|overrides|policy|ci|siem-export|servicenow-export|azure-devops-export]")
	}

	switch args[0] {
	case "generate":
		return cmdReportGenerate(args[1:])
	case "evidence-pack":
		return cmdReportEvidencePack(args[1:])
	case "beta-evidence":
		return cmdReportBetaEvidence(args[1:])
	case "ga-evidence":
		return cmdReportEvidence(args[1:], "ga")
	case "team-evidence":
		return cmdReportTeamEvidence(args[1:])
	case "exceptions":
		return cmdReportExceptions(args[1:])
	case "overrides":
		return cmdReportOverrides(args[1:])
	case "policy":
		return cmdReportPolicy(args[1:])
	case "ci":
		return cmdReportCI(args[1:])
	case "siem-export":
		return cmdReportSIEM(args[1:])
	case "servicenow-export":
		return cmdReportServiceNow(args[1:])
	case "azure-devops-export":
		return cmdReportAzureDevOps(args[1:])
	default:
		return fmt.Errorf("unknown report subcommand %q", args[0])
	}
}

type betaEvidenceReport struct {
	EvidenceKind          string                               `json:"evidence_kind"`
	GeneratedAt           string                               `json:"generated_at"`
	ProductionReadiness   validation.ProductionReadinessReport `json:"production_readiness"`
	BenchmarkReport       validation.BenchmarkReport           `json:"benchmark_output"`
	BenchmarkSummary      validation.BenchmarkMetrics          `json:"benchmark_summary"`
	RolloutLimitations    []string                             `json:"rollout_limitations"`
	EcosystemDepth        map[string]string                    `json:"ecosystem_depth"`
	BehaviorModeSummary   string                               `json:"behavior_mode_summary"`
	OSVDBStatus           string                               `json:"osv_db_status"`
	ReleaseArtifactStatus map[string]string                    `json:"release_artifact_status"`
	SecurityGateStatus    map[string]string                    `json:"security_gate_status"`
	KnownLimitations      []string                             `json:"known_limitations"`
	Recommendation        string                               `json:"recommendation"`
}

type teamEvidenceReport struct {
	SchemaVersion             string                               `json:"schema_version"`
	EvidenceKind              string                               `json:"evidence_kind"`
	GeneratedAt               string                               `json:"generated_at"`
	Tool                      string                               `json:"tool"`
	PkgSafeVersion            string                               `json:"pkgsafe_version"`
	PkgSafeCommit             string                               `json:"pkgsafe_commit"`
	RepoListPath              string                               `json:"repo_list_path"`
	RepositoryCount           int                                  `json:"repository_count"`
	RepositoriesPassed        int                                  `json:"repositories_passed"`
	RepositoriesFailed        int                                  `json:"repositories_failed"`
	Summary                   teamEvidenceTotals                   `json:"summary"`
	Repositories              []teamEvidenceRepoSummary            `json:"repositories"`
	Policy                    teamEvidencePolicySummary            `json:"policy"`
	OSVDBStatus               string                               `json:"osv_db_status"`
	ReleaseVerificationStatus map[string]string                    `json:"release_verification_status"`
	ProductionReadiness       validation.ProductionReadinessReport `json:"production_readiness"`
	KnownLimitations          []string                             `json:"known_limitations"`
	Recommendation            string                               `json:"recommendation"`
}

type teamEvidenceTotals struct {
	DirectDependencies       int `json:"direct_dependencies"`
	TransitiveDependencies   int `json:"transitive_dependencies"`
	TotalDependencies        int `json:"total_dependencies"`
	AllowCount               int `json:"allow_count"`
	WarnCount                int `json:"warn_count"`
	BlockCount               int `json:"block_count"`
	FalseBlockCount          int `json:"false_block_count"`
	ScannerCrashCount        int `json:"scanner_crash_count"`
	JSONArtifacts            int `json:"json_artifacts"`
	SARIFArtifacts           int `json:"sarif_artifacts"`
	MarkdownSummaryArtifacts int `json:"markdown_summary_artifacts"`
	EvidencePackArtifacts    int `json:"evidence_pack_artifacts"`
}

type teamEvidenceRepoSummary struct {
	Name                   string           `json:"name"`
	Path                   string           `json:"path"`
	Ecosystems             []string         `json:"ecosystems"`
	DependencyCounts       dependencyCounts `json:"dependency_counts"`
	AllowCount             int              `json:"allow_count"`
	WarnCount              int              `json:"warn_count"`
	BlockCount             int              `json:"block_count"`
	FalseBlock             bool             `json:"false_block"`
	ScannerCrash           bool             `json:"scanner_crash"`
	EvidenceArtifactStatus artifactStatus   `json:"evidence_artifact_status"`
	PolicyVersion          string           `json:"policy_version"`
	ScanTimestamp          string           `json:"scan_timestamp"`
	PkgSafeVersion         string           `json:"pkgsafe_version"`
	Decision               string           `json:"decision,omitempty"`
	RiskScore              int              `json:"risk_score,omitempty"`
	Status                 string           `json:"status"`
	Passed                 bool             `json:"passed"`
	FailureClassifications []string         `json:"failure_classifications,omitempty"`
	Details                []string         `json:"details,omitempty"`
	FindingsBySeverity     map[string]int   `json:"findings_by_severity,omitempty"`
}

type dependencyCounts struct {
	Direct     int `json:"direct"`
	Transitive int `json:"transitive"`
	Total      int `json:"total"`
	Source     int `json:"source_imports"`
}

type artifactStatus struct {
	JSON            bool `json:"json"`
	SARIF           bool `json:"sarif"`
	MarkdownSummary bool `json:"markdown_summary"`
	EvidencePack    bool `json:"evidence_pack"`
}

type teamEvidencePolicySummary struct {
	Source      string `json:"source"`
	PackName    string `json:"pack_name"`
	PackVersion string `json:"pack_version"`
	Owner       string `json:"owner"`
}

func cmdReportBetaEvidence(args []string) error {
	return cmdReportEvidence(args, "private-beta")
}

func cmdReportTeamEvidence(args []string) error {
	fs := flag.NewFlagSet("team-evidence", flag.ContinueOnError)
	repoList := fs.String("repo-list", "", "JSON file listing repositories to aggregate")
	output := fs.String("output", "pkgsafe-team-evidence.zip", "output zip file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*repoList) == "" {
		return fmt.Errorf("--repo-list is required")
	}
	if err := validateTeamRepoList(*repoList); err != nil {
		return err
	}

	prod, err := validation.RunProductionReadinessWithOptions(validation.ProductionReadinessOptions{
		CorpusDir:    "testdata/corpus",
		GoldenFile:   "testdata/corpus-golden.json",
		BenchmarkDir: "testdata/benchmarks",
		RepoListPath: *repoList,
	})
	if err != nil {
		return err
	}
	bench, err := validation.RunBenchmarkPackWithOptions(validation.BenchmarkOptions{
		FixturesDir:    "testdata/benchmarks",
		DefinitionsDir: "benchmarks",
		RepoListPath:   *repoList,
		Offline:        true,
	})
	if err != nil {
		return err
	}
	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	evidence := buildTeamEvidenceReport(*repoList, prod, bench, pol)
	if err := writeTeamEvidenceZip(*output, evidence, bench, pol); err != nil {
		return err
	}
	fmt.Printf("PkgSafe team evidence generated: %s\n", *output)
	fmt.Printf("Repositories: %d passed / %d failed\n", evidence.RepositoriesPassed, evidence.RepositoriesFailed)
	fmt.Printf("Summary: allow=%d warn=%d block=%d false_blocks=%d scanner_crashes=%d\n",
		evidence.Summary.AllowCount,
		evidence.Summary.WarnCount,
		evidence.Summary.BlockCount,
		evidence.Summary.FalseBlockCount,
		evidence.Summary.ScannerCrashCount,
	)
	return nil
}

func validateTeamRepoList(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read repo list: %w", err)
	}
	var specs []validation.RealRepoSpec
	if err := json.Unmarshal(b, &specs); err != nil {
		return fmt.Errorf("parse repo list: %w", err)
	}
	if len(specs) == 0 {
		return fmt.Errorf("repo list %q is empty; add at least one repository", path)
	}
	return nil
}

func buildTeamEvidenceReport(repoList string, prod validation.ProductionReadinessReport, bench validation.BenchmarkReport, pol policy.Policy) teamEvidenceReport {
	generatedAt := bench.GeneratedAt
	if generatedAt == "" {
		generatedAt = prod.GeneratedAt
	}
	policySummary := teamEvidencePolicySummary{
		Source:      firstNonEmpty(pol.PolicyPackSource, "embedded default"),
		PackName:    firstNonEmpty(pol.PolicyPackName, "default-policy"),
		PackVersion: firstNonEmpty(pol.PolicyPackVersion, "1"),
		Owner:       firstNonEmpty(pol.PolicyPackOwner, "local"),
	}
	evidence := teamEvidenceReport{
		SchemaVersion:  "1.0",
		EvidenceKind:   "team-evidence",
		GeneratedAt:    generatedAt,
		Tool:           "pkgsafe",
		PkgSafeVersion: versionpkg.Version,
		PkgSafeCommit:  versionpkg.Commit,
		RepoListPath:   repoList,
		Policy:         policySummary,
		OSVDBStatus:    gateSummary(prod, "OSV cache"),
		ReleaseVerificationStatus: map[string]string{
			"signed_release":      prod.SignedReleaseStatus,
			"signing_verified":    fmt.Sprintf("%t", prod.SigningVerified),
			"checksums":           prod.ChecksumsStatus,
			"checksums_verified":  fmt.Sprintf("%t", prod.ChecksumsVerified),
			"sbom":                prod.SBOMStatus,
			"sbom_verified":       fmt.Sprintf("%t", prod.SBOMVerified),
			"provenance":          prod.ProvenanceStatus,
			"provenance_verified": fmt.Sprintf("%t", prod.ProvenanceVerified),
		},
		ProductionReadiness: prod,
		KnownLimitations: []string{
			"Team evidence is local-first and does not upload results to a hosted service.",
			"PkgSafe v1.0.0 remains npm-first GA; PyPI, Go, and Cargo are preview coverage and are not npm-equivalent.",
			"Heuristic behavior analysis is disabled by default and is non-isolated host execution when explicitly enabled.",
			"Missing repository paths are recorded as failed repo validations.",
		},
		Recommendation: prod.Recommendation,
	}
	for _, repo := range bench.RepoValidations {
		summary := teamEvidenceRepoSummary{
			Name:       repo.Name,
			Path:       repo.Path,
			Ecosystems: repo.Ecosystems,
			DependencyCounts: dependencyCounts{
				Direct:     repo.DirectDependencies,
				Transitive: repo.TransitiveDependencies,
				Total:      repo.TotalDependencies,
				Source:     repo.SourceImportCount,
			},
			AllowCount:   repo.AllowCount,
			WarnCount:    repo.WarnCount,
			BlockCount:   repo.BlockCount,
			FalseBlock:   repo.FalseBlock,
			ScannerCrash: repo.ScannerCrash,
			EvidenceArtifactStatus: artifactStatus{
				JSON:            repo.JSONOutputGenerated,
				SARIF:           repo.SARIFOutputGenerated,
				MarkdownSummary: repo.MarkdownSummaryGenerated,
				EvidencePack:    repo.EvidencePackGenerated,
			},
			PolicyVersion:          firstNonEmpty(policySummary.PackVersion, policySummary.PackName),
			ScanTimestamp:          generatedAt,
			PkgSafeVersion:         versionpkg.Version,
			Decision:               repo.Decision,
			RiskScore:              repo.Score,
			Status:                 repo.Status,
			Passed:                 repo.Passed,
			FailureClassifications: repo.FailureClassifications,
			Details:                repo.Details,
			FindingsBySeverity:     repo.FindingCountBySeverity,
		}
		evidence.Repositories = append(evidence.Repositories, summary)
		evidence.RepositoryCount++
		if repo.Passed {
			evidence.RepositoriesPassed++
		} else {
			evidence.RepositoriesFailed++
		}
		evidence.Summary.DirectDependencies += repo.DirectDependencies
		evidence.Summary.TransitiveDependencies += repo.TransitiveDependencies
		evidence.Summary.TotalDependencies += repo.TotalDependencies
		evidence.Summary.AllowCount += repo.AllowCount
		evidence.Summary.WarnCount += repo.WarnCount
		evidence.Summary.BlockCount += repo.BlockCount
		if repo.FalseBlock {
			evidence.Summary.FalseBlockCount++
		}
		if repo.ScannerCrash {
			evidence.Summary.ScannerCrashCount++
		}
		if repo.JSONOutputGenerated {
			evidence.Summary.JSONArtifacts++
		}
		if repo.SARIFOutputGenerated {
			evidence.Summary.SARIFArtifacts++
		}
		if repo.MarkdownSummaryGenerated {
			evidence.Summary.MarkdownSummaryArtifacts++
		}
		if repo.EvidencePackGenerated {
			evidence.Summary.EvidencePackArtifacts++
		}
	}
	return evidence
}

func writeTeamEvidenceZip(outputPath string, evidence teamEvidenceReport, bench validation.BenchmarkReport, pol policy.Policy) error {
	files := map[string][]byte{}
	summaryJSON, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	files["summary/team-evidence-summary.json"] = summaryJSON
	files["summary/team-evidence-summary.md"] = []byte(renderTeamEvidenceMarkdown(evidence))

	benchJSON, err := json.MarshalIndent(bench, "", "  ")
	if err != nil {
		return err
	}
	files["raw/benchmark-output.json"] = benchJSON
	prodJSON, err := json.MarshalIndent(evidence.ProductionReadiness, "", "  ")
	if err != nil {
		return err
	}
	files["raw/production-readiness-output.json"] = prodJSON
	policyJSON, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	files["policy/policy-summary.json"] = []byte(renderTeamPolicyJSON(evidence.Policy))
	files["policy/policy-used.json"] = policyJSON
	files["status/osv-db-status.md"] = []byte(renderTeamOSVStatus(evidence))
	files["status/release-verification-status.md"] = []byte(renderTeamReleaseStatus(evidence))
	files["known-limitations.md"] = []byte(renderTeamKnownLimitations(evidence))
	for _, repo := range evidence.Repositories {
		repoJSON, err := json.MarshalIndent(repo, "", "  ")
		if err != nil {
			return err
		}
		name := safeEvidenceName(firstNonEmpty(repo.Name, filepath.Base(repo.Path), "repo"))
		files[filepath.Join("per-repo", name, "summary.json")] = repoJSON
		files[filepath.Join("per-repo", name, "summary.md")] = []byte(renderTeamRepoMarkdown(repo))
	}
	for path, content := range files {
		files[path] = []byte(registry.RedactSecrets(string(content)))
	}
	return writeDeterministicEvidenceZip(outputPath, "pkgsafe-team-evidence", files)
}

func writeDeterministicEvidenceZip(outputPath, prefix string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	var paths []string
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	manifest := report.Manifest{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		GeneratedAt:   "1970-01-01T00:00:00Z",
		Repository:    "team-evidence",
	}
	for _, path := range paths {
		content := files[path]
		manifest.Files = append(manifest.Files, report.ManifestFile{
			Path:   prefix + "/" + filepath.ToSlash(path),
			SHA256: sha256Hex(content),
		})
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeDeterministicZipFile(zw, prefix+"/manifest.json", manifestJSON); err != nil {
		return err
	}
	for _, path := range paths {
		if err := writeDeterministicZipFile(zw, prefix+"/"+filepath.ToSlash(path), files[path]); err != nil {
			return err
		}
	}
	return nil
}

func cmdReportEvidence(args []string, kind string) error {
	commandName := "beta-evidence"
	defaultOutput := "beta-evidence.md"
	if kind == "ga" {
		commandName = "ga-evidence"
		defaultOutput = "pkgsafe-ga-evidence.zip"
	}
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	output := fs.String("output", defaultOutput, "Markdown or .zip output path")
	jsonOutput := fs.String("json-output", "", "optional JSON output path")
	repo := fs.String("repo", "", "optional real repository path to validate")
	repoList := fs.String("repo-list", "", "optional real repository list JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	prodOpts := validation.ProductionReadinessOptions{
		CorpusDir:    "testdata/corpus",
		GoldenFile:   "testdata/corpus-golden.json",
		BenchmarkDir: "testdata/benchmarks",
		RepoListPath: *repoList,
	}
	if *repo != "" {
		prodOpts.RealRepos = []string{*repo}
	}
	prod, err := validation.RunProductionReadinessWithOptions(prodOpts)
	if err != nil {
		return err
	}
	bench, err := validation.RunBenchmarkPackWithOptions(validation.BenchmarkOptions{
		FixturesDir:    "testdata/benchmarks",
		DefinitionsDir: "benchmarks",
		RepoPath:       *repo,
		RepoListPath:   *repoList,
		Offline:        true,
	})
	if err != nil {
		return err
	}
	evidence := betaEvidenceReport{
		EvidenceKind:        kind,
		GeneratedAt:         prod.GeneratedAt,
		ProductionReadiness: prod,
		BenchmarkReport:     bench,
		BenchmarkSummary:    bench.Metrics,
		RolloutLimitations: []string{
			"PkgSafe GA v1 is scoped as npm-first supply-chain scanning.",
			"PyPI, Go, and Cargo are preview coverage and are not npm-equivalent yet.",
			"heuristic behavior mode executes on the host and is not sandboxing.",
			"isolated behavior mode is experimental, Linux-only, and unavailable unless bubblewrap isolation is available.",
			"GA remains blocked until real repository validation and release-integrity verification thresholds are met.",
		},
		EcosystemDepth: map[string]string{
			"npm":   "production-ready GA v1 scope after GA evidence gates pass",
			"pypi":  "preview coverage; not npm-equivalent",
			"go":    "preview metadata and OSV-oriented coverage; not npm-equivalent",
			"cargo": "preview metadata and OSV-oriented coverage; not npm-equivalent",
		},
		BehaviorModeSummary: "Private beta defaults behavior analysis to disabled. Heuristic mode is host execution; isolated mode is experimental, Linux-only, and unavailable unless bubblewrap isolation is available.",
		OSVDBStatus:         gateSummary(prod, "OSV cache"),
		ReleaseArtifactStatus: map[string]string{
			"signed_release":      prod.SignedReleaseStatus,
			"signing_verified":    fmt.Sprintf("%t", prod.SigningVerified),
			"checksums":           prod.ChecksumsStatus,
			"checksums_verified":  fmt.Sprintf("%t", prod.ChecksumsVerified),
			"sbom":                prod.SBOMStatus,
			"sbom_verified":       fmt.Sprintf("%t", prod.SBOMVerified),
			"provenance":          prod.ProvenanceStatus,
			"provenance_verified": fmt.Sprintf("%t", prod.ProvenanceVerified),
		},
		SecurityGateStatus: map[string]string{
			"rollout_readiness": gateSummary(prod, "rollout readiness"),
			"policy_validation": gateSummary(prod, "policy validation"),
			"ci_outputs":        gateSummary(prod, "CI outputs"),
		},
		KnownLimitations: []string{
			"Real repo validation count may be below GA threshold.",
			"Isolated behavior backend is experimental, Linux-only, and requires bubblewrap.",
			"PyPI/Go/Cargo remain preview until depth parity is implemented and validated.",
		},
		Recommendation: prod.Recommendation,
	}
	if *jsonOutput != "" {
		b, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOutput, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if strings.HasSuffix(strings.ToLower(*output), ".zip") {
		return writeBetaEvidenceZip(*output, evidence)
	}
	return os.WriteFile(*output, []byte(renderBetaEvidenceMarkdown(evidence)), 0o644)
}

func writeBetaEvidenceZip(outputPath string, evidence betaEvidenceReport) error {
	files := map[string][]byte{}
	summaryJSON, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	files["repo-validation-summary.json"] = summaryJSON
	files["repo-validation-summary.md"] = []byte(renderBetaEvidenceMarkdown(evidence))
	benchJSON, err := json.MarshalIndent(evidence.BenchmarkReport, "", "  ")
	if err != nil {
		return err
	}
	files["benchmark-output.json"] = benchJSON
	prodJSON, err := json.MarshalIndent(evidence.ProductionReadiness, "", "  ")
	if err != nil {
		return err
	}
	files["production-readiness-output.json"] = prodJSON
	versionInfo, err := json.MarshalIndent(map[string]string{
		"tool":         "pkgsafe",
		"version":      versionpkg.Version,
		"commit":       versionpkg.Commit,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	files["version-info.json"] = versionInfo
	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err == nil {
		policyJSON, marshalErr := json.MarshalIndent(pol, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		files["policy-used.json"] = policyJSON
	} else {
		files["policy-used.json"] = []byte(fmt.Sprintf(`{"error":%q}`+"\n", err.Error()))
	}
	files["known-limitations.md"] = []byte(renderKnownLimitations(evidence))
	for _, repo := range evidence.BenchmarkReport.RepoValidations {
		repoJSON, err := json.MarshalIndent(repo, "", "  ")
		if err != nil {
			return err
		}
		name := strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(firstNonEmpty(repo.Name, filepath.Base(repo.Path)))
		files[filepath.Join("per-repo", name+".json")] = repoJSON
	}
	for path, content := range files {
		files[path] = []byte(registry.RedactSecrets(string(content)))
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	prefix := "pkgsafe-private-beta-evidence"
	if evidence.EvidenceKind == "ga" {
		prefix = "pkgsafe-ga-evidence"
	}
	manifest := report.Manifest{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repository:    "private-beta-validation",
		PolicyPack:    "",
	}
	for path, content := range files {
		manifest.Files = append(manifest.Files, report.ManifestFile{
			Path:   prefix + "/" + path,
			SHA256: sha256Hex(content),
		})
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeZipFile(zw, prefix+"/manifest.json", manifestJSON); err != nil {
		return err
	}
	for path, content := range files {
		if err := writeZipFile(zw, prefix+"/"+path, content); err != nil {
			return err
		}
	}
	return nil
}

func renderKnownLimitations(e betaEvidenceReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Known Limitations")
	fmt.Fprintln(&b)
	for _, limitation := range e.KnownLimitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Rollout Limitations")
	for _, limitation := range e.RolloutLimitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

func writeZipFile(zw *zip.Writer, path string, content []byte) error {
	w, err := zw.Create(path)
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}

func writeDeterministicZipFile(zw *zip.Writer, path string, content []byte) error {
	header := &zip.FileHeader{
		Name:   filepath.ToSlash(path),
		Method: zip.Deflate,
	}
	header.SetMode(0o644)
	header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func gateSummary(rep validation.ProductionReadinessReport, name string) string {
	for _, gate := range rep.Gates {
		if gate.Name == name {
			if gate.Passed {
				return "pass: " + gate.Summary
			}
			return "fail: " + gate.Summary
		}
	}
	return "not_run"
}

func renderBetaEvidenceMarkdown(e betaEvidenceReport) string {
	var b strings.Builder
	title := "PkgSafe Private Beta Evidence"
	if e.EvidenceKind == "ga" {
		title = "PkgSafe GA Candidate Evidence"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Generated: %s\n\n", e.GeneratedAt)
	fmt.Fprintf(&b, "## Readiness\n\n")
	fmt.Fprintf(&b, "- Current stage: %s\n", e.ProductionReadiness.CurrentStage)
	fmt.Fprintf(&b, "- Private beta ready: %t\n", e.ProductionReadiness.PrivateBetaReady)
	fmt.Fprintf(&b, "- GA ready: %t\n", e.ProductionReadiness.GAReady)
	fmt.Fprintf(&b, "- Real repo validations: %d / %d\n", e.ProductionReadiness.RealRepoValidationCount, e.ProductionReadiness.RequiredRealRepoValidationCount)
	for _, blocker := range e.ProductionReadiness.GABlockers {
		fmt.Fprintf(&b, "- GA blocker: %s\n", blocker)
	}
	fmt.Fprintf(&b, "\n## Benchmark Summary\n\n")
	fmt.Fprintf(&b, "- Repos passed / failed: %d / %d\n", e.BenchmarkSummary.ReposPassed, e.BenchmarkSummary.ReposFailed)
	fmt.Fprintf(&b, "- npm / PyPI / Go / Cargo repos: %d / %d / %d / %d\n", e.BenchmarkSummary.NPMRepoCount, e.BenchmarkSummary.PyPIRepoCount, e.BenchmarkSummary.GoRepoCount, e.BenchmarkSummary.CargoRepoCount)
	fmt.Fprintf(&b, "- Average / p95 scan duration: %dms / %dms\n", e.BenchmarkSummary.RealRepoAverageScanDurationMs, e.BenchmarkSummary.RealRepoP95ScanDurationMs)
	fmt.Fprintf(&b, "\n## Ecosystem Depth\n\n")
	for _, eco := range []string{"npm", "pypi", "go", "cargo"} {
		fmt.Fprintf(&b, "- %s: %s\n", eco, e.EcosystemDepth[eco])
	}
	fmt.Fprintf(&b, "\n## Behavior Analysis\n\n%s\n\n", e.BehaviorModeSummary)
	fmt.Fprintf(&b, "## Security Gates\n\n")
	for name, status := range e.SecurityGateStatus {
		fmt.Fprintf(&b, "- %s: %s\n", name, status)
	}
	fmt.Fprintf(&b, "- OSV DB: %s\n", e.OSVDBStatus)
	fmt.Fprintf(&b, "\n## Release Artifacts\n\n")
	for name, status := range e.ReleaseArtifactStatus {
		fmt.Fprintf(&b, "- %s: %s\n", name, status)
	}
	fmt.Fprintf(&b, "\n## Known Limitations\n\n")
	for _, limitation := range e.KnownLimitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	fmt.Fprintf(&b, "\n## Recommendation\n\n%s\n", e.Recommendation)
	return b.String()
}

func renderTeamEvidenceMarkdown(e teamEvidenceReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# PkgSafe Team Evidence")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Generated: %s\n\n", e.GeneratedAt)
	fmt.Fprintf(&b, "- Repositories: %d\n", e.RepositoryCount)
	fmt.Fprintf(&b, "- Passed / failed: %d / %d\n", e.RepositoriesPassed, e.RepositoriesFailed)
	fmt.Fprintf(&b, "- Direct / transitive dependencies: %d / %d\n", e.Summary.DirectDependencies, e.Summary.TransitiveDependencies)
	fmt.Fprintf(&b, "- Allow / warn / block: %d / %d / %d\n", e.Summary.AllowCount, e.Summary.WarnCount, e.Summary.BlockCount)
	fmt.Fprintf(&b, "- False blocks: %d\n", e.Summary.FalseBlockCount)
	fmt.Fprintf(&b, "- Scanner crashes: %d\n", e.Summary.ScannerCrashCount)
	fmt.Fprintf(&b, "- PkgSafe version: %s (%s)\n", e.PkgSafeVersion, e.PkgSafeCommit)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Policy")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Source: %s\n", e.Policy.Source)
	fmt.Fprintf(&b, "- Pack: %s@%s\n", e.Policy.PackName, e.Policy.PackVersion)
	fmt.Fprintf(&b, "- Owner: %s\n", e.Policy.Owner)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Repository Summary")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Repository | Ecosystems | Dependencies | Allow | Warn | Block | False block | Scanner crash | Status |")
	fmt.Fprintln(&b, "|---|---:|---:|---:|---:|---:|---:|---:|---|")
	for _, repo := range e.Repositories {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %t | %t | %s |\n",
			repo.Name,
			strings.Join(repo.Ecosystems, ", "),
			repo.DependencyCounts.Total,
			repo.AllowCount,
			repo.WarnCount,
			repo.BlockCount,
			repo.FalseBlock,
			repo.ScannerCrash,
			repo.Status,
		)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## OSV DB Status")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%s\n\n", e.OSVDBStatus)
	fmt.Fprintln(&b, "## Release Verification")
	fmt.Fprintln(&b)
	for _, key := range sortedMapKeys(e.ReleaseVerificationStatus) {
		fmt.Fprintf(&b, "- %s: %s\n", key, e.ReleaseVerificationStatus[key])
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Known Limitations")
	fmt.Fprintln(&b)
	for _, limitation := range e.KnownLimitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

func renderTeamRepoMarkdown(repo teamEvidenceRepoSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", repo.Name)
	fmt.Fprintf(&b, "- Path: %s\n", repo.Path)
	fmt.Fprintf(&b, "- Ecosystems: %s\n", strings.Join(repo.Ecosystems, ", "))
	fmt.Fprintf(&b, "- Dependencies: %d direct, %d transitive, %d total\n", repo.DependencyCounts.Direct, repo.DependencyCounts.Transitive, repo.DependencyCounts.Total)
	fmt.Fprintf(&b, "- Allow / warn / block: %d / %d / %d\n", repo.AllowCount, repo.WarnCount, repo.BlockCount)
	fmt.Fprintf(&b, "- False block: %t\n", repo.FalseBlock)
	fmt.Fprintf(&b, "- Scanner crash: %t\n", repo.ScannerCrash)
	fmt.Fprintf(&b, "- JSON / SARIF / Markdown / Evidence pack: %t / %t / %t / %t\n", repo.EvidenceArtifactStatus.JSON, repo.EvidenceArtifactStatus.SARIF, repo.EvidenceArtifactStatus.MarkdownSummary, repo.EvidenceArtifactStatus.EvidencePack)
	fmt.Fprintf(&b, "- Policy version: %s\n", repo.PolicyVersion)
	fmt.Fprintf(&b, "- Scan timestamp: %s\n", repo.ScanTimestamp)
	fmt.Fprintf(&b, "- PkgSafe version: %s\n", repo.PkgSafeVersion)
	fmt.Fprintf(&b, "- Status: %s\n", repo.Status)
	if len(repo.Details) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "## Details")
		for _, detail := range repo.Details {
			fmt.Fprintf(&b, "- %s\n", detail)
		}
	}
	return b.String()
}

func renderTeamPolicyJSON(summary teamEvidencePolicySummary) string {
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "{}\n"
	}
	return string(append(b, '\n'))
}

func renderTeamOSVStatus(e teamEvidenceReport) string {
	return fmt.Sprintf("# OSV DB Status\n\n%s\n", e.OSVDBStatus)
}

func renderTeamReleaseStatus(e teamEvidenceReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Release Verification Status")
	fmt.Fprintln(&b)
	for _, key := range sortedMapKeys(e.ReleaseVerificationStatus) {
		fmt.Fprintf(&b, "- %s: %s\n", key, e.ReleaseVerificationStatus[key])
	}
	return b.String()
}

func renderTeamKnownLimitations(e teamEvidenceReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Known Limitations")
	fmt.Fprintln(&b)
	for _, limitation := range e.KnownLimitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func safeEvidenceName(name string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-", "@", "-")
	name = strings.Trim(replacer.Replace(name), ".-")
	if name == "" {
		return "repo"
	}
	return name
}

func cmdReportGenerate(args []string) error {
	fs := flag.NewFlagSet("report-generate", flag.ContinueOnError)
	repo := fs.String("repo", ".", "repository root directory")
	output := fs.String("output", "pkgsafe-report", "output file path")
	format := fs.String("format", "markdown", "output format: json, markdown, html, csv, all")
	repType := fs.String("type", "repository-risk-report", "report type: registry, dependency-confusion, ai-agent, repository-risk-report")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(*repo, pol, true)
	if err != nil {
		return err
	}

	if *repType == "registry" {
		content := report.ExportRegistryEvidence(r)
		outPath := *output
		if !strings.HasSuffix(outPath, ".md") {
			outPath += ".md"
		}
		return os.WriteFile(outPath, []byte(content), 0644)
	} else if *repType == "dependency-confusion" {
		content := report.ExportDependencyConfusionReport(r)
		outPath := *output
		if !strings.HasSuffix(outPath, ".md") {
			outPath += ".md"
		}
		return os.WriteFile(outPath, []byte(content), 0644)
	} else if *repType == "ai-agent" {
		content := report.ExportAIAgentActivityReport(r)
		outPath := *output
		if !strings.HasSuffix(outPath, ".md") {
			outPath += ".md"
		}
		return os.WriteFile(outPath, []byte(content), 0644)
	}

	var filesWritten []string

	writeFormat := func(fmtType string) error {
		switch fmtType {
		case "markdown":
			content, _ := report.ExportMarkdown(r)
			outPath := *output
			if !strings.HasSuffix(outPath, ".md") {
				outPath += ".md"
			}
			filesWritten = append(filesWritten, filepath.Base(outPath))
			return os.WriteFile(outPath, []byte(content), 0644)
		case "json":
			content, _ := report.ExportJSON(r)
			outPath := *output
			if !strings.HasSuffix(outPath, ".json") {
				outPath += ".json"
			}
			filesWritten = append(filesWritten, filepath.Base(outPath))
			return os.WriteFile(outPath, []byte(content), 0644)
		case "html":
			content, _ := report.ExportHTML(r)
			outPath := *output
			if !strings.HasSuffix(outPath, ".html") {
				outPath += ".html"
			}
			filesWritten = append(filesWritten, filepath.Base(outPath))
			return os.WriteFile(outPath, []byte(content), 0644)
		case "csv":
			dir := filepath.Dir(*output)
			for _, csvName := range []string{"findings", "exceptions", "overrides", "packages"} {
				csvContent, _ := report.ExportCSV(r, csvName)
				fileName := csvName + ".csv"
				outPath := filepath.Join(dir, fileName)
				filesWritten = append(filesWritten, fileName)
				if err := os.WriteFile(outPath, []byte(csvContent), 0644); err != nil {
					return err
				}
			}
			return nil
		}
		return nil
	}

	if *format == "all" {
		for _, f := range []string{"markdown", "json", "html", "csv"} {
			if err := writeFormat(f); err != nil {
				return err
			}
		}
	} else {
		if err := writeFormat(*format); err != nil {
			return err
		}
	}

	fmt.Println("PkgSafe Report Generated")
	fmt.Println()
	fmt.Printf("Report Type: repository-risk-report\n")
	fmt.Printf("Repository: %s\n", r.Repository.Name)
	fmt.Printf("Policy Pack: %s@%s\n", r.Policy.PackName, r.Policy.PackVersion)
	overall := "ALLOW"
	if r.Summary.Blocked > 0 {
		overall = "BLOCK"
	} else if r.Summary.Warnings > 0 {
		overall = "WARN"
	}
	fmt.Printf("Overall Decision: %s\n", overall)
	fmt.Println()
	fmt.Println("Files:")
	for _, f := range filesWritten {
		fmt.Printf("- %s\n", f)
	}
	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("- Packages scanned: %d\n", r.Summary.PackagesScanned)
	fmt.Printf("- Allowed: %d\n", r.Summary.Allowed)
	fmt.Printf("- Warned: %d\n", r.Summary.Warnings)
	fmt.Printf("- Blocked: %d\n", r.Summary.Blocked)
	fmt.Printf("- Exceptions used: %d\n", r.Summary.ActiveExceptions)
	fmt.Printf("- Overrides used: %d\n", r.Summary.DeveloperOverrides)

	return nil
}

func cmdReportEvidencePack(args []string) error {
	fs := flag.NewFlagSet("evidence-pack", flag.ContinueOnError)
	repo := fs.String("repo", ".", "repository root directory")
	output := fs.String("output", "pkgsafe-evidence-pack.zip", "output zip file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(*repo, pol, true)
	if err != nil {
		return err
	}

	return report.CreateEvidencePack(*output, r, pol)
}

func cmdReportExceptions(args []string) error {
	fs := flag.NewFlagSet("exceptions", flag.ContinueOnError)
	output := fs.String("output", "exceptions.md", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(".", pol, true)
	if err != nil {
		return err
	}

	content := report.ExportExceptionsReport(r)
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportOverrides(args []string) error {
	fs := flag.NewFlagSet("overrides", flag.ContinueOnError)
	output := fs.String("output", "overrides.csv", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(".", pol, true)
	if err != nil {
		return err
	}

	content, err := report.ExportCSV(r, "overrides")
	if err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportPolicy(args []string) error {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	policyPack := fs.String("policy-pack", "enterprise-standard", "policy pack name")
	output := fs.String("output", "policy-evidence.md", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy(*policyPack, "", "", "", "")
	if err != nil {
		return err
	}

	content := report.ExportPolicyEvidence(pol)
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	input := fs.String("input", "pkgsafe-results.json", "CI results JSON input path")
	output := fs.String("output", "ci-evidence.md", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	content, err := report.ExportCIGateReport(*input)
	if err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportSIEM(args []string) error {
	fs := flag.NewFlagSet("siem-export", flag.ContinueOnError)
	output := fs.String("output", "pkgsafe-events.jsonl", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(".", pol, true)
	if err != nil {
		return err
	}

	content, err := report.ExportSIEM(r)
	if err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportServiceNow(args []string) error {
	fs := flag.NewFlagSet("servicenow-export", flag.ContinueOnError)
	output := fs.String("output", "servicenow-evidence.json", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(".", pol, true)
	if err != nil {
		return err
	}

	content, err := report.ExportServiceNow(r)
	if err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(content), 0644)
}

func cmdReportAzureDevOps(args []string) error {
	fs := flag.NewFlagSet("azure-devops-export", flag.ContinueOnError)
	output := fs.String("output", "azure-devops-evidence.md", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := policy.ResolvePolicy("", "", "", "", "")
	if err != nil {
		return err
	}

	r, err := report.GenerateReport(".", pol, true)
	if err != nil {
		return err
	}

	content, err := report.ExportAzureDevOps(r)
	if err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(content), 0644)
}
