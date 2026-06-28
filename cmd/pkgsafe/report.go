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
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	"github.com/niyam-ai/pkgsafe/internal/report"
	"github.com/niyam-ai/pkgsafe/internal/validation"
	versionpkg "github.com/niyam-ai/pkgsafe/internal/version"
)

func cmdReport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe report [generate|evidence-pack|beta-evidence|exceptions|overrides|policy|ci|siem-export|servicenow-export|azure-devops-export]")
	}

	switch args[0] {
	case "generate":
		return cmdReportGenerate(args[1:])
	case "evidence-pack":
		return cmdReportEvidencePack(args[1:])
	case "beta-evidence":
		return cmdReportBetaEvidence(args[1:])
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

func cmdReportBetaEvidence(args []string) error {
	fs := flag.NewFlagSet("beta-evidence", flag.ContinueOnError)
	output := fs.String("output", "beta-evidence.md", "Markdown or .zip output path")
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
		GeneratedAt:         prod.GeneratedAt,
		ProductionReadiness: prod,
		BenchmarkReport:     bench,
		BenchmarkSummary:    bench.Metrics,
		RolloutLimitations: []string{
			"npm has the strongest artifact and lifecycle-script coverage.",
			"PyPI, Go, and Cargo are not npm-equivalent yet.",
			"heuristic behavior mode executes on the host and is not sandboxing.",
			"isolated behavior mode is unavailable until a real backend lands.",
			"GA remains blocked until real repository validation and ecosystem-depth thresholds are met.",
		},
		EcosystemDepth: map[string]string{
			"npm":   "strongest private-beta coverage",
			"pypi":  "early coverage; not npm-equivalent",
			"go":    "metadata and OSV-oriented; not npm-equivalent",
			"cargo": "metadata and OSV-oriented; not npm-equivalent",
		},
		BehaviorModeSummary: "Private beta defaults behavior analysis to disabled. Heuristic mode is host execution; isolated mode reports unavailable until a real isolation backend exists.",
		OSVDBStatus:         gateSummary(prod, "OSV cache"),
		ReleaseArtifactStatus: map[string]string{
			"signed_release": prod.SignedReleaseStatus,
			"sbom":           prod.SBOMStatus,
			"provenance":     prod.ProvenanceStatus,
		},
		SecurityGateStatus: map[string]string{
			"rollout_readiness": gateSummary(prod, "rollout readiness"),
			"policy_validation": gateSummary(prod, "policy validation"),
			"ci_outputs":        gateSummary(prod, "CI outputs"),
		},
		KnownLimitations: []string{
			"Real repo validation count may be below GA threshold.",
			"Isolated behavior backend is not implemented.",
			"PyPI/Go/Cargo depth is not npm-equivalent.",
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
	manifest := report.Manifest{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repository:    "private-beta-validation",
		PolicyPack:    "",
	}
	for path, content := range files {
		manifest.Files = append(manifest.Files, report.ManifestFile{
			Path:   "pkgsafe-private-beta-evidence/" + path,
			SHA256: sha256Hex(content),
		})
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeZipFile(zw, "pkgsafe-private-beta-evidence/manifest.json", manifestJSON); err != nil {
		return err
	}
	for path, content := range files {
		if err := writeZipFile(zw, "pkgsafe-private-beta-evidence/"+path, content); err != nil {
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
	fmt.Fprintf(&b, "# PkgSafe Private Beta Evidence\n\n")
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
