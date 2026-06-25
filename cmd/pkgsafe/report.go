package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/report"
)

func cmdReport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe report [generate|evidence-pack|exceptions|overrides|policy|ci|siem-export|servicenow-export|azure-devops-export]")
	}

	switch args[0] {
	case "generate":
		return cmdReportGenerate(args[1:])
	case "evidence-pack":
		return cmdReportEvidencePack(args[1:])
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
