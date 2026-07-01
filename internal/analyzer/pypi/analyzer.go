package pypi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Metadata struct {
	Name        string
	Version     string
	Summary     string
	Description string
	Repository  string
	License     string
	Yanked      bool
	Wheel       bool
	Source      bool
}

type Analysis struct {
	Result   types.ScanResult
	Findings []types.Reason
	Artifact types.ArtifactSummary
}

func AnalyzeDir(dir string, md Metadata, pol policy.Policy) (Analysis, error) {
	pkg := types.PackageIdentity{Ecosystem: "pypi", Name: md.Name, Version: md.Version}
	artifact := types.ArtifactSummary{
		WheelAvailable:              md.Wheel,
		SourceDistributionAvailable: md.Source,
		Yanked:                      md.Yanked,
	}
	var findings []types.Reason
	var suspicious []string

	if md.Source && !md.Wheel {
		findings = risk.AddReason(findings, "pypi_source_distribution_only", "Package version only provides a source distribution", "")
	}
	if md.Yanked {
		findings = risk.AddReason(findings, "pypi_yanked_release", "Selected PyPI release is yanked", "")
	}
	if strings.TrimSpace(md.Repository) == "" {
		findings = risk.AddReason(findings, "missing_repository", "Package metadata does not include a source repository", "")
	}
	if strings.TrimSpace(md.License) == "" {
		findings = risk.AddReason(findings, "missing_license", "Package metadata does not include a license", "")
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		slashRel := filepath.ToSlash(rel)
		base := filepath.Base(path)
		inspect := base == "setup.py" ||
			base == "setup.cfg" ||
			base == "pyproject.toml" ||
			base == "MANIFEST.in" ||
			strings.HasSuffix(base, ".py") ||
			strings.HasPrefix(slashRel, "scripts/") ||
			strings.HasPrefix(slashRel, "bin/")
		if nativeExtensionName(slashRel) {
			artifact.NativeExtension = true
			findings = risk.AddReason(findings, "pypi_native_extension", "Package artifact contains native extension or native source files", slashRel)
			suspicious = append(suspicious, "native extension: "+slashRel)
		}
		if !inspect {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(b)
		lower := strings.ToLower(text)
		if base == "setup.py" {
			artifact.SetupPyPresent = true
			findings = risk.AddReason(findings, "pypi_setup_py_present", "Source distribution contains setup.py", slashRel)
			setupFindings, setupSuspicious := AnalyzeSetupPy(slashRel, lower)
			findings = append(findings, setupFindings...)
			suspicious = append(suspicious, setupSuspicious...)
		}
		if base == "pyproject.toml" {
			backend := BuildBackend(text)
			if backend != "" {
				artifact.BuildBackend = backend
				if UnknownBuildBackend(backend) {
					findings = risk.AddReason(findings, "pypi_unknown_build_backend", "pyproject.toml uses an unusual or unknown build backend", backend)
				}
			}
		}
		if strings.HasSuffix(base, ".py") {
			staticFindings, staticSuspicious := AnalyzePythonStaticPatterns(slashRel, lower)
			findings = append(findings, staticFindings...)
			suspicious = append(suspicious, staticSuspicious...)
		}
		for _, pat := range RiskyPatterns() {
			if strings.Contains(lower, strings.ToLower(pat)) {
				suspicious = append(suspicious, pat)
			}
		}
		if looksEncodedPayload(lower) {
			suspicious = append(suspicious, "encoded payload")
		}
		if suspiciousBinaryName(base) {
			suspicious = append(suspicious, "suspicious binary name: "+base)
		}
		return nil
	})
	if err != nil {
		return Analysis{}, fmt.Errorf("analyze pypi artifact: %w", err)
	}

	res := risk.Evaluate(pkg, dedupeReasons(findings), nil, unique(suspicious), nil, pol)
	res.Artifact = artifact
	return Analysis{Result: res, Findings: dedupeReasons(findings), Artifact: artifact}, nil
}

func dedupeReasons(in []types.Reason) []types.Reason {
	seen := map[string]bool{}
	var out []types.Reason
	for _, r := range in {
		key := r.ID + ":" + r.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
