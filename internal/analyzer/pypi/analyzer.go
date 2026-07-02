package pypi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
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
	pyFiles := map[string]bool{}
	var pycFiles []string
	var allFiles []string
	recordContents := map[string]string{}
	distInfoSeen := false

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
		allFiles = append(allFiles, slashRel)
		lowerRel := strings.ToLower(slashRel)
		if strings.HasSuffix(lowerRel, ".py") {
			pyFiles[slashRel] = true
		}
		if strings.HasSuffix(lowerRel, ".pyc") || strings.HasSuffix(lowerRel, ".pyo") {
			pycFiles = append(pycFiles, slashRel)
		}
		if strings.Contains(slashRel, ".dist-info/") {
			distInfoSeen = true
			if base == "RECORD" {
				if b, err := os.ReadFile(path); err == nil {
					recordContents[slashRel] = string(b)
				}
			}
		}
		inspect := base == "setup.py" ||
			base == "setup.cfg" ||
			base == "pyproject.toml" ||
			base == "MANIFEST.in" ||
			strings.HasSuffix(base, ".py") ||
			strings.HasPrefix(slashRel, "scripts/") ||
			strings.HasPrefix(slashRel, "bin/") ||
			wheelDataScript(slashRel)
		if nativeExtensionName(slashRel) {
			artifact.NativeExtension = true
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
		if base == "setup.py" && installRootManifest(slashRel) {
			artifact.SetupPyPresent = true
			findings = risk.AddReason(findings, "pypi_setup_py_present", "Source distribution contains setup.py", slashRel)
			setupFindings, setupSuspicious := AnalyzeSetupPy(slashRel, lower)
			findings = append(findings, setupFindings...)
			suspicious = append(suspicious, setupSuspicious...)
		}
		if base == "pyproject.toml" && installRootManifest(slashRel) {
			bs := ParseBuildSystem(text)
			if bs.Backend != "" {
				artifact.BuildBackend = bs.Backend
				if UnknownBuildBackend(bs.Backend) {
					findings = risk.AddReason(findings, "pypi_unknown_build_backend", "pyproject.toml uses an unusual or unknown build backend", bs.Backend)
				}
			}
			if len(bs.BackendPath) > 0 {
				artifact.BuildBackendPath = strings.Join(bs.BackendPath, ", ")
				findings = risk.AddReason(findings, "pypi_in_tree_build_backend", "pyproject.toml loads the build backend from code inside the package (backend-path)", slashRel+": "+artifact.BuildBackendPath)
				suspicious = append(suspicious, "in-tree build backend")
			}
			for _, req := range bs.Requires {
				if DirectBuildRequirement(req) {
					findings = risk.AddReason(findings, "pypi_build_requires_direct_reference", "pyproject.toml build requirements pull code from a direct URL or VCS reference", slashRel+": "+req)
					suspicious = append(suspicious, "direct-URL build requirement")
				}
			}
		}
		if shouldAnalyzePythonExecutionSurface(slashRel, base) {
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
	if artifact.NativeExtension {
		findings = risk.AddReason(findings, "pypi_native_extension", "Package artifact contains native extension or native source files", "")
		suspicious = append(suspicious, "native extension")
	}
	if orphans := orphanedBytecode(pycFiles, pyFiles); len(orphans) > 0 {
		artifact.OrphanedBytecode = true
		findings = risk.AddReason(findings, "pypi_compiled_bytecode_payload", "Package artifact ships compiled Python bytecode without matching source files", strings.Join(capList(orphans, 5), ", "))
		suspicious = append(suspicious, "orphaned compiled bytecode")
	}
	if md.Wheel {
		if len(recordContents) == 0 {
			evidence := "no .dist-info RECORD found"
			if distInfoSeen {
				evidence = ".dist-info present but RECORD unreadable or absent"
			}
			findings = risk.AddReason(findings, "pypi_wheel_record_missing", "Wheel artifact is missing its .dist-info RECORD manifest", evidence)
		}
		if unlisted := filesNotInRecord(recordContents, allFiles); len(unlisted) > 0 {
			findings = risk.AddReason(findings, "pypi_wheel_record_unlisted_files", "Wheel artifact contains files not declared in its RECORD manifest", strings.Join(capList(unlisted, 5), ", "))
			suspicious = append(suspicious, "wheel files missing from RECORD")
		}
	}

	res := risk.Evaluate(pkg, dedupeReasons(findings), nil, unique(suspicious), nil, pol)
	res.Artifact = artifact
	return Analysis{Result: res, Findings: dedupeReasons(findings), Artifact: artifact}, nil
}

func shouldAnalyzePythonExecutionSurface(slashRel, base string) bool {
	if base == "setup.py" {
		return false
	}
	return strings.HasPrefix(slashRel, "scripts/") ||
		strings.HasPrefix(slashRel, "bin/") ||
		wheelDataScript(slashRel) ||
		base == "__main__.py"
}

// wheelDataScript reports whether the path is inside a wheel's
// {name}-{version}.data/scripts/ directory, which installs onto PATH.
func wheelDataScript(slashRel string) bool {
	return strings.Contains(slashRel, ".data/scripts/")
}

// installRootManifest reports whether a setup.py/pyproject.toml path sits at
// the root of an extracted artifact (./, artifact-N/, or
// artifact-N/{name}-{version}/). Only the root manifest participates in the
// build/install; copies nested deeper — examples, tests, vendored fixtures —
// are inert at install time and scoring them false-blocks real packages.
func installRootManifest(slashRel string) bool {
	return strings.Count(slashRel, "/") <= 2
}

// orphanedBytecode returns compiled bytecode files that have no matching .py
// source in the artifact — the classic shape of a payload hidden from source
// review.
func orphanedBytecode(pycFiles []string, pyFiles map[string]bool) []string {
	var orphans []string
	for _, pyc := range pycFiles {
		dir := ""
		base := pyc
		if idx := strings.LastIndex(pyc, "/"); idx >= 0 {
			dir, base = pyc[:idx], pyc[idx+1:]
		}
		module := base
		if cut := strings.Index(base, "."); cut >= 0 {
			module = base[:cut]
		}
		// __pycache__/mod.cpython-311.pyc maps to ../mod.py; legacy mod.pyc
		// maps to a sibling mod.py.
		sourceDir := dir
		if strings.HasSuffix(dir, "__pycache__") {
			sourceDir = strings.TrimSuffix(strings.TrimSuffix(dir, "__pycache__"), "/")
		}
		source := module + ".py"
		if sourceDir != "" {
			source = sourceDir + "/" + source
		}
		if !pyFiles[source] {
			orphans = append(orphans, pyc)
		}
	}
	return orphans
}

// filesNotInRecord compares the files extracted for each wheel against the
// wheel's RECORD manifest and returns extracted files RECORD does not list.
// The comparison is scoped to the directory tree containing the .dist-info,
// so a source distribution extracted alongside the wheel is not inspected.
func filesNotInRecord(recordContents map[string]string, allFiles []string) []string {
	var unlisted []string
	for recordPath, content := range recordContents {
		distInfoDir := recordPath[:strings.LastIndex(recordPath, "/")]
		root := ""
		if idx := strings.LastIndex(distInfoDir, "/"); idx >= 0 {
			root = distInfoDir[:idx]
		}
		listed := map[string]bool{}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			entry := line
			if idx := strings.Index(line, ","); idx >= 0 {
				entry = line[:idx]
			}
			entry = strings.Trim(entry, `"`)
			entry = strings.TrimPrefix(filepath.ToSlash(entry), "./")
			if root != "" {
				entry = root + "/" + entry
			}
			listed[entry] = true
		}
		for _, f := range allFiles {
			if root != "" && !strings.HasPrefix(f, root+"/") {
				continue
			}
			base := filepath.Base(f)
			// RECORD signature companions are legitimately unlisted.
			if base == "RECORD.jws" || base == "RECORD.p7s" {
				continue
			}
			if !listed[f] {
				unlisted = append(unlisted, f)
			}
		}
	}
	return unlisted
}

func capList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	return append(out, fmt.Sprintf("(+%d more)", len(in)-n))
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
