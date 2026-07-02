package python

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Dependency struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Specifier  string `json:"specifier,omitempty"`
	Pinned     bool   `json:"pinned"`
	SourceFile string `json:"source_file,omitempty"`
	// Hashes holds artifact digests recorded by the source file (poetry.lock
	// files, uv.lock wheels/sdist, Pipfile.lock hashes, requirements --hash).
	Hashes []string `json:"hashes,omitempty"`
	// Registry is the explicit package index recorded by the source file for
	// this dependency, when it names one (uv.lock source.registry,
	// poetry.lock [package.source] url, Pipfile.lock index URL).
	Registry string `json:"registry,omitempty"`
	// DirectURL is set for PEP 508 direct references and git/url lock sources.
	// These do not resolve from a package index, so scanning the same name on
	// PyPI would inspect a different artifact.
	DirectURL string `json:"direct_url,omitempty"`
	// FromLockfile marks entries parsed from a resolved lockfile, where the
	// list includes transitive dependencies.
	FromLockfile bool `json:"from_lockfile,omitempty"`
	// LocalSource marks lock entries that point at the project itself or a
	// local path (uv.lock virtual/editable/path/directory sources). They are
	// not registry packages and must not be scanned against PyPI.
	LocalSource bool `json:"local_source,omitempty"`
}

func ParseFile(path string) ([]Dependency, error) {
	switch strings.ToLower(filepath.Base(path)) {
	case "requirements.txt":
		return ParseRequirementsFile(path)
	case "pyproject.toml":
		return ParsePyprojectFile(path)
	case "poetry.lock":
		return ParsePoetryLockFile(path)
	case "uv.lock":
		return ParseUVLockFile(path)
	case "pipfile":
		return ParsePipfile(path)
	case "pipfile.lock":
		return ParsePipfileLock(path)
	case "environment.yml", "environment.yaml":
		return ParseCondaEnvFile(path)
	default:
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".txt" {
			return ParseRequirementsFile(path)
		}
		return nil, fmt.Errorf("unsupported Python dependency file %q", path)
	}
}

func ParseRequirementSpec(spec string) Dependency {
	spec = strings.TrimSpace(stripInlineComment(spec))
	spec = strings.Trim(spec, `"'`)
	if spec == "" {
		return Dependency{}
	}
	// Per-requirement pip options (e.g. --hash=sha256:...) come after the
	// requirement itself.
	hashes, spec := splitRequirementOptions(spec)
	for _, marker := range []string{";", " #"} {
		if idx := strings.Index(spec, marker); idx >= 0 {
			spec = strings.TrimSpace(spec[:idx])
		}
	}
	// PEP 508 direct reference: "name @ https://..." resolves outside any
	// package index.
	directURL := ""
	if name, url, ok := strings.Cut(spec, "@"); ok && strings.Contains(url, "://") {
		spec = strings.TrimSpace(name)
		directURL = strings.TrimSpace(url)
	}
	namePart := spec
	version := ""
	specifier := ""
	for _, op := range []string{"===", "==", "~=", ">=", "<=", "!=", ">", "<"} {
		if idx := strings.Index(spec, op); idx > 0 {
			namePart = strings.TrimSpace(spec[:idx])
			specifier = strings.TrimSpace(spec[idx:])
			if op == "==" || op == "===" {
				version = strings.TrimSpace(strings.TrimPrefix(specifier, op))
				if cut := strings.IndexAny(version, ", "); cut >= 0 {
					version = version[:cut]
				}
			}
			break
		}
	}
	if idx := strings.Index(namePart, "["); idx >= 0 {
		namePart = namePart[:idx]
	}
	name := normalizeName(namePart)
	if !validPackageName(name) {
		return Dependency{}
	}
	return Dependency{
		Name:      name,
		Version:   version,
		Specifier: specifier,
		Pinned:    version != "",
		Hashes:    hashes,
		DirectURL: directURL,
	}
}

// splitRequirementOptions strips pip per-requirement options from a
// requirements line, capturing any --hash digests.
func splitRequirementOptions(spec string) ([]string, string) {
	if !strings.Contains(spec, "--") {
		return nil, spec
	}
	var hashes []string
	fields := strings.Fields(spec)
	kept := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "--hash="):
			hashes = append(hashes, strings.TrimPrefix(f, "--hash="))
		case f == "--hash" && i+1 < len(fields):
			i++
			hashes = append(hashes, fields[i])
		case strings.HasPrefix(f, "--"):
			// Any other per-requirement option and its inline value.
			if !strings.Contains(f, "=") && i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "--") {
				i++
			}
		default:
			kept = append(kept, f)
		}
	}
	return hashes, strings.Join(kept, " ")
}

var packageNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$`)

// validPackageName reports whether name is a plausible normalized PyPI
// project name. Rejecting anything else keeps URLs, local paths, and parse
// garbage from being looked up against the registry under a bogus name.
func validPackageName(name string) bool {
	return name != "" && packageNamePattern.MatchString(name)
}

// normalizeName applies PEP 503 canonicalization: lowercase with runs of
// ".", "-", and "_" collapsed to a single "-".
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return nameSeparatorRuns.ReplaceAllString(s, "-")
}

var nameSeparatorRuns = regexp.MustCompile(`[-_.]+`)

// Dedupe merges dependencies collected from multiple manifests and lockfiles
// into one entry per name@version. Manifest provenance wins over lockfile
// provenance (so direct dependencies stay marked direct), and recorded
// hashes, registries, and pins are unioned. A version-less manifest entry
// collapses into the versioned entry that a lockfile resolved it to, instead
// of remaining a second scan target.
func Dedupe(deps []Dependency) []Dependency {
	type key struct{ name, version string }
	versioned := map[string]bool{}
	for _, dep := range deps {
		if dep.Version != "" {
			versioned[dep.Name] = true
		}
	}
	index := map[key]int{}
	out := make([]Dependency, 0, len(deps))
	var unversioned []Dependency
	for _, dep := range deps {
		if dep.Version == "" && versioned[dep.Name] {
			unversioned = append(unversioned, dep)
			continue
		}
		k := key{dep.Name, dep.Version}
		i, ok := index[k]
		if !ok {
			index[k] = len(out)
			out = append(out, dep)
			continue
		}
		merged := out[i]
		if !dep.FromLockfile {
			merged.FromLockfile = false
		}
		if merged.Specifier == "" {
			merged.Specifier = dep.Specifier
		}
		if merged.Registry == "" {
			merged.Registry = dep.Registry
		}
		if merged.DirectURL == "" {
			merged.DirectURL = dep.DirectURL
		}
		merged.Pinned = merged.Pinned || dep.Pinned
		merged.LocalSource = merged.LocalSource && dep.LocalSource
		merged.Hashes = unionStrings(merged.Hashes, dep.Hashes)
		if merged.SourceFile != dep.SourceFile && dep.SourceFile != "" && merged.SourceFile != "" {
			merged.SourceFile = merged.SourceFile + ", " + dep.SourceFile
		}
		out[i] = merged
	}
	// Fold each collapsed manifest entry into every versioned entry for the
	// same name: the direct-dependency provenance carries over.
	for _, dep := range unversioned {
		if dep.FromLockfile {
			continue
		}
		for i := range out {
			if out[i].Name == dep.Name {
				out[i].FromLockfile = false
			}
		}
	}
	return out
}

func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if v != "" && !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	return a
}

func stripInlineComment(s string) string {
	inQuote := false
	var quote rune
	for i, r := range s {
		if (r == '\'' || r == '"') && (!inQuote || quote == r) {
			if inQuote {
				inQuote = false
			} else {
				inQuote = true
				quote = r
			}
		}
		if r == '#' && !inQuote {
			return s[:i]
		}
	}
	return s
}
