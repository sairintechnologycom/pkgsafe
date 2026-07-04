package pypi

import (
	"fmt"
	"strings"
)

func ResolveVersion(md Metadata, requested string) (VersionMetadata, error) {
	if len(md.Releases) == 0 {
		return VersionMetadata{}, fmt.Errorf("no releases found for %s", md.Info.Name)
	}
	version := requested
	if version == "" || version == "latest" {
		version = latestNonYanked(md)
		if version == "" {
			version = latestAny(md)
		}
	}
	files, ok := md.Releases[version]
	if !ok {
		return VersionMetadata{}, fmt.Errorf("version %s not found for %s", version, md.Info.Name)
	}
	vm := VersionMetadata{
		Name:           md.Info.Name,
		Version:        version,
		Summary:        md.Info.Summary,
		Description:    md.Info.Description,
		Repository:     RepositoryURL(md.Info),
		License:        md.Info.License,
		RequiresPython: md.Info.RequiresPython,
		Dependencies:   md.Info.RequiresDist,
		Classifiers:    md.Info.Classifiers,
		Files:          files,
		Info:           md.Info,
	}
	for _, f := range files {
		if f.PackageType == "bdist_wheel" || hasSuffixFold(f.Filename, ".whl") {
			vm.WheelFiles = append(vm.WheelFiles, f)
		}
		if f.PackageType == "sdist" || hasSuffixFold(f.Filename, ".tar.gz") || hasSuffixFold(f.Filename, ".zip") {
			vm.SourceFiles = append(vm.SourceFiles, f)
		}
		if f.Yanked {
			vm.Yanked = true
		}
		if t := f.UploadTime(); !t.IsZero() && (vm.Time.IsZero() || t.Before(vm.Time)) {
			vm.Time = t
		}
	}
	return vm, nil
}

func RepositoryURL(info Info) string {
	for _, key := range []string{"Source", "Source Code", "Repository", "Code", "Homepage"} {
		if info.ProjectURLs != nil && info.ProjectURLs[key] != "" {
			return info.ProjectURLs[key]
		}
	}
	return info.HomePage
}

func latestNonYanked(md Metadata) string {
	return latestMatching(md, false)
}

func latestAny(md Metadata) string {
	return latestMatching(md, true)
}

// latestMatching picks the version pip would install by default: the highest
// PEP 440 stable release, falling back to pre-releases only when no stable
// release exists, and to raw string order only when nothing parses as PEP 440.
func latestMatching(md Metadata, allowYanked bool) string {
	type candidate struct {
		raw    string
		parsed pep440Version
		ok     bool
	}
	var candidates []candidate
	for v, files := range md.Releases {
		if len(files) == 0 {
			continue
		}
		yanked := true
		for _, f := range files {
			if !f.Yanked {
				yanked = false
				break
			}
		}
		if !allowYanked && yanked {
			continue
		}
		pv, ok := parsePEP440(v)
		candidates = append(candidates, candidate{raw: v, parsed: pv, ok: ok})
	}
	best := func(include func(candidate) bool) string {
		var b *candidate
		for i := range candidates {
			c := &candidates[i]
			if !include(*c) {
				continue
			}
			if b == nil {
				b = c
				continue
			}
			cmp := comparePEP440(c.parsed, b.parsed)
			if cmp > 0 || (cmp == 0 && c.raw > b.raw) {
				b = c
			}
		}
		if b == nil {
			return ""
		}
		return b.raw
	}
	if v := best(func(c candidate) bool { return c.ok && !c.parsed.isPrerelease() }); v != "" {
		return v
	}
	if v := best(func(c candidate) bool { return c.ok }); v != "" {
		return v
	}
	var fallback string
	for _, c := range candidates {
		if c.raw > fallback {
			fallback = c.raw
		}
	}
	return fallback
}

func hasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}
