package pypi

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
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

func latestMatching(md Metadata, allowYanked bool) string {
	var versions []string
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
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		vi, ei := semver.NewVersion(versions[i])
		vj, ej := semver.NewVersion(versions[j])
		if ei == nil && ej == nil {
			return vi.GreaterThan(vj)
		}
		return versions[i] > versions[j]
	})
	if len(versions) == 0 {
		return ""
	}
	return versions[0]
}

func hasSuffixFold(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}
