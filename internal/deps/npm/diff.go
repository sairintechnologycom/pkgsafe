package npm

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/git"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type ChangedDependency struct {
	Name        string `json:"package_name"`
	SourceFile  string `json:"source_file"`
	BaseVersion string `json:"base_version"`
	CurVersion  string `json:"current_version"`
	BaseType    string `json:"base_type"`
	CurType     string `json:"current_type"`
	BaseDirect  bool   `json:"base_direct"`
	CurDirect   bool   `json:"current_direct"`
}

type InventoryDiffReport struct {
	Added   []types.Dependency  `json:"added"`
	Removed []types.Dependency  `json:"removed"`
	Changed []ChangedDependency `json:"changed"`
}

// ScanInventoryGit gathers all dependencies from a specific Git revision (base branch).
func ScanInventoryGit(repoPath, revision string) ([]types.Dependency, error) {
	out, err := git.RunGit(repoPath, "ls-tree", "-r", "--name-only", revision)
	if err != nil {
		return nil, fmt.Errorf("git ls-tree: %w", err)
	}

	files := strings.Split(out, "\n")
	var packageJSONPaths []string
	var packageLockPaths []string
	var sourcePaths []string

	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		name := filepath.Base(file)
		if name == "node_modules" || strings.Contains(file, "/node_modules/") {
			continue
		}

		if name == "package.json" {
			packageJSONPaths = append(packageJSONPaths, file)
		} else if name == "package-lock.json" {
			packageLockPaths = append(packageLockPaths, file)
		} else if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".jsx") || strings.HasSuffix(name, ".tsx") {
			sourcePaths = append(sourcePaths, file)
		}
	}

	readGitFiles := func(paths []string) []namedFile {
		out := make([]namedFile, 0, len(paths))
		for _, relPath := range paths {
			bStr, err := git.RunGit(repoPath, "show", revision+":"+relPath)
			if err != nil {
				continue
			}
			out = append(out, namedFile{relPath: relPath, content: []byte(bStr)})
		}
		return out
	}

	return buildNPMInventory(readGitFiles(packageJSONPaths), readGitFiles(packageLockPaths), readGitFiles(sourcePaths)), nil
}

// DiffInventories compares dependency lists.
func DiffInventories(baseDeps, currentDeps []types.Dependency) InventoryDiffReport {
	var report InventoryDiffReport

	baseMap := make(map[string]types.Dependency)
	for _, d := range baseDeps {
		if d.Name == "" {
			continue
		}
		key := fmt.Sprintf("%s:%s", d.SourceFile, d.Name)
		baseMap[key] = d
	}

	currentMap := make(map[string]types.Dependency)
	for _, d := range currentDeps {
		if d.Name == "" {
			continue
		}
		key := fmt.Sprintf("%s:%s", d.SourceFile, d.Name)
		currentMap[key] = d
	}

	for key, cur := range currentMap {
		if base, ok := baseMap[key]; ok {
			if base.VersionRange != cur.VersionRange || base.DependencyType != cur.DependencyType || base.Direct != cur.Direct {
				report.Changed = append(report.Changed, ChangedDependency{
					Name:        cur.Name,
					SourceFile:  cur.SourceFile,
					BaseVersion: base.VersionRange,
					CurVersion:  cur.VersionRange,
					BaseType:    base.DependencyType,
					CurType:     cur.DependencyType,
					BaseDirect:  base.Direct,
					CurDirect:   cur.Direct,
				})
			}
		} else {
			report.Added = append(report.Added, cur)
		}
	}

	for key, base := range baseMap {
		if _, ok := currentMap[key]; !ok {
			report.Removed = append(report.Removed, base)
		}
	}

	return report
}
