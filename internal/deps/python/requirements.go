package python

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ParseRequirementsFile(path string) ([]Dependency, error) {
	return parseRequirementsFile(path, map[string]bool{})
}

func parseRequirementsFile(path string, seen map[string]bool) ([]Dependency, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if seen[abs] {
		return nil, nil
	}
	seen[abs] = true
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var deps []Dependency
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "--index-url") || strings.HasPrefix(line, "--extra-index-url") || strings.HasPrefix(line, "-i ") {
			continue
		}
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				child := parts[1]
				if !filepath.IsAbs(child) {
					child = filepath.Join(filepath.Dir(path), child)
				}
				childDeps, err := parseRequirementsFile(child, seen)
				if err != nil {
					return nil, err
				}
				deps = append(deps, childDeps...)
			}
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		dep := ParseRequirementSpec(line)
		if dep.Name != "" {
			dep.SourceFile = path
			deps = append(deps, dep)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read requirements %q: %w", path, err)
	}
	return deps, nil
}
