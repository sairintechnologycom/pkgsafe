package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/ci"
	goinventory "github.com/sairintechnologycom/pkgsafe/internal/deps/golang"
	"github.com/sairintechnologycom/pkgsafe/internal/git"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ReviewDependencyDiffParams defines parameters for review_dependency_diff.
type ReviewDependencyDiffParams struct {
	RepoPath string `json:"repo_path"`
	BaseRef  string `json:"base_ref"`
	HeadRef  string `json:"head_ref"`
}

// ReviewDependencyDiffResult defines the detailed output.
type ReviewDependencyDiffResult struct {
	Decision            string   `json:"decision"`
	RiskScore           int      `json:"risk_score"`
	Confidence          string   `json:"confidence"`
	TopReasons          []string `json:"top_reasons"`
	PolicyResult        string   `json:"policy_result"`
	EvidenceID          string   `json:"evidence_id"`
	AgentInstruction    string   `json:"agent_instruction"`
	AllowedNextActions  []string `json:"allowed_next_actions"`
	ProhibitedActions   []string `json:"prohibited_actions"`
	NewDependencies     int      `json:"new_dependencies"`
	BlockedDependencies int      `json:"blocked_dependencies"`
	WarnDependencies    int      `json:"warn_dependencies"`
}

// ReviewDependencyDiff reviews dependency changes created by AI agents in branches or PRs.
func (e *Executor) ReviewDependencyDiff(args json.RawMessage) CallToolResult {
	var p ReviewDependencyDiffParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.RepoPath == "" {
		p.RepoPath = "."
	}
	if p.BaseRef == "" {
		p.BaseRef = "main"
	}
	if p.HeadRef == "" {
		p.HeadRef = "agent-branch"
	}

	// 1. Load active policy
	policyFile := filepath.Join(p.RepoPath, ".pkgsafe/policy.yaml")
	pol, err := policy.ResolvePolicy("", policyFile, e.PolicyPath, "", "")
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	// 2. Identify repository changes using git
	_, err = git.RunGit(p.RepoPath, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		// Not in a git repo or git not available, return empty result or mock/fallback
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("GIT_NOT_AVAILABLE", "Not in a Git repository: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	// Fetch diff files
	diffOutput, err := git.RunGit(p.RepoPath, "diff", "--name-only", p.BaseRef+"..."+p.HeadRef)
	if err != nil {
		// Fallback to direct ref diff
		diffOutput, err = git.RunGit(p.RepoPath, "diff", "--name-only", p.BaseRef, p.HeadRef)
		if err != nil {
			// Fallback to simple local diff
			diffOutput, _ = git.RunGit(p.RepoPath, "diff", "--name-only")
		}
	}

	lines := strings.Split(diffOutput, "\n")
	var manifestFiles []string
	manifestSet := map[string]bool{
		"package.json":      true,
		"package-lock.json": true,
		"pnpm-lock.yaml":    true,
		"yarn.lock":         true,
		"requirements.txt":  true,
		"pyproject.toml":    true,
		"poetry.lock":       true,
		"uv.lock":           true,
		"go.mod":            true,
		"Cargo.toml":        true,
		"Cargo.lock":        true,
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		baseName := filepath.Base(line)
		if manifestSet[baseName] {
			manifestFiles = append(manifestFiles, line)
		}
	}

	newDepsCount := 0
	blockedCount := 0
	warnCount := 0
	maxScore := 0
	var topReasons []string

	type targetPackage struct {
		ecosystem string
		name      string
		version   string
	}
	var packagesToCheck []targetPackage

	for _, relPath := range manifestFiles {
		baseName := filepath.Base(relPath)
		ecosystem := getEcosystemForFile(baseName)

		// Get content at base ref
		baseBytes, _ := git.RunGit(p.RepoPath, "show", p.BaseRef+":"+relPath)
		// Get content at head ref (or fallback to local file)
		headBytes, err := git.RunGit(p.RepoPath, "show", p.HeadRef+":"+relPath)
		if err != nil {
			// Read from filesystem directly
			localPath := filepath.Join(p.RepoPath, relPath)
			if data, err := os.ReadFile(localPath); err == nil {
				headBytes = string(data)
			}
		}

		baseDeps, _ := parseDeps(baseName, []byte(baseBytes))
		headDeps, _ := parseDeps(baseName, []byte(headBytes))

		// Find new/updated dependencies
		for name, headVer := range headDeps {
			baseVer, exists := baseDeps[name]
			if !exists {
				newDepsCount++
				packagesToCheck = append(packagesToCheck, targetPackage{ecosystem, name, headVer})
			} else if baseVer != headVer {
				packagesToCheck = append(packagesToCheck, targetPackage{ecosystem, name, headVer})
			}
		}
	}

	// 3. Scan each added/updated package
	for _, pkg := range packagesToCheck {
		var res types.ScanResult
		var err error

		switch pkg.ecosystem {
		case "pypi":
			scanner := spypi.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pkg.name, pkg.version)
		case "cargo":
			scanner := scargo.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pkg.name, pkg.version)
		case "go", "golang":
			scanner := sgolang.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pkg.name, pkg.version)
		default: // npm
			scanner := snpm.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pkg.name, pkg.version)
		}

		if err != nil {
			// Skip packages that fail to scan or log warning
			continue
		}

		if res.Decision == types.DecisionBlock {
			blockedCount++
			topReasons = append(topReasons, fmt.Sprintf("[%s:%s] Blocked: %d risk score", pkg.name, pkg.ecosystem, res.Score))
		} else if res.Decision == types.DecisionWarn {
			warnCount++
			topReasons = append(topReasons, fmt.Sprintf("[%s:%s] Warning: %d risk score", pkg.name, pkg.ecosystem, res.Score))
		}

		if res.Score > maxScore {
			maxScore = res.Score
		}
	}

	overallDecision := "ALLOW"
	if blockedCount > 0 || warnCount > 0 {
		overallDecision = "REVIEW_REQUIRED"
	}

	evidenceID := fmt.Sprintf("pkg-%s-%03d", time.Now().Format("20060102"), time.Now().UnixNano()%1000)

	// Build guidance instructions with agent policy overrides
	overallDecision, instruction, allowedActions, prohibitedActions := ApplyAgentPolicyOverrides(overallDecision, pol.AgentPolicy)
	if overallDecision == "ALLOW" {
		instruction = "Dependency diff is clean. No risk found."
	} else if overallDecision == "REVIEW_REQUIRED" {
		instruction = "Do not open PR as ready. Mark PR as requiring security review."
		allowedActions = []string{"mark_review", "proceed_coding"}
	} else if overallDecision == "BLOCK" {
		instruction = "Do not open PR as ready. The dependency review has failed with decision BLOCK."
		allowedActions = []string{"suggest_alternative", "remove_dependency"}
	}

	if len(topReasons) == 0 {
		topReasons = []string{"No policy violations detected in the dependency diff."}
	}

	toolRes := ReviewDependencyDiffResult{
		Decision:            overallDecision,
		RiskScore:           maxScore,
		Confidence:          "high",
		TopReasons:          topReasons,
		PolicyResult:        fmt.Sprintf("mode: %s", pol.Mode),
		EvidenceID:          evidenceID,
		AgentInstruction:    instruction,
		AllowedNextActions:  allowedActions,
		ProhibitedActions:   prohibitedActions,
		NewDependencies:     newDepsCount,
		BlockedDependencies: blockedCount,
		WarnDependencies:    warnCount,
	}

	b, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}

func getEcosystemForFile(filename string) string {
	switch filename {
	case "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock":
		return "npm"
	case "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock":
		return "pypi"
	case "go.mod":
		return "go"
	case "Cargo.toml", "Cargo.lock":
		return "cargo"
	}
	return "npm"
}

// parseDeps delegates parsing of dependency files using inline/utility code.
func parseDeps(filename string, content []byte) (map[string]string, error) {
	filename = filepath.Base(filename)
	switch filename {
	case "package.json":
		var pj struct {
			Deps map[string]string `json:"dependencies"`
			Dev  map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(content, &pj); err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for k, v := range pj.Deps {
			res[k] = v
		}
		for k, v := range pj.Dev {
			res[k] = v
		}
		return res, nil
	case "package-lock.json":
		deps, _, err := ci.DiffLockfilesDetailed(content, []byte(`{"lockfileVersion":2,"packages":{},"dependencies":{}}`))
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range deps {
			res[d.Name] = d.Version
		}
		return res, nil
	case "requirements.txt":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if idx := strings.Index(line, "#"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if idx := strings.Index(line, ";"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line == "" {
				continue
			}
			name := line
			version := "latest"
			for _, op := range []string{"===", "==", "~=", ">=", "<=", "!=", ">", "<"} {
				if idx := strings.Index(line, op); idx > 0 {
					name = strings.TrimSpace(line[:idx])
					version = strings.TrimSpace(line[idx+len(op):])
					if cidx := strings.IndexAny(version, ", ;<>="); cidx >= 0 {
						version = version[:cidx]
					}
					break
				}
			}
			if name != "" {
				res[name] = version
			}
		}
		return res, nil
	case "go.mod":
		deps, err := goinventory.ParseGoMod(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range deps {
			res[d.Name] = d.Version
		}
		return res, nil
	case "Cargo.toml":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		inDeps := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "[dependencies]") || strings.HasPrefix(line, "[dev-dependencies]") || strings.HasPrefix(line, "[build-dependencies]") {
				inDeps = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inDeps = false
				continue
			}
			if inDeps && line != "" && !strings.HasPrefix(line, "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
					val := strings.TrimSpace(parts[1])
					version := "latest"
					if strings.HasPrefix(val, `"`) {
						version = strings.Trim(val, `"`)
					} else if strings.HasPrefix(val, `{`) {
						if vIdx := strings.Index(val, `version`); vIdx >= 0 {
							sub := val[vIdx:]
							if eqIdx := strings.Index(sub, `=[ \t]*"`); eqIdx >= 0 {
								verSub := sub[eqIdx:]
								firstQuote := strings.Index(verSub, `"`)
								if firstQuote >= 0 {
									secondQuote := strings.Index(verSub[firstQuote+1:], `"`)
									if secondQuote >= 0 {
										version = verSub[firstQuote+1 : firstQuote+1+secondQuote]
									}
								}
							}
						}
					}
					res[name] = version
				}
			}
		}
		return res, nil
	case "Cargo.lock", "poetry.lock", "uv.lock":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		var currentName string
		var currentVersion string
		inPackage := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "[[package]]" {
				if inPackage && currentName != "" && currentVersion != "" {
					res[currentName] = currentVersion
				}
				currentName = ""
				currentVersion = ""
				inPackage = true
				continue
			}
			if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
				if inPackage && currentName != "" && currentVersion != "" {
					res[currentName] = currentVersion
				}
				inPackage = false
				currentName = ""
				currentVersion = ""
				continue
			}
			if inPackage {
				if strings.HasPrefix(line, "name =") {
					currentName = strings.Trim(strings.TrimPrefix(line, "name ="), ` "`)
				} else if strings.HasPrefix(line, "version =") {
					currentVersion = strings.Trim(strings.TrimPrefix(line, "version ="), ` "`)
				}
			}
		}
		if inPackage && currentName != "" && currentVersion != "" {
			res[currentName] = currentVersion
		}
		return res, nil
	case "pyproject.toml":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		inDeps := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "[project.dependencies]") || strings.HasPrefix(line, "[tool.poetry.dependencies]") || strings.HasPrefix(line, "[tool.poetry.dev-dependencies]") {
				inDeps = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inDeps = false
				continue
			}
			if inDeps && line != "" && !strings.HasPrefix(line, "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
					val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					version := "latest"
					if strings.HasPrefix(val, `"`) || strings.HasPrefix(val, `'`) {
						version = strings.Trim(val, `"'`)
					} else if strings.HasPrefix(val, `{`) {
						if vIdx := strings.Index(val, `version`); vIdx >= 0 {
							sub := val[vIdx:]
							if eqIdx := strings.Index(sub, `=[ \t]*"`); eqIdx >= 0 {
								verSub := sub[eqIdx:]
								firstQuote := strings.Index(verSub, `"`)
								if firstQuote >= 0 {
									secondQuote := strings.Index(verSub[firstQuote+1:], `"`)
									if secondQuote >= 0 {
										version = verSub[firstQuote+1 : firstQuote+1+secondQuote]
									}
								}
							}
						}
					}
					res[name] = version
				} else {
					name := strings.Trim(strings.TrimSpace(line), `", '`)
					if name != "" {
						res[name] = "latest"
					}
				}
			}
		}
		return res, nil
	case "pnpm-lock.yaml":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "/") || (strings.Contains(line, "@") && strings.HasSuffix(line, ":")) {
				line = strings.TrimSuffix(line, ":")
				line = strings.Trim(line, `'"`)
				if strings.HasPrefix(line, "/") {
					line = line[1:]
				}
				idx := strings.LastIndex(line, "@")
				if idx > 0 {
					name := line[:idx]
					version := line[idx+1:]
					res[name] = version
				} else {
					idxSlash := strings.LastIndex(line, "/")
					if idxSlash > 0 {
						name := line[:idxSlash]
						version := line[idxSlash+1:]
						res[name] = version
					}
				}
			}
		}
		return res, nil
	case "yarn.lock":
		res := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(content))
		var currentNames []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasSuffix(line, ":") {
				currentNames = nil
				header := strings.TrimSuffix(line, ":")
				parts := strings.Split(header, ",")
				for _, p := range parts {
					p = strings.Trim(strings.TrimSpace(p), `'"`)
					idx := strings.LastIndex(p, "@")
					if idx > 0 {
						name := p[:idx]
						currentNames = append(currentNames, name)
					} else if p != "" {
						currentNames = append(currentNames, p)
					}
				}
				continue
			}
			if strings.HasPrefix(line, "version ") {
				version := strings.Trim(strings.TrimPrefix(line, "version "), `'"`)
				for _, name := range currentNames {
					res[name] = version
				}
				currentNames = nil
			}
		}
		return res, nil
	}
	return nil, nil
}
