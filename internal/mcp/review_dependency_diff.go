package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/ci"
	depscargo "github.com/sairintechnologycom/pkgsafe/internal/deps/cargo"
	goinventory "github.com/sairintechnologycom/pkgsafe/internal/deps/golang"
	depsnpm "github.com/sairintechnologycom/pkgsafe/internal/deps/npm"
	depspython "github.com/sairintechnologycom/pkgsafe/internal/deps/python"
	"github.com/sairintechnologycom/pkgsafe/internal/git"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
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
	Decision            string               `json:"decision"`
	RiskScore           int                  `json:"risk_score"`
	Confidence          string               `json:"confidence"`
	TopReasons          []string             `json:"top_reasons"`
	PackageProfile      types.PackageProfile `json:"package_profile"`
	PolicyResult        string               `json:"policy_result"`
	EvidenceID          string               `json:"evidence_id"`
	AgentInstruction    string               `json:"agent_instruction"`
	AllowedNextActions  []string             `json:"allowed_next_actions"`
	ProhibitedActions   []string             `json:"prohibited_actions"`
	NewDependencies     int                  `json:"new_dependencies"`
	BlockedDependencies int                  `json:"blocked_dependencies"`
	WarnDependencies    int                  `json:"warn_dependencies"`
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

	// 2. Confirm we are inside a git repository
	_, err = git.RunGit(p.RepoPath, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("GIT_NOT_AVAILABLE", "Not in a Git repository: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	// 3. Obtain list of changed manifest/lockfiles
	diffOutput, err := git.RunGit(p.RepoPath, "diff", "--name-only", p.BaseRef+"..."+p.HeadRef)
	if err != nil {
		diffOutput, err = git.RunGit(p.RepoPath, "diff", "--name-only", p.BaseRef, p.HeadRef)
		if err != nil {
			diffOutput, _ = git.RunGit(p.RepoPath, "diff", "--name-only")
		}
	}

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

	var manifestFiles []string
	for _, line := range strings.Split(diffOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if manifestSet[filepath.Base(line)] {
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

	// 4. Parse each manifest with real parsers, compute diff of new/changed deps
	for _, relPath := range manifestFiles {
		baseName := filepath.Base(relPath)
		ecosystem := getEcosystemForFile(baseName)

		baseBytes, _ := git.RunGit(p.RepoPath, "show", p.BaseRef+":"+relPath)
		headBytes, err := git.RunGit(p.RepoPath, "show", p.HeadRef+":"+relPath)
		if err != nil {
			if data, ferr := os.ReadFile(filepath.Join(p.RepoPath, relPath)); ferr == nil {
				headBytes = string(data)
			}
		}

		baseDeps, _ := parseDepsWithRealParsers(baseName, []byte(baseBytes), p.RepoPath)
		headDeps, _ := parseDepsWithRealParsers(baseName, []byte(headBytes), p.RepoPath)

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

	// 5. Scan each new/updated package
	opts := ScanOpts{
		RequestedBy: "ai_agent",
		Environment: "ai_agent",
	}
	for _, pkg := range packagesToCheck {
		res, _, err := e.evaluatePackage(pkg.ecosystem, pkg.name, pkg.version, pol, e.Offline, "ai_agent", opts)
		if err != nil {
			continue // skip unresolvable packages; log could go here
		}

		switch res.Decision {
		case types.DecisionBlock:
			blockedCount++
			topReasons = append(topReasons, fmt.Sprintf("[%s:%s] Blocked: %d risk score", pkg.name, pkg.ecosystem, res.Score))
		case types.DecisionWarn:
			warnCount++
			topReasons = append(topReasons, fmt.Sprintf("[%s:%s] Warning: %d risk score", pkg.name, pkg.ecosystem, res.Score))
		}

		if res.Score > maxScore {
			maxScore = res.Score
		}
	}

	// 6. Determine overall decision.
	// If any dep is blocked, the overall decision is BLOCK (not REVIEW_REQUIRED).
	var overallDecision types.Decision
	switch {
	case blockedCount > 0:
		overallDecision = types.DecisionBlock
	case warnCount > 0:
		overallDecision = types.DecisionWarn
	default:
		overallDecision = types.DecisionAllow
	}

	evidenceID := generateEvidenceID("diff", p.BaseRef, p.HeadRef)

	guidance := GetAgentGuidance(overallDecision, pol.AgentPolicy, pol.Mode)

	instruction := guidance.Instruction
	allowedActions := guidance.AllowedNextActions
	prohibitedActions := guidance.ProhibitedActions

	// Semantic overrides for diff context
	switch overallDecision {
	case types.DecisionAllow:
		instruction = "Dependency diff is clean. No risk found."
		allowedActions = []string{"proceed"}
		prohibitedActions = []string{}
	case types.DecisionWarn:
		// Keep guidance, but surface the review action
		instruction = "Do not open PR as ready. Mark PR as requiring security review."
		allowedActions = dedup(append([]string{"mark_review", "proceed_coding"}, guidance.AllowedNextActions...))
	case types.DecisionBlock:
		instruction = "Do not open PR as ready. The dependency review has failed with decision BLOCK."
		allowedActions = dedup(append([]string{"suggest_alternative", "remove_dependency"}, guidance.AllowedNextActions...))
	}

	if len(topReasons) == 0 {
		topReasons = []string{"No policy violations detected in the dependency diff."}
	}

	toolRes := ReviewDependencyDiffResult{
		Decision:            guidance.Decision,
		RiskScore:           maxScore,
		Confidence:          "high",
		TopReasons:          topReasons,
		PackageProfile:      types.PackageProfile{},
		PolicyResult:        fmt.Sprintf("mode: %s", pol.Mode),
		EvidenceID:          evidenceID,
		AgentInstruction:    instruction,
		AllowedNextActions:  allowedActions,
		ProhibitedActions:   prohibitedActions,
		NewDependencies:     newDepsCount,
		BlockedDependencies: blockedCount,
		WarnDependencies:    warnCount,
	}

	if len(packagesToCheck) > 0 {
		toolRes.PackageProfile = types.PackageProfile{
			SchemaVersion: "1.0",
			Package: types.PackageProfileIdentity{
				Ecosystem:        packagesToCheck[0].ecosystem,
				Name:             packagesToCheck[0].name,
				RequestedVersion: packagesToCheck[0].version,
				ResolvedVersion:  packagesToCheck[0].version,
			},
			Decision:   types.Decision(guidance.Decision),
			RiskScore:  maxScore,
			Confidence: "high",
			TopReasons: append([]string{}, topReasons...),
			Policy: types.PackageProfilePolicy{
				Mode:              string(pol.Mode),
				Thresholds:        pol.Thresholds,
				Enforcement:       instruction,
				RecommendedAction: instruction,
			},
			EvidenceID: evidenceID,
		}
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

// parseDepsWithRealParsers delegates to real internal/deps parsers for each manifest type.
// It returns a name→version map suitable for diffing.
func parseDepsWithRealParsers(filename string, content []byte, repoPath string) (map[string]string, error) {
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
		added, _, err := ci.DiffLockfilesDetailed(content, []byte(`{"lockfileVersion":2,"packages":{},"dependencies":{}}`))
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range added {
			res[d.Name] = d.Version
		}
		return res, nil

	case "yarn.lock":
		lockDeps, err := depsnpm.ParseYarnLock(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range lockDeps {
			res[d.Name] = d.Version
		}
		return res, nil

	case "pnpm-lock.yaml":
		lockDeps, err := depsnpm.ParsePnpmLock(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range lockDeps {
			res[d.Name] = d.Version
		}
		return res, nil

	case "go.mod":
		goDeps, err := goinventory.ParseGoMod(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range goDeps {
			res[d.Name] = d.Version
		}
		return res, nil

	case "Cargo.lock":
		cargoDeps, err := depscargo.ParseCargoLock(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range cargoDeps {
			res[d.Name] = d.Version
		}
		return res, nil

	case "Cargo.toml":
		cargoDeps, err := depscargo.ParseCargoToml(content)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range cargoDeps {
			res[d.Name] = d.Version
		}
		return res, nil

	case "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock":
		// Write to temp file so the Python parser's path-based dispatch works
		tmpDir, err := os.MkdirTemp("", "pkgsafe-diff-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)

		tmpFile := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(tmpFile, content, 0600); err != nil {
			return nil, err
		}
		pyDeps, err := depspython.ParseFile(tmpFile)
		if err != nil {
			return nil, err
		}
		res := make(map[string]string)
		for _, d := range pyDeps {
			if d.LocalSource {
				continue
			}
			version := d.Version
			if version == "" {
				version = d.Specifier
			}
			if version == "" {
				version = "latest"
			}
			res[d.Name] = version
		}
		return res, nil
	}

	return nil, nil
}
