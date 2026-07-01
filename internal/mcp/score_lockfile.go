package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
	"github.com/sairintechnologycom/pkgsafe/internal/typosquat"
)

// ScoreLockfileParams defines the input for score_lockfile.
type ScoreLockfileParams struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	Mode      string `json:"mode"`
	Offline   bool   `json:"offline"`
}

// ScoreLockfileFinding represents a single dependency finding in the lockfile.
type ScoreLockfileFinding struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Decision  string `json:"decision"`
	RiskScore int    `json:"risk_score"`
	Reason    string `json:"reason"`
}

// ScoreLockfileResult represents the tool response for score_lockfile.
type ScoreLockfileResult struct {
	Ecosystem         string                 `json:"ecosystem"`
	Path              string                 `json:"path"`
	Decision          string                 `json:"decision"`
	RiskScore         int                    `json:"risk_score"`
	Summary           ScoreLockfileSummary   `json:"summary"`
	TopFindings       []ScoreLockfileFinding `json:"top_findings"`
	RecommendedAction string                 `json:"recommended_action"`
}

type ScoreLockfileSummary struct {
	TotalPackages int `json:"total_packages"`
	Allow         int `json:"allow"`
	Warn          int `json:"warn"`
	Block         int `json:"block"`
}

type packageLock struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	LockfileVersion int    `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		Dev       bool   `json:"dev"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// ScoreLockfile scans a lockfile and returns vulnerability and safety scores.
func (e *Executor) ScoreLockfile(args json.RawMessage) CallToolResult {
	var p ScoreLockfileParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.Ecosystem == "" {
		p.Ecosystem = "npm"
	}
	if p.Ecosystem != "npm" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("UNSUPPORTED_ECOSYSTEM", "Only npm ecosystem is supported", map[string]string{"ecosystem": p.Ecosystem}),
			}},
			IsError: true,
		}
	}

	if p.Path == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Path is required", nil),
			}},
			IsError: true,
		}
	}

	b, err := os.ReadFile(p.Path)
	if err != nil {
		te := MapScanError(err, p.Ecosystem, "", "")
		bErr, _ := json.MarshalIndent(te, "", "  ")
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: string(bErr),
			}},
			IsError: true,
		}
	}

	var lf packageLock
	if err := json.Unmarshal(b, &lf); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Failed to parse lockfile: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	pol, err := policy.Load(e.PolicyPath)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if e.Mode != "" {
		pol.Mode = policy.ParseMode(e.Mode)
	}
	if p.Mode != "" {
		pol.Mode = policy.ParseMode(p.Mode)
	}

	packagesMap := make(map[string]string)
	for pkgPath, pkg := range lf.Packages {
		if pkgPath == "" || pkgPath == "node_modules" {
			continue
		}
		name := extractModuleName(pkgPath)
		if name != "" && pkg.Version != "" {
			packagesMap[name] = pkg.Version
		}
	}
	for name, dep := range lf.Dependencies {
		if dep.Version != "" {
			packagesMap[name] = dep.Version
		}
	}

	var allowCount, warnCount, blockCount int
	var findings []ScoreLockfileFinding
	maxScore := 0

	d, dbErr := db.Open("")
	var dbConn *db.DB
	if dbErr == nil {
		dbConn = d
		defer d.Close()
	}

	for name, ver := range packagesMap {
		decision := types.DecisionAllow
		score := 0
		reason := ""

		if policy.IsBlocked(pol, "npm", name) {
			decision = types.DecisionBlock
			score = 100
			reason = "Package is listed as blocked by policy"
		} else if len(typosquat.Check(name)) > 0 {
			decision = types.DecisionWarn
			score = 25
			reason = "Package name resembles a popular package"
		}

		if dbErr == nil {
			vulns, err := dbConn.GetVulnerabilitiesForPackage(context.Background(), "npm", name)
			if err == nil {
				for _, v := range vulns {
					if intel.IsVersionAffected(ver, v) {
						if intel.IsMalware(v) {
							decision = types.DecisionBlock
							score = 100
							reason = "Package contains malware: " + v.ID
						} else {
							vScore := 10
							if v.Severity == "critical" {
								vScore = 70
							} else if v.Severity == "high" {
								vScore = 50
							} else if v.Severity == "medium" {
								vScore = 25
							}

							if vScore > score {
								score = vScore
								reason = fmt.Sprintf("Package has a %s vulnerability: %s", v.Severity, v.ID)
								if v.Severity == "critical" || v.Severity == "high" {
									decision = types.DecisionBlock
								} else {
									decision = types.DecisionWarn
								}
							}
						}
					}
				}
			}
		}

		if score > maxScore {
			maxScore = score
		}

		if decision == types.DecisionBlock {
			blockCount++
			findings = append(findings, ScoreLockfileFinding{
				Package:   name,
				Version:   ver,
				Decision:  "block",
				RiskScore: score,
				Reason:    reason,
			})
		} else if decision == types.DecisionWarn {
			warnCount++
			findings = append(findings, ScoreLockfileFinding{
				Package:   name,
				Version:   ver,
				Decision:  "warn",
				RiskScore: score,
				Reason:    reason,
			})
		} else {
			allowCount++
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	overallDecision := "allow"
	if blockCount > 0 {
		overallDecision = "block"
	} else if warnCount > 0 {
		overallDecision = "warn"
	}

	recommendedAction := "Lockfile looks clean and safe."
	if blockCount > 0 {
		recommendedAction = "Remove or replace blocked dependencies before proceeding."
	} else if warnCount > 0 {
		recommendedAction = "Review warnings and vulnerability findings in dependencies."
	}

	toolRes := ScoreLockfileResult{
		Ecosystem: "npm",
		Path:      p.Path,
		Decision:  overallDecision,
		RiskScore: maxScore,
		Summary: ScoreLockfileSummary{
			TotalPackages: len(packagesMap),
			Allow:         allowCount,
			Warn:          warnCount,
			Block:         blockCount,
		},
		TopFindings:       findings,
		RecommendedAction: recommendedAction,
	}

	bResult, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(bResult),
		}},
		IsError: false,
	}
}

func extractModuleName(path string) string {
	const prefix = "node_modules/"
	idx := lastIndex(path, prefix)
	if idx < 0 {
		return ""
	}
	name := path[idx+len(prefix):]
	if len(name) == 0 {
		return ""
	}
	if name[0] == '@' {
		parts := splitN(name, '/', 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	}
	parts := splitN(name, '/', 2)
	return parts[0]
}

func lastIndex(s, sep string) int {
	last := -1
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			last = i
		}
	}
	return last
}

func splitN(s string, sep byte, n int) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}
