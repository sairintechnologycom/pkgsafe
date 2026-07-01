package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/registry"
	"github.com/niyam-ai/pkgsafe/internal/types"
	versionpkg "github.com/niyam-ai/pkgsafe/internal/version"
)

type Options struct {
	InputPath string
	OutputDir string
	Reason    string
	Command   string
}

type FindingFeedback struct {
	SchemaVersion            string                        `json:"schema_version"`
	FeedbackType             string                        `json:"feedback_type"`
	GeneratedAt              string                        `json:"generated_at"`
	Fingerprint              string                        `json:"fingerprint"`
	Package                  string                        `json:"package"`
	Ecosystem                string                        `json:"ecosystem"`
	Version                  string                        `json:"version,omitempty"`
	RuleIDs                  []string                      `json:"rule_ids"`
	Decision                 string                        `json:"decision"`
	RiskScore                int                           `json:"risk_score"`
	CommandUsed              string                        `json:"command_used,omitempty"`
	SanitizedFindingOutput   json.RawMessage               `json:"sanitized_finding_output"`
	UserReason               string                        `json:"user_reason,omitempty"`
	PrivateRegistryInvolved  bool                          `json:"private_registry_involved"`
	LifecycleScriptsInvolved bool                          `json:"lifecycle_scripts_involved"`
	BehaviorAnalysis         types.BehaviorAnalysisSummary `json:"behavior_analysis"`
	PkgSafeVersion           string                        `json:"pkgsafe_version"`
	PkgSafeCommit            string                        `json:"pkgsafe_commit"`
}

type Artifacts struct {
	JSONPath     string
	MarkdownPath string
	Feedback     FindingFeedback
}

type scanJSON struct {
	Ecosystem        string                        `json:"ecosystem"`
	Package          string                        `json:"package"`
	Version          string                        `json:"version"`
	Decision         string                        `json:"decision"`
	RiskScore        int                           `json:"risk_score"`
	Reasons          []types.Reason                `json:"reasons"`
	LifecycleScripts []string                      `json:"lifecycle_scripts"`
	BehaviorAnalysis types.BehaviorAnalysisSummary `json:"behavior_analysis"`
	Registry         *types.RegistryEvidence       `json:"registry"`
	PackageIdentity  types.PackageIdentity         `json:"package_identity"`
}

func Create(opts Options) (Artifacts, error) {
	if strings.TrimSpace(opts.InputPath) == "" {
		return Artifacts{}, fmt.Errorf("--input is required")
	}
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = filepath.Join(".pkgsafe", "feedback")
	}
	raw, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return Artifacts{}, fmt.Errorf("read input: %w", err)
	}
	sanitized := registry.RedactSecrets(string(raw))
	var scan scanJSON
	if err := json.Unmarshal([]byte(sanitized), &scan); err != nil {
		return Artifacts{}, fmt.Errorf("parse scan JSON: %w", err)
	}
	normalizeScan(&scan)
	if scan.Package == "" || scan.Ecosystem == "" || scan.Decision == "" {
		return Artifacts{}, fmt.Errorf("input must include package, ecosystem, and decision fields")
	}
	ruleIDs := ruleIDs(scan.Reasons)
	feedback := FindingFeedback{
		SchemaVersion:            "1.0",
		FeedbackType:             "false_positive",
		GeneratedAt:              time.Now().UTC().Format(time.RFC3339),
		Package:                  scan.Package,
		Ecosystem:                scan.Ecosystem,
		Version:                  scan.Version,
		RuleIDs:                  ruleIDs,
		Decision:                 scan.Decision,
		RiskScore:                scan.RiskScore,
		CommandUsed:              registry.RedactSecrets(opts.Command),
		SanitizedFindingOutput:   json.RawMessage(sanitizedJSON([]byte(sanitized))),
		UserReason:               registry.RedactSecrets(opts.Reason),
		PrivateRegistryInvolved:  privateRegistryInvolved(scan.Registry),
		LifecycleScriptsInvolved: len(scan.LifecycleScripts) > 0,
		BehaviorAnalysis:         scan.BehaviorAnalysis,
		PkgSafeVersion:           versionpkg.Version,
		PkgSafeCommit:            versionpkg.Commit,
	}
	feedback.Fingerprint = Fingerprint(feedback)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return Artifacts{}, fmt.Errorf("create output directory: %w", err)
	}
	base := safeName(fmt.Sprintf("%s-%s-%s", feedback.Ecosystem, feedback.Package, feedback.Fingerprint[:12]))
	jsonPath := filepath.Join(outputDir, base+".json")
	mdPath := filepath.Join(outputDir, base+".md")
	b, err := json.MarshalIndent(feedback, "", "  ")
	if err != nil {
		return Artifacts{}, err
	}
	b = append(b, '\n')
	if err := os.WriteFile(jsonPath, []byte(registry.RedactSecrets(string(b))), 0o644); err != nil {
		return Artifacts{}, fmt.Errorf("write feedback JSON: %w", err)
	}
	if err := os.WriteFile(mdPath, []byte(registry.RedactSecrets(RenderMarkdown(feedback))), 0o644); err != nil {
		return Artifacts{}, fmt.Errorf("write feedback Markdown: %w", err)
	}
	return Artifacts{JSONPath: jsonPath, MarkdownPath: mdPath, Feedback: feedback}, nil
}

func Fingerprint(f FindingFeedback) string {
	parts := []string{
		strings.ToLower(f.Ecosystem),
		strings.ToLower(f.Package),
		f.Version,
		strings.ToLower(f.Decision),
		fmt.Sprintf("%d", f.RiskScore),
	}
	ids := append([]string(nil), f.RuleIDs...)
	sort.Strings(ids)
	parts = append(parts, ids...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func RenderMarkdown(f FindingFeedback) string {
	var b strings.Builder
	fmt.Fprintln(&b, "## False Positive Feedback")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Package: `%s`\n", f.Package)
	fmt.Fprintf(&b, "- Ecosystem: `%s`\n", f.Ecosystem)
	if f.Version != "" {
		fmt.Fprintf(&b, "- Version: `%s`\n", f.Version)
	}
	fmt.Fprintf(&b, "- Decision: `%s`\n", f.Decision)
	fmt.Fprintf(&b, "- Risk score: `%d`\n", f.RiskScore)
	fmt.Fprintf(&b, "- Rule IDs: `%s`\n", strings.Join(f.RuleIDs, ", "))
	fmt.Fprintf(&b, "- Fingerprint: `%s`\n", f.Fingerprint)
	fmt.Fprintf(&b, "- Lifecycle scripts involved: `%t`\n", f.LifecycleScriptsInvolved)
	fmt.Fprintf(&b, "- Private registry involved: `%t`\n", f.PrivateRegistryInvolved)
	if f.CommandUsed != "" {
		fmt.Fprintf(&b, "- Command used: `%s`\n", f.CommandUsed)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### Why This Is Believed Safe")
	fmt.Fprintln(&b)
	if strings.TrimSpace(f.UserReason) == "" {
		fmt.Fprintln(&b, "_Add maintainer/source review context here before filing._")
	} else {
		fmt.Fprintln(&b, f.UserReason)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### Sanitized Scan Output")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "```json")
	if len(f.SanitizedFindingOutput) > 0 {
		fmt.Fprintln(&b, string(f.SanitizedFindingOutput))
	} else {
		fmt.Fprintln(&b, "{}")
	}
	fmt.Fprintln(&b, "```")
	return b.String()
}

func normalizeScan(scan *scanJSON) {
	if scan.Package == "" {
		scan.Package = scan.PackageIdentity.Name
	}
	if scan.Ecosystem == "" {
		scan.Ecosystem = scan.PackageIdentity.Ecosystem
	}
	if scan.Version == "" {
		scan.Version = scan.PackageIdentity.Version
	}
}

func privateRegistryInvolved(reg *types.RegistryEvidence) bool {
	if reg == nil {
		return false
	}
	if strings.EqualFold(reg.Type, "private") {
		return true
	}
	return reg.URL != "" || reg.AuthMethod != ""
}

func ruleIDs(reasons []types.Reason) []string {
	seen := map[string]bool{}
	var ids []string
	for _, reason := range reasons {
		if reason.ID == "" || seen[reason.ID] {
			continue
		}
		seen[reason.ID] = true
		ids = append(ids, reason.ID)
	}
	sort.Strings(ids)
	return ids
}

func sanitizedJSON(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("{}")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return b
}

func safeName(name string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", "@", "", ":", "-", " ", "-")
	name = strings.Trim(replacer.Replace(name), ".-")
	if name == "" {
		return "feedback"
	}
	return name
}
