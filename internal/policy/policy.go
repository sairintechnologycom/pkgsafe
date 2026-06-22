package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Mode string

const (
	ModeWarn  Mode = "warn"
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)

type Rule struct {
	Enabled    bool
	Severity   string
	Score      int
	MaxAgeDays int
}

type PackageLists struct {
	NPM []string
}

type Policy struct {
	Mode            Mode
	Thresholds      types.Thresholds
	ProtectedPaths  []string
	TrustedPackages PackageLists
	BlockedPackages PackageLists
	Rules           map[string]Rule
	BlockPatterns   []string
	WarnPatterns    []string
}

func Default() Policy {
	return Policy{
		Mode: ModeWarn,
		Thresholds: types.Thresholds{
			AllowMaxScore: 29,
			WarnMaxScore:  69,
			BlockMinScore: 70,
		},
		ProtectedPaths: []string{
			"~/.aws", "~/.azure", "~/.gcp", "~/.ssh", "~/.kube",
			"~/.npmrc", "~/.pypirc", ".env", ".env.local", ".vault-token",
		},
		TrustedPackages: PackageLists{NPM: []string{"lodash", "axios", "react", "express", "typescript"}},
		BlockedPackages: PackageLists{NPM: []string{}},
		Rules: map[string]Rule{
			"lifecycle_script_present":     {Enabled: true, Severity: "medium", Score: 20},
			"network_command_in_lifecycle": {Enabled: true, Severity: "high", Score: 30},
			"credential_path_reference":    {Enabled: true, Severity: "critical", Score: 100},
			"secret_keyword_reference":     {Enabled: true, Severity: "high", Score: 35},
			"obfuscated_script":            {Enabled: true, Severity: "high", Score: 25},
			"typosquat_candidate":          {Enabled: true, Severity: "high", Score: 25},
			"missing_repository":           {Enabled: true, Severity: "low", Score: 10},
			"missing_license":              {Enabled: true, Severity: "low", Score: 5},
			"new_package":                  {Enabled: true, Severity: "medium", Score: 15, MaxAgeDays: 14},
			"trusted_package_reduction":    {Enabled: true, Severity: "informational", Score: -20},
			"blocked_package":              {Enabled: true, Severity: "critical", Score: 100},
			"known_vulnerability_critical": {Enabled: true, Severity: "critical", Score: 70},
			"known_vulnerability_high":     {Enabled: true, Severity: "high", Score: 50},
			"known_vulnerability_medium":   {Enabled: true, Severity: "medium", Score: 25},
			"known_vulnerability_low":      {Enabled: true, Severity: "low", Score: 10},
			"known_malware_indicator":      {Enabled: true, Severity: "critical", Score: 100},
		},
		BlockPatterns: []string{
			"~/.aws", "~/.azure", "~/.gcp", "~/.ssh", "~/.kube", "~/.npmrc", "~/.pypirc",
			".aws", ".azure", ".gcp", ".ssh", ".kube", ".npmrc", ".pypirc",
			".env", ".env.local", ".vault-token", "id_rsa", "credentials",
		},
		WarnPatterns: []string{
			"curl", "wget", "invoke-webrequest", "http://", "https://", "bash -c", "sh -c",
			"base64", "eval", "child_process", "powershell", "netcat", " nc ",
			"aws_access_key_id", "aws_secret_access_key", "github_token", "vault_token", "token", "secret",
		},
	}
}

func Load(path string) (Policy, error) {
	if strings.TrimSpace(path) == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("load policy %q: %w", path, err)
	}
	pol := Default()
	if err := parseYAMLPolicy(string(b), &pol); err != nil {
		return Policy{}, fmt.Errorf("parse policy %q: %w", path, err)
	}
	if err := Validate(pol); err != nil {
		return Policy{}, fmt.Errorf("invalid policy %q: %w", path, err)
	}
	return pol, nil
}

func Validate(pol Policy) error {
	if pol.Mode != ModeAudit && pol.Mode != ModeWarn && pol.Mode != ModeBlock {
		return fmt.Errorf("mode must be one of audit, warn, block")
	}
	t := pol.Thresholds
	if t.AllowMaxScore < 0 || t.WarnMaxScore < 0 || t.BlockMinScore < 0 ||
		t.AllowMaxScore > 100 || t.WarnMaxScore > 100 || t.BlockMinScore > 100 {
		return fmt.Errorf("thresholds must be between 0 and 100")
	}
	if !(t.AllowMaxScore < t.WarnMaxScore && t.WarnMaxScore < t.BlockMinScore) {
		return fmt.Errorf("thresholds must satisfy allow_max_score < warn_max_score < block_min_score")
	}
	for id, rule := range pol.Rules {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("rule id cannot be empty")
		}
		if strings.TrimSpace(rule.Severity) == "" {
			return fmt.Errorf("rule %s severity is required", id)
		}
	}
	return nil
}

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block":
		return ModeBlock
	case "audit":
		return ModeAudit
	case "warn", "":
		return ModeWarn
	default:
		return Mode(strings.ToLower(strings.TrimSpace(s)))
	}
}

func ApplyMode(pol Policy, mode string) (Policy, error) {
	if strings.TrimSpace(mode) == "" {
		return pol, nil
	}
	parsed := ParseMode(mode)
	if parsed != ModeAudit && parsed != ModeWarn && parsed != ModeBlock {
		return Policy{}, fmt.Errorf("mode must be one of audit, warn, block")
	}
	pol.Mode = parsed
	return pol, nil
}

func IsTrusted(pol Policy, ecosystem, name string) bool {
	return containsPackage(listForEcosystem(pol.TrustedPackages, ecosystem), name)
}

func IsBlocked(pol Policy, ecosystem, name string) bool {
	return containsPackage(listForEcosystem(pol.BlockedPackages, ecosystem), name)
}

func RuleFor(pol Policy, id string) (Rule, bool) {
	rule, ok := pol.Rules[id]
	return rule, ok && rule.Enabled
}

func listForEcosystem(l PackageLists, ecosystem string) []string {
	if ecosystem == "npm" {
		return l.NPM
	}
	return nil
}

func containsPackage(packages []string, name string) bool {
	for _, pkg := range packages {
		if strings.EqualFold(strings.TrimSpace(pkg), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func parseYAMLPolicy(raw string, pol *Policy) error {
	var section, subsection, ruleID string
	var hasProtectedPaths bool
	for lineNo, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimRight(rawLine, " \t\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "- ") {
			item := unquote(strings.TrimSpace(strings.TrimPrefix(text, "- ")))
			switch {
			case section == "protected_paths":
				pol.ProtectedPaths = append(pol.ProtectedPaths, item)
			case section == "trusted_packages" && subsection == "npm":
				pol.TrustedPackages.NPM = append(pol.TrustedPackages.NPM, item)
			case section == "blocked_packages" && subsection == "npm":
				pol.BlockedPackages.NPM = append(pol.BlockedPackages.NPM, item)
			default:
				return fmt.Errorf("line %d: list item is not under a supported list", lineNo+1)
			}
			continue
		}
		key, val, ok := strings.Cut(text, ":")
		if !ok {
			return fmt.Errorf("line %d: expected key: value", lineNo+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if indent == 0 {
			section, subsection, ruleID = key, "", ""
			switch key {
			case "mode":
				pol.Mode = ParseMode(unquote(val))
			case "thresholds", "rules":
			case "protected_paths":
				pol.ProtectedPaths = nil
				pol.BlockPatterns = nil
				hasProtectedPaths = true
			case "trusted_packages":
				pol.TrustedPackages = PackageLists{}
			case "blocked_packages":
				pol.BlockedPackages = PackageLists{}
			default:
				return fmt.Errorf("line %d: unsupported top-level key %q", lineNo+1, key)
			}
			continue
		}
		switch section {
		case "thresholds":
			n, err := strconv.Atoi(unquote(val))
			if err != nil {
				return fmt.Errorf("line %d: threshold %s must be an integer", lineNo+1, key)
			}
			switch key {
			case "allow_max_score":
				pol.Thresholds.AllowMaxScore = n
			case "warn_max_score":
				pol.Thresholds.WarnMaxScore = n
			case "block_min_score":
				pol.Thresholds.BlockMinScore = n
			default:
				return fmt.Errorf("line %d: unsupported threshold %q", lineNo+1, key)
			}
		case "trusted_packages", "blocked_packages":
			if indent == 2 && val == "" {
				subsection = key
			} else if indent == 2 && val == "[]" {
				subsection = key
			} else {
				return fmt.Errorf("line %d: expected ecosystem list", lineNo+1)
			}
		case "rules":
			if indent == 2 && val == "" {
				ruleID = key
				if pol.Rules == nil {
					pol.Rules = map[string]Rule{}
				}
				if _, ok := pol.Rules[ruleID]; !ok {
					pol.Rules[ruleID] = Rule{}
				}
				continue
			}
			if indent != 4 || ruleID == "" {
				return fmt.Errorf("line %d: expected rule property", lineNo+1)
			}
			rule := pol.Rules[ruleID]
			switch key {
			case "enabled":
				rule.Enabled = strings.EqualFold(unquote(val), "true")
			case "severity":
				rule.Severity = unquote(val)
			case "score":
				n, err := strconv.Atoi(unquote(val))
				if err != nil {
					return fmt.Errorf("line %d: score must be an integer", lineNo+1)
				}
				rule.Score = n
			case "max_age_days":
				n, err := strconv.Atoi(unquote(val))
				if err != nil {
					return fmt.Errorf("line %d: max_age_days must be an integer", lineNo+1)
				}
				rule.MaxAgeDays = n
			default:
				return fmt.Errorf("line %d: unsupported rule property %q", lineNo+1, key)
			}
			pol.Rules[ruleID] = rule
		default:
			return fmt.Errorf("line %d: unsupported section %q", lineNo+1, section)
		}
	}
	if hasProtectedPaths {
		pol.BlockPatterns = deriveBlockPatterns(pol.ProtectedPaths)
	}
	return nil
}

func deriveBlockPatterns(paths []string) []string {
	seen := make(map[string]bool)
	var bp []string
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !seen[path] {
			seen[path] = true
			bp = append(bp, path)
		}
		if strings.HasPrefix(path, "~/") {
			unprefixed := strings.TrimPrefix(path, "~/")
			if unprefixed != "" && !seen[unprefixed] {
				seen[unprefixed] = true
				bp = append(bp, unprefixed)
			}
		}
		if strings.Contains(path, ".ssh") {
			if !seen["id_rsa"] {
				seen["id_rsa"] = true
				bp = append(bp, "id_rsa")
			}
		}
		if strings.Contains(path, ".aws") {
			if !seen["credentials"] {
				seen["credentials"] = true
				bp = append(bp, "credentials")
			}
		}
	}
	return bp
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	return s
}
