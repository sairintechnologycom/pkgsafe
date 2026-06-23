package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SarifDescription struct {
	Text string `json:"text"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	ShortDescription SarifDescription `json:"shortDescription"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SarifMessage      `json:"message"`
	Locations           []SarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

func ExportSarif(r *RepositoryRiskReport) (string, error) {
	var rules []SarifRule
	var results []SarifResult
	ruleSeen := make(map[string]bool)

	addRule := func(id, desc string) {
		if id == "" {
			return
		}
		if !ruleSeen[id] {
			ruleSeen[id] = true
			rules = append(rules, SarifRule{
				ID:               id,
				ShortDescription: SarifDescription{Text: desc},
			})
		}
	}

	for _, f := range r.Findings {
		if f.RuleID != "" && f.RuleID != "default_allow" {
			addRule(f.RuleID, f.Message)
			level := severityToSarifLevel(f.Severity)

			results = append(results, SarifResult{
				RuleID: f.RuleID,
				Level:  level,
				Message: SarifMessage{
					Text: fmt.Sprintf("%s in package %s@%s: %s", f.RuleID, f.Package, f.Version, f.Message),
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{URI: "package-lock.json"},
							Region: &SarifRegion{
								StartLine: 1,
							},
						},
					},
				},
				PartialFingerprints: map[string]string{
					"package": f.Package,
					"version": f.Version,
				},
			})
		}
	}

	sarif := SarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "PkgSafe",
						InformationURI: "https://github.com/niyam-ai/pkgsafe",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	b, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func severityToSarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "informational":
		return "note"
	default:
		return "note"
	}
}
