package intel_test

import (
	"encoding/json"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/intel"
	"github.com/niyam-ai/pkgsafe/internal/intel/osv"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		name        string
		osvSeverity []intel.OSVSeverity
		dbSpecific  map[string]any
		ecoSpecific map[string]any
		expected    string
	}{
		{
			name: "severity from dbSpecific",
			dbSpecific: map[string]any{
				"severity": "HIGH",
			},
			expected: "high",
		},
		{
			name: "severity from ecoSpecific",
			ecoSpecific: map[string]any{
				"severity": "critical",
			},
			expected: "critical",
		},
		{
			name: "nested cvss score",
			dbSpecific: map[string]any{
				"cvss": map[string]any{
					"score": 5.4,
				},
			},
			expected: "medium",
		},
		{
			name: "nested cvss score critical",
			dbSpecific: map[string]any{
				"cvss": map[string]any{
					"score": 9.8,
				},
			},
			expected: "critical",
		},
		{
			name: "nested cvss severity",
			dbSpecific: map[string]any{
				"cvss": map[string]any{
					"severity": "low",
				},
			},
			expected: "low",
		},
		{
			name: "from osvSeverity CVSS vector high",
			osvSeverity: []intel.OSVSeverity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
			expected: "high",
		},
		{
			name:     "fallback default",
			expected: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intel.NormalizeSeverity(tt.osvSeverity, tt.dbSpecific, tt.ecoSpecific)
			if got != tt.expected {
				t.Errorf("NormalizeSeverity() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestIsVersionAffected(t *testing.T) {
	vuln := db.Vulnerability{
		ID:          "GHSA-123",
		Ecosystem:   "npm",
		PackageName: "lodash",
		AffectedRanges: []db.Range{
			{
				Type: "SEMVER",
				Events: []db.Event{
					{Introduced: "0", Fixed: "4.17.21"},
				},
			},
		},
	}

	tests := []struct {
		version  string
		expected bool
	}{
		{"4.17.20", true},
		{"4.17.21", false},
		{"4.18.0", false},
		{"0.0.1", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := intel.IsVersionAffected(tt.version, vuln)
			if got != tt.expected {
				t.Errorf("IsVersionAffected(%q) = %v, expected %v", tt.version, got, tt.expected)
			}
		})
	}
}

func TestIsMalware(t *testing.T) {
	tests := []struct {
		id       string
		summary  string
		expected bool
	}{
		{"MAL-123", "Malicious package containing malware", true},
		{"GHSA-123", "Prototype pollution backdoor in npm package", true},
		{"CVE-2026-999", "Regular buffer overflow", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			v := db.Vulnerability{ID: tt.id, Summary: tt.summary}
			got := intel.IsMalware(v)
			if got != tt.expected {
				t.Errorf("IsMalware(%q, %q) = %v, expected %v", tt.id, tt.summary, got, tt.expected)
			}
		})
	}
}

func TestMapVulnerability(t *testing.T) {
	rawJSON := `{
		"id": "GHSA-123",
		"summary": "Prototype pollution",
		"details": "Detailed advisory text",
		"published": "2024-01-02T03:04:05Z",
		"modified": "2024-02-03T04:05:06Z",
		"aliases": ["CVE-456"],
		"affected": [
			{
				"package": {
					"name": "lodash",
					"ecosystem": "npm"
				},
				"ranges": [
					{
						"type": "SEMVER",
						"events": [
							{"introduced": "0"},
							{"fixed": "4.17.21"}
						]
					}
				],
				"database_specific": {
					"severity": "HIGH"
				}
			}
		]
	}`

	var raw osv.Vulnerability
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		t.Fatal(err)
	}

	mapped := osv.MapVulnerability(raw, "lodash", "npm")

	if mapped.ID != "GHSA-123" {
		t.Errorf("expected ID GHSA-123, got %s", mapped.ID)
	}
	if mapped.Severity != "high" {
		t.Errorf("expected severity high, got %s", mapped.Severity)
	}
	if len(mapped.Aliases) != 1 || mapped.Aliases[0] != "CVE-456" {
		t.Errorf("unexpected aliases: %v", mapped.Aliases)
	}
	if len(mapped.AffectedRanges) != 1 || mapped.AffectedRanges[0].Type != "SEMVER" {
		t.Errorf("unexpected ranges: %+v", mapped.AffectedRanges)
	}
	if mapped.Details != "Detailed advisory text" || mapped.PublishedAt.IsZero() || mapped.ModifiedAt.IsZero() {
		t.Errorf("expected advisory metadata to be mapped, got %+v", mapped)
	}
	if len(mapped.FixedVersions) != 1 || mapped.FixedVersions[0] != "4.17.21" {
		t.Errorf("expected fixed version 4.17.21, got %v", mapped.FixedVersions)
	}
}
