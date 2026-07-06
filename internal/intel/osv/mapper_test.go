package osv

import (
	"testing"
	"time"
)

// TestMapVulnerabilityFullRecord exercises the happy path: a matching affected
// entry contributes ranges, events, and fixed versions; aliases, references,
// and timestamps are carried through; source is stamped "OSV".
func TestMapVulnerabilityFullRecord(t *testing.T) {
	v := Vulnerability{
		ID:      "GHSA-abcd",
		Summary: "prototype pollution",
		Details: "details here",
		Aliases: []string{"CVE-2021-0001"},
		Severity: []OSVSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []Affected{
			{
				Package: Package{Name: "lodash", Ecosystem: "npm"},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
		},
		References: []Reference{
			{Type: "WEB", URL: "https://example.com/advisory"},
		},
		Published: "2021-02-15T00:00:00Z",
		Modified:  "2021-03-01T00:00:00Z",
	}

	got := MapVulnerability(v, "lodash", "npm")

	if got.ID != "GHSA-abcd" || got.PackageName != "lodash" || got.Ecosystem != "npm" {
		t.Fatalf("identity mismatch: %+v", got)
	}
	if got.Source != "OSV" {
		t.Errorf("Source = %q, want OSV", got.Source)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "CVE-2021-0001" {
		t.Errorf("aliases not carried: %v", got.Aliases)
	}
	if len(got.References) != 1 || got.References[0] != "https://example.com/advisory" {
		t.Errorf("references not flattened to URLs: %v", got.References)
	}
	if len(got.AffectedRanges) != 1 || got.AffectedRanges[0].Type != "SEMVER" {
		t.Fatalf("affected ranges not mapped: %+v", got.AffectedRanges)
	}
	if len(got.AffectedRanges[0].Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(got.AffectedRanges[0].Events))
	}
	if len(got.FixedVersions) != 1 || got.FixedVersions[0] != "4.17.21" {
		t.Errorf("fixed versions not collected from events: %v", got.FixedVersions)
	}
	if got.PublishedAt.IsZero() || got.PublishedAt.Year() != 2021 {
		t.Errorf("published timestamp not parsed: %v", got.PublishedAt)
	}
	if got.ModifiedAt.IsZero() {
		t.Errorf("modified timestamp not parsed: %v", got.ModifiedAt)
	}
	if got.FetchedAt.IsZero() || time.Since(got.FetchedAt) > time.Hour {
		t.Errorf("FetchedAt should be stamped ~now, got %v", got.FetchedAt)
	}
}

// TestMapVulnerabilityFiltersOtherPackages ensures affected entries for a
// different package or ecosystem do not leak into the mapped ranges — the
// caller resolves per (package, ecosystem).
func TestMapVulnerabilityFiltersOtherPackages(t *testing.T) {
	v := Vulnerability{
		ID: "GHSA-multi",
		Affected: []Affected{
			{
				Package: Package{Name: "lodash", Ecosystem: "npm"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Fixed: "4.17.21"}}}},
			},
			{
				// Same name, different ecosystem — must be excluded.
				Package: Package{Name: "lodash", Ecosystem: "PyPI"},
				Ranges:  []Range{{Type: "ECOSYSTEM", Events: []Event{{Fixed: "9.9.9"}}}},
			},
			{
				// Different name, same ecosystem — must be excluded.
				Package: Package{Name: "underscore", Ecosystem: "npm"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Fixed: "1.0.0"}}}},
			},
		},
	}

	got := MapVulnerability(v, "lodash", "npm")

	if len(got.AffectedRanges) != 1 {
		t.Fatalf("expected exactly 1 range from the matching package, got %d", len(got.AffectedRanges))
	}
	if len(got.FixedVersions) != 1 || got.FixedVersions[0] != "4.17.21" {
		t.Errorf("fixed versions leaked from non-matching packages: %v", got.FixedVersions)
	}
}

// TestMapVulnerabilityNonFixedEvents verifies that last_affected / limit events
// (no Fixed field) map into events but contribute no fixed versions.
func TestMapVulnerabilityNonFixedEvents(t *testing.T) {
	v := Vulnerability{
		ID: "GHSA-nofix",
		Affected: []Affected{
			{
				Package: Package{Name: "left-pad", Ecosystem: "npm"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "1.0.0"}, {LastAffected: "1.2.0"}}},
				},
			},
		},
	}

	got := MapVulnerability(v, "left-pad", "npm")

	if len(got.AffectedRanges) != 1 || len(got.AffectedRanges[0].Events) != 2 {
		t.Fatalf("events not preserved: %+v", got.AffectedRanges)
	}
	if len(got.FixedVersions) != 0 {
		t.Errorf("expected no fixed versions without a Fixed event, got %v", got.FixedVersions)
	}
}

// TestMapVulnerabilityMinimalRecord confirms an advisory with no affected
// entries and unparseable timestamps degrades to safe zero values rather than
// panicking.
func TestMapVulnerabilityMinimalRecord(t *testing.T) {
	v := Vulnerability{ID: "GHSA-min", Published: "not-a-date"}

	got := MapVulnerability(v, "pkg", "npm")

	if got.ID != "GHSA-min" {
		t.Fatalf("ID lost: %+v", got)
	}
	if len(got.AffectedRanges) != 0 || len(got.FixedVersions) != 0 || len(got.Aliases) != 0 {
		t.Errorf("expected empty slices for a minimal record, got %+v", got)
	}
	if !got.PublishedAt.IsZero() {
		t.Errorf("unparseable timestamp should yield zero time, got %v", got.PublishedAt)
	}
}
