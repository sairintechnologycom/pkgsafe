package osv

import (
	"time"

	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/intel"
)

func MapVulnerability(v Vulnerability, packageName, ecosystem string) db.Vulnerability {
	var aliases []string
	if len(v.Aliases) > 0 {
		aliases = v.Aliases
	}

	var affectedRanges []db.Range
	var fixedVersions []string

	for _, aff := range v.Affected {
		if aff.Package.Name == packageName && aff.Package.Ecosystem == ecosystem {
			for _, r := range aff.Ranges {
				var events []db.Event
				for _, ev := range r.Events {
					events = append(events, db.Event{
						Introduced:   ev.Introduced,
						Fixed:        ev.Fixed,
						LastAffected: ev.LastAffected,
						Limit:        ev.Limit,
					})
					if ev.Fixed != "" {
						fixedVersions = append(fixedVersions, ev.Fixed)
					}
				}
				affectedRanges = append(affectedRanges, db.Range{
					Type:   r.Type,
					Events: events,
				})
			}
		}
	}

	var references []string
	for _, ref := range v.References {
		references = append(references, ref.URL)
	}

	var osvSeverities []intel.OSVSeverity
	for _, s := range v.Severity {
		osvSeverities = append(osvSeverities, intel.OSVSeverity{
			Type:  s.Type,
			Score: s.Score,
		})
	}

	var dbSpecific map[string]any
	var ecoSpecific map[string]any
	if len(v.Affected) > 0 {
		dbSpecific = v.Affected[0].DatabaseSpecific
		ecoSpecific = v.Affected[0].EcosystemSpecific
	}

	severity := intel.NormalizeSeverity(osvSeverities, dbSpecific, ecoSpecific)
	publishedAt, _ := time.Parse(time.RFC3339, v.Published)
	modifiedAt, _ := time.Parse(time.RFC3339, v.Modified)

	return db.Vulnerability{
		ID:             v.ID,
		Ecosystem:      ecosystem,
		PackageName:    packageName,
		Summary:        v.Summary,
		Details:        v.Details,
		Severity:       severity,
		Aliases:        aliases,
		AffectedRanges: affectedRanges,
		FixedVersions:  fixedVersions,
		References:     references,
		Source:         "OSV",
		PublishedAt:    publishedAt,
		ModifiedAt:     modifiedAt,
		FetchedAt:      time.Now().UTC(),
	}
}
