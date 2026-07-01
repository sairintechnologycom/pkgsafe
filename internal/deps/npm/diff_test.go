package npm

import (
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestDiffInventories(t *testing.T) {
	base := []types.Dependency{
		{Ecosystem: "npm", Name: "lodash", VersionRange: "^4.17.20", SourceFile: "package.json", DependencyType: "production", Direct: true},
		{Ecosystem: "npm", Name: "express", VersionRange: "^4.18.1", SourceFile: "package.json", DependencyType: "production", Direct: true},
	}

	curr := []types.Dependency{
		{Ecosystem: "npm", Name: "lodash", VersionRange: "^4.17.21", SourceFile: "package.json", DependencyType: "production", Direct: true}, // Changed version
		{Ecosystem: "npm", Name: "axios", VersionRange: "^1.6.0", SourceFile: "package.json", DependencyType: "production", Direct: true},    // Added dependency
	}

	report := DiffInventories(base, curr)

	// lodash version changed
	if len(report.Changed) != 1 || report.Changed[0].Name != "lodash" || report.Changed[0].BaseVersion != "^4.17.20" || report.Changed[0].CurVersion != "^4.17.21" {
		t.Errorf("expected 1 changed dependency (lodash), got: %+v", report.Changed)
	}

	// axios added
	if len(report.Added) != 1 || report.Added[0].Name != "axios" {
		t.Errorf("expected 1 added dependency (axios), got: %+v", report.Added)
	}

	// express removed
	if len(report.Removed) != 1 || report.Removed[0].Name != "express" {
		t.Errorf("expected 1 removed dependency (express), got: %+v", report.Removed)
	}
}
