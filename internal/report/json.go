package report

import (
	"encoding/json"

	"github.com/niyam-ai/pkgsafe/internal/registry"
)

// ExportJSON formats a report as pretty-printed JSON text.
func ExportJSON(r *RepositoryRiskReport) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return registry.RedactSecrets(string(b)), nil
}
