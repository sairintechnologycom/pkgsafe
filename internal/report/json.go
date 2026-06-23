package report

import "encoding/json"

// ExportJSON formats a report as pretty-printed JSON text.
func ExportJSON(r *RepositoryRiskReport) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
