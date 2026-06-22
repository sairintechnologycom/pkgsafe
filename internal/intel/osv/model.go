package osv

type QueryRequest struct {
	Package *Package `json:"package,omitempty"`
	Version string   `json:"version,omitempty"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl,omitempty"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Details    string        `json:"details"`
	Aliases    []string      `json:"aliases"`
	Severity   []OSVSeverity `json:"severity"`
	Affected   []Affected    `json:"affected"`
	References []Reference   `json:"references"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package           Package        `json:"package"`
	Ranges            []Range        `json:"ranges"`
	Versions          []string       `json:"versions"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
