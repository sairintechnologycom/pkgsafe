package types

type Dependency struct {
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"package_name"`
	VersionRange   string `json:"version_range"`
	SourceFile     string `json:"source_file"`
	DependencyType string `json:"dependency_type"` // production, dev, peer, optional, bundled, transitive, source-import
	Direct         bool   `json:"direct"`
	Dev            bool   `json:"dev,omitempty"`
	Optional       bool   `json:"optional,omitempty"`
	Resolved       string `json:"resolved,omitempty"`
	Integrity      string `json:"integrity,omitempty"`
	PackagePath    string `json:"package_path,omitempty"`
}
