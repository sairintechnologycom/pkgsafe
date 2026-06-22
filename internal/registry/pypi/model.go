package pypi

import "time"

type Metadata struct {
	Info     Info              `json:"info"`
	Releases map[string][]File `json:"releases"`
	URLs     []File            `json:"urls"`
}

type Info struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Summary         string            `json:"summary"`
	Description     string            `json:"description"`
	Author          string            `json:"author"`
	AuthorEmail     string            `json:"author_email"`
	Maintainer      string            `json:"maintainer"`
	MaintainerEmail string            `json:"maintainer_email"`
	License         string            `json:"license"`
	HomePage        string            `json:"home_page"`
	ProjectURLs     map[string]string `json:"project_urls"`
	RequiresPython  string            `json:"requires_python"`
	RequiresDist    []string          `json:"requires_dist"`
	Classifiers     []string          `json:"classifiers"`
}

type File struct {
	Filename      string            `json:"filename"`
	PackageType   string            `json:"packagetype"`
	PythonVersion string            `json:"python_version"`
	URL           string            `json:"url"`
	Size          int64             `json:"size"`
	UploadTimeISO string            `json:"upload_time_iso_8601"`
	Digests       map[string]string `json:"digests"`
	Yanked        bool              `json:"yanked"`
	YankedReason  any               `json:"yanked_reason"`
}

func (f File) UploadTime() time.Time {
	if f.UploadTimeISO == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, f.UploadTimeISO)
	return t
}

type VersionMetadata struct {
	Name           string
	Version        string
	Summary        string
	Description    string
	Repository     string
	License        string
	RequiresPython string
	Dependencies   []string
	Classifiers    []string
	Files          []File
	WheelFiles     []File
	SourceFiles    []File
	Yanked         bool
	Time           time.Time
	Info           Info
}
