package intercept

type InstallCommand struct {
	Ecosystem        string
	PackageManager   string // "npm" or "pip"
	RawCommand       []string
	Operation        string // "install", "i", "add", "ci", etc.
	Packages         []PackageRequest
	DependencyFiles  []string // requirements.txt, package.json, etc.
	Flags            []string
	UnknownArgs      []string
	IsProjectInstall bool
	IsCIInstall      bool
}

type PackageRequest struct {
	Name             string
	VersionSpecifier string
	ExactVersion     string
	IsDevDependency  bool
	IsDirect         bool
	Source           string
}
