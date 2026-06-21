package npm

import (
	"fmt"
	"os"
	"path/filepath"

	anpm "github.com/niyam-ai/pkgsafe/internal/analyzer/npm"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	rnpm "github.com/niyam-ai/pkgsafe/internal/registry/npm"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Scanner struct {
	Registry rnpm.Client
	Policy   policy.Policy
	CacheDir string
}

func New() Scanner {
	return Scanner{
		Registry: rnpm.NewClient(""),
		Policy:   policy.Default(),
	}
}

func (s Scanner) ScanPackage(name, version string) (types.ScanResult, error) {
	if name == "" {
		return types.ScanResult{}, fmt.Errorf("package name is required")
	}
	pol := s.Policy
	if pol.Mode == "" {
		pol = policy.Default()
	}

	md, err := s.Registry.FetchMetadata(name)
	if err != nil {
		return types.ScanResult{}, err
	}
	vm, err := rnpm.ResolveVersion(md, version)
	if err != nil {
		return types.ScanResult{}, err
	}
	if vm.Dist.Tarball == "" {
		return types.ScanResult{}, fmt.Errorf("missing tarball URL for %s@%s", name, vm.Version)
	}

	tarballPath, err := s.Registry.DownloadTarball(vm.Dist.Tarball, s.CacheDir)
	if err != nil {
		return types.ScanResult{}, err
	}
	if err := rnpm.VerifyTarballIntegrity(tarballPath, vm.Dist.Integrity, vm.Dist.Shasum); err != nil {
		return types.ScanResult{}, err
	}
	tmp, err := os.MkdirTemp("", "pkgsafe-npm-*")
	if err != nil {
		return types.ScanResult{}, err
	}
	defer os.RemoveAll(tmp)

	if err := rnpm.ExtractTarball(tarballPath, tmp); err != nil {
		return types.ScanResult{}, err
	}
	pkgJSON, err := rnpm.LocatePackageJSON(tmp)
	if err != nil {
		return types.ScanResult{}, err
	}
	res, err := anpm.AnalyzePackageDir(filepath.Dir(pkgJSON), pol)
	if err != nil {
		return types.ScanResult{}, err
	}
	if res.Package.Name == "" || res.Package.Name == "unknown" {
		res.Package.Name = name
	}
	if vm.Version != "" {
		res.Package.Version = vm.Version
	}
	return res, nil
}

func ScanPackage(name, version string) (types.ScanResult, error) {
	return New().ScanPackage(name, version)
}
