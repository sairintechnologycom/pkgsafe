package cargo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type Analysis struct {
	Result   types.ScanResult
	Findings []types.Reason
}

func AnalyzeDir(dir string, name, version string, pol policy.Policy) (Analysis, error) {
	pkg := types.PackageIdentity{Ecosystem: "cargo", Name: name, Version: version}
	var findings []types.Reason
	var suspicious []string

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		base := filepath.Base(path)
		lowerBase := strings.ToLower(base)

		if base == "build.rs" || strings.HasSuffix(lowerBase, ".rs") {
			b, err := os.ReadFile(path)
			if err == nil {
				content := string(b)
				contentLower := strings.ToLower(content)

				// 1. Process execution in build scripts
				if base == "build.rs" && (strings.Contains(content, "Command::new") || strings.Contains(content, "std::process")) {
					findings = risk.AddReason(findings, "pypi_setup_py_shell_execution", "build.rs compiles and executes shell processes", rel)
				}

				// 2. Network calls
				if strings.Contains(content, "TcpStream::connect") || strings.Contains(content, "reqwest::") {
					findings = risk.AddReason(findings, "network_command_in_lifecycle", "Rust source performs raw TCP connection or reqwest calls", rel)
				}

				// 3. Credential path reference
				for _, p := range []string{".aws/credentials", ".ssh/id_", ".env"} {
					if strings.Contains(contentLower, p) {
						findings = risk.AddReason(findings, "credential_path_reference", fmt.Sprintf("Rust source references protected credential path: %s", p), rel)
					}
				}

				// 4. Secret keyword reference
				for _, k := range []string{"aws_access_key_id", "github_token", "sec_"} {
					if strings.Contains(contentLower, k) {
						findings = risk.AddReason(findings, "secret_keyword_reference", fmt.Sprintf("Rust source references secret-related keyword: %s", k), rel)
					}
				}
			}
		}
		return nil
	})

	res := risk.Evaluate(pkg, findings, nil, suspicious, nil, pol)
	return Analysis{Result: res, Findings: findings}, err
}
