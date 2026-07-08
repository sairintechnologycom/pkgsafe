package golang

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
	pkg := types.PackageIdentity{Ecosystem: "go", Name: name, Version: version}
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

		if strings.HasSuffix(lowerBase, ".go") {
			b, err := os.ReadFile(path)
			if err == nil {
				content := string(b)
				contentLower := strings.ToLower(content)

				// 1. Syscall / Unsafe references
				if strings.Contains(content, "syscall.Syscall") || strings.Contains(content, "unsafe.Pointer") {
					suspicious = append(suspicious, fmt.Sprintf("%s: uses syscall/unsafe", rel))
				}

				// 2. Network calls
				if strings.Contains(content, "http.Post") || strings.Contains(content, "net.Dial") {
					findings = risk.AddReason(findings, "network_command_in_lifecycle", "Source code performs network socket or POST operations", rel)
				}

				// 3. Credential path reference
				for _, p := range []string{".aws/credentials", ".ssh/id_", ".env"} {
					if strings.Contains(contentLower, p) {
						findings = risk.AddReason(findings, "credential_path_reference", fmt.Sprintf("Source code references protected credential path: %s", p), rel)
					}
				}

				// 4. Secret keyword reference
				for _, k := range []string{"aws_access_key_id", "github_token", "sec_"} {
					if strings.Contains(contentLower, k) {
						findings = risk.AddReason(findings, "secret_keyword_reference", fmt.Sprintf("Source code references secret-related keyword: %s", k), rel)
					}
				}
			}
		}
		return nil
	})

	res := risk.Evaluate(pkg, findings, nil, suspicious, nil, pol)
	return Analysis{Result: res, Findings: findings}, err
}
