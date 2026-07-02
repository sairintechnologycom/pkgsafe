package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

func cmdPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe policy [validate|explain|test]")
	}

	switch args[0] {
	case "validate":
		if len(args) < 2 {
			return fmt.Errorf("usage: pkgsafe policy validate <path>")
		}
		path := args[1]
		_, err := policy.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			return exitError{code: 1, err: err}
		}
		fmt.Println("Policy is valid.")
		return nil

	case "explain":
		if len(args) < 2 {
			return fmt.Errorf("usage: pkgsafe policy explain <path>")
		}
		path := args[1]
		pol, err := policy.Load(path)
		if err != nil {
			return err
		}

		// Count entries
		npmTrusted := 0
		pypiTrusted := 0
		for _, r := range pol.TrustedPackageRules {
			if strings.Contains(r.Name, "@") || strings.Contains(r.Name, "/") {
				npmTrusted++ // rough heuristic, let's also support clean separation if loaded from trusted-packages.yaml
			} else {
				pypiTrusted++
			}
		}
		if npmTrusted == 0 && len(pol.TrustedPackages.NPM) > 0 {
			npmTrusted = len(pol.TrustedPackages.NPM)
		}
		if pypiTrusted == 0 && len(pol.TrustedPackages.PyPI) > 0 {
			pypiTrusted = len(pol.TrustedPackages.PyPI)
		}

		npmBlocked := len(pol.BlockedPackages.NPM)
		pypiBlocked := len(pol.BlockedPackages.PyPI)

		fmt.Printf(`PkgSafe Policy Summary

Policy: %s
Schema Version: %s
Mode: %s
Owner: %s
Version: %s

Thresholds:
- Allow: 0-%d
- Warn: %d-%d
- Block: %d-100

Ecosystems:
- npm: %s
- pypi: %s

Registries:
- npm public: enabled
- npm internal: enabled
- PyPI public: enabled
- PyPI internal: enabled

Controls:
- Known malware always blocked
- Credential access always blocked
- AI-agent warn requires confirmation
- Force risk accept: %s
- Force risk accept requires reason: %s
- Override audit log: %s
- Private registry packages: trusted only when registry matches approved source
- Hard-block rules: enforced

Trusted packages:
- npm: %d entries
- pypi: %d entries

Blocked packages:
- npm: %d entries
- pypi: %d entries

Active exceptions:
- %d entries
`,
			nonEmpty(pol.PolicyPackName, "enterprise-standard"),
			nonEmpty(pol.SchemaVersion, "1.0"),
			pol.Mode,
			nonEmpty(pol.PolicyPackOwner, "Platform Engineering"),
			nonEmpty(pol.PolicyPackVersion, "2026.06.01"),
			pol.Thresholds.AllowMaxScore,
			pol.Thresholds.AllowMaxScore+1,
			pol.Thresholds.WarnMaxScore,
			pol.Thresholds.BlockMinScore,
			boolEnabled(pol.Ecosystems.NPM.Enabled),
			boolEnabled(pol.Ecosystems.PyPI.Enabled),
			boolEnabled(pol.InstallInterception.AllowForceRiskAccept),
			boolEnabled(pol.InstallInterception.ForceRiskAcceptRequiresReason),
			registry.RedactSecrets(nonEmpty(pol.InstallInterception.AuditLogPath, "disabled")),
			npmTrusted,
			pypiTrusted,
			npmBlocked,
			pypiBlocked,
			len(pol.Exceptions),
		)
		return nil

	case "test":
		return cmdPolicyTest(args[1:])

	case "pack":
		return fmt.Errorf("signed policy archive commands are private-enterprise functionality; use pkgsafe-enterprise")
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

type policyTestResult struct {
	Path          string `json:"path"`
	ExpectedValid bool   `json:"expected_valid"`
	Passed        bool   `json:"passed"`
	Error         string `json:"error,omitempty"`
}

func cmdPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy-test", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: pkgsafe policy test [--json] <file-or-dir>")
	}
	results, err := runPolicyTests(fs.Arg(0))
	if err != nil {
		return err
	}
	allPassed := true
	for _, result := range results {
		if !result.Passed {
			allPassed = false
			break
		}
	}
	if *asJSON {
		b, err := json.MarshalIndent(struct {
			Pass    bool               `json:"pass"`
			Results []policyTestResult `json:"results"`
		}{Pass: allPassed, Results: results}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		for _, result := range results {
			status := "PASS"
			if !result.Passed {
				status = "FAIL"
			}
			expectation := "valid"
			if !result.ExpectedValid {
				expectation = "invalid"
			}
			fmt.Printf("[%s] %s expected=%s", status, result.Path, expectation)
			if result.Error != "" {
				fmt.Printf(" error=%s", result.Error)
			}
			fmt.Println()
		}
	}
	if !allPassed {
		return exitError{code: 1, err: fmt.Errorf("policy fixture tests failed")}
	}
	return nil
}

func runPolicyTests(path string) ([]policyTestResult, error) {
	var files []string
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yaml" || ext == ".yml" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = append(files, path)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no policy fixtures found in %s", path)
	}
	var results []policyTestResult
	for _, file := range files {
		base := filepath.Base(file)
		expectedValid := !(strings.HasPrefix(base, "invalid-") || strings.Contains(base, ".invalid."))
		_, err := policy.Load(file)
		result := policyTestResult{Path: file, ExpectedValid: expectedValid}
		if err != nil {
			result.Error = registry.RedactSecrets(err.Error())
		}
		result.Passed = (err == nil) == expectedValid
		results = append(results, result)
	}
	return results, nil
}

func cmdRegistry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe registry [list|test|auth]")
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("registry-list", flag.ContinueOnError)
		policyPath := fs.String("policy", "", "path to policy file")
		registryConfig := fs.String("registry-config", "", "path to registries.yaml")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pol, err := policy.ResolvePolicy("", "", *policyPath, "", *registryConfig)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tECOSYSTEM\tTYPE\tURL\tAUTH METHOD")
		for eco, regs := range pol.Registries.Registries {
			for name, cfg := range regs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, eco, cfg.Type, registry.RedactURL(cfg.URL), cfg.Auth.Method)
			}
		}
		w.Flush()
		return nil

	case "test":
		fs := flag.NewFlagSet("registry-test", flag.ContinueOnError)
		policyPath := fs.String("policy", "", "path to policy file")
		registryConfig := fs.String("registry-config", "", "path to registries.yaml")
		ecosystem := fs.String("ecosystem", "", "ecosystem for package routing test: npm or pypi")
		packageName := fs.String("package", "", "package name for routing test")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pol, err := policy.ResolvePolicy("", "", *policyPath, "", *registryConfig)
		if err != nil {
			return err
		}
		if *packageName != "" || *ecosystem != "" {
			if *packageName == "" || *ecosystem == "" {
				return fmt.Errorf("usage: pkgsafe registry test --ecosystem <npm|pypi> --package <name>")
			}
			res, err := registry.TestPackageRouting(*ecosystem, *packageName, pol)
			if err != nil {
				return err
			}
			fmt.Printf("Registry Routing Test: %s/%s\n\n", res.Ecosystem, res.Package)
			if res.NormalizedName != "" {
				fmt.Printf("Normalized Package: %s\n", res.NormalizedName)
			}
			fmt.Printf("Resolved Registry: %s\n", res.RegistryName)
			fmt.Printf("Registry Type: %s\n", res.RegistryType)
			fmt.Printf("Registry URL: %s\n", res.RegistryURL)
			fmt.Printf("Private Match: %s\n", boolEnabled(res.PrivateMatch))
			if res.PrivateRegistry != "" {
				fmt.Printf("Private Registry: %s\n", res.PrivateRegistry)
			}
			fmt.Printf("Public Fallback: %s\n", boolEnabled(res.PublicFallback))
			fmt.Printf("Status: %s\n", res.Status)
			if res.Reason != "" {
				fmt.Printf("Reason: %s\n", registry.RedactSecrets(res.Reason))
			}
			if res.Status != "OK" {
				return exitError{code: 1, err: fmt.Errorf("registry routing test failed")}
			}
			return nil
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: pkgsafe registry test <name> OR pkgsafe registry test --ecosystem <npm|pypi> --package <name>")
		}
		name := fs.Arg(0)
		res, err := registry.TestRegistry(name, pol)
		if err != nil {
			return err
		}

		fmt.Printf("Registry Test: %s\n\n", res.Name)
		fmt.Printf("Type: %s\n", res.Type)
		fmt.Printf("URL: %s\n", res.URL)
		fmt.Printf("Auth Method: %s\n", res.AuthMethod)
		if res.TokenEnv != "" {
			fmt.Printf("Token Env: %s\n", res.TokenEnv)
		}
		fmt.Printf("Status: %s\n", res.Status)
		if res.Status == "OK" {
			fmt.Printf("Latency: %d ms\n\n", res.Latency.Milliseconds())
			fmt.Println("Result:")
			fmt.Println("Registry reachable and authentication succeeded.")
		} else {
			fmt.Printf("Reason: %s\n", res.Reason)
			return fmt.Errorf("registry test failed")
		}
		return nil

	case "auth":
		if len(args) > 1 && args[1] == "status" {
			fmt.Println("Registry Authentication Status:")
			for _, envVar := range []string{"NPM_TOKEN", "PYPI_TOKEN", "PYPI_USERNAME", "PYPI_PASSWORD"} {
				val := os.Getenv(envVar)
				status := "MISSING"
				if val != "" {
					status = "SET"
				}
				fmt.Printf("- %s: %s\n", envVar, status)
			}
			return nil
		}
		return fmt.Errorf("usage: pkgsafe registry auth status")

	default:
		return fmt.Errorf("unknown registry subcommand %q", args[0])
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func boolEnabled(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
