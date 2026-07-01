package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/niyam-ai/pkgsafe/internal/enterprise"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
)

// resolveTrustedKeys returns the default trusted keys plus, if keyPath is set,
// the explicitly-provided public key.
func resolveTrustedKeys(keyPath string) ([]ed25519.PublicKey, error) {
	keys := enterprise.DefaultTrustedKeys()
	if keyPath != "" {
		k, err := enterprise.LoadPublicKey(keyPath)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func cmdPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe policy [validate|explain|test|pack]")
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
		return cmdPolicyPack(args[1:])
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

func cmdPolicyPack(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pkgsafe policy pack [create|verify|install|list|export]")
	}

	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("policy-pack-keygen", flag.ContinueOnError)
		out := fs.String("out", "pkgsafe-pack-key", "output path prefix (writes <prefix>.key and <prefix>.pub)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		priv, pub, err := enterprise.GenerateKeypair()
		if err != nil {
			return err
		}
		privPath := *out + ".key"
		pubPath := *out + ".pub"
		if err := os.WriteFile(privPath, priv, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
			return err
		}
		fmt.Printf("Wrote signing (private) key: %s\nWrote trusted (public) key: %s\n", privPath, pubPath)
		fmt.Printf("Keep %s secret. Distribute %s to verifiers (e.g. ~/.pkgsafe/trusted-keys/).\n", privPath, pubPath)
		return nil

	case "create":
		fs := flag.NewFlagSet("policy-pack-create", flag.ContinueOnError)
		name := fs.String("name", "enterprise-standard", "policy pack name")
		output := fs.String("output", "enterprise-policy-pack.tar.gz", "output tar.gz file path")
		signingKey := fs.String("signing-key", "", "ed25519 private key (PEM) to sign the pack")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		err := enterprise.CreatePolicyPack(*name, ".pkgsafe", *output, *signingKey)
		if err != nil {
			return err
		}
		if *signingKey != "" {
			fmt.Printf("Policy pack %s created and signed successfully: %s\n", *name, *output)
		} else {
			fmt.Printf("Policy pack %s created successfully (unsigned): %s\n", *name, *output)
		}
		return nil

	case "verify":
		fs := flag.NewFlagSet("policy-pack-verify", flag.ContinueOnError)
		keyPath := fs.String("key", "", "trusted ed25519 public key (PEM) to verify the signature")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: pkgsafe policy pack verify [--key <pubkey>] <path>")
		}
		keys, err := resolveTrustedKeys(*keyPath)
		if err != nil {
			return exitError{code: 1, err: err}
		}
		if _, err := enterprise.VerifyPolicyPackWithKeys(fs.Arg(0), keys); err != nil {
			if ve, ok := err.(enterprise.PackValidationError); ok {
				return exitError{code: ve.Code, err: ve.Err}
			}
			return exitError{code: 1, err: err}
		}
		fmt.Println("Policy pack verified successfully.")
		return nil

	case "install":
		fs := flag.NewFlagSet("policy-pack-install", flag.ContinueOnError)
		keyPath := fs.String("key", "", "trusted ed25519 public key (PEM) to verify the signature")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: pkgsafe policy pack install [--key <pubkey>] <path>")
		}
		keys, err := resolveTrustedKeys(*keyPath)
		if err != nil {
			return exitError{code: 1, err: err}
		}
		if err := enterprise.InstallPolicyPackWithKeys(fs.Arg(0), keys); err != nil {
			if ve, ok := err.(enterprise.PackValidationError); ok {
				return exitError{code: ve.Code, err: ve.Err}
			}
			return err
		}
		fmt.Println("Policy pack installed successfully.")
		return nil

	case "list":
		packs, err := enterprise.ListPolicyPacks()
		if err != nil {
			return err
		}
		if len(packs) == 0 {
			fmt.Println("No policy packs installed.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NAME\tVERSION\tOWNER\tSTATUS\tEXPIRES AT")
		for _, p := range packs {
			status := "OK"
			if p.Expired {
				status = "EXPIRED"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Owner, status, p.ExpiresAt.Format("2006-01-02"))
		}
		w.Flush()
		return nil

	case "export":
		fs := flag.NewFlagSet("policy-pack-export", flag.ContinueOnError)
		output := fs.String("output", "pkgsafe-policy-bundle.tar.gz", "output tar.gz file path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		err := enterprise.ExportBundle(*output)
		if err != nil {
			return err
		}
		fmt.Printf("Policy bundle exported successfully: %s\n", *output)
		return nil

	default:
		return fmt.Errorf("unknown policy pack subcommand %q", args[0])
	}
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
