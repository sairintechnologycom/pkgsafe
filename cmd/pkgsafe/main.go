package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	anpm "github.com/niyam-ai/pkgsafe/internal/analyzer/npm"
	"github.com/niyam-ai/pkgsafe/internal/api"
	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/ci"
	"github.com/niyam-ai/pkgsafe/internal/cli"
	cargodeps "github.com/niyam-ai/pkgsafe/internal/deps/cargo"
	godeps "github.com/niyam-ai/pkgsafe/internal/deps/golang"
	npminventory "github.com/niyam-ai/pkgsafe/internal/deps/npm"
	pydeps "github.com/niyam-ai/pkgsafe/internal/deps/python"
	"github.com/niyam-ai/pkgsafe/internal/intercept"
	"github.com/niyam-ai/pkgsafe/internal/mcp"
	"github.com/niyam-ai/pkgsafe/internal/output"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	scargo "github.com/niyam-ai/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/niyam-ai/pkgsafe/internal/scanner/golang"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
	"github.com/niyam-ai/pkgsafe/internal/validation"
	versionpkg "github.com/niyam-ai/pkgsafe/internal/version"
)

// version/commit mirror the build-injected values in internal/version so the
// existing `version` command and tests keep working. The real source of truth
// is internal/version, populated via -ldflags.
var version = versionpkg.Version
var commit = versionpkg.Commit

var apiServeFunc = api.Serve

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit status %d", e.code)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if eErr, ok := err.(exitError); ok {
			if eErr.err != nil {
				fmt.Fprintln(os.Stderr, "error:", eErr.err)
			}
			os.Exit(eErr.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("pkgsafe %s (%s)\n", version, commit)
		return nil
	case "scan-local-npm":
		return cmdScanLocalNPM(args[1:])
	case "scan-npm-package":
		return cmdScanNPMPackage(args[1:])
	case "scan-pypi-package":
		return cmdScanPyPIPackage(args[1:])
	case "scan-python-deps":
		return cmdScanPythonDeps(args[1:])
	case "scan-go-deps":
		return cmdScanGoDeps(args[1:])
	case "scan-cargo-deps":
		return cmdScanCargoDeps(args[1:])
	case "scan-lockfile":
		return cmdScanLockfile(args[1:])
	case "explain":
		return cmdExplain(args[1:])
	case "explain-pypi":
		return cmdExplainPyPI(args[1:])
	case "npm-install":
		return cmdNPMInstall(args[1:])
	case "policy":
		return cmdPolicy(args[1:])
	case "registry":
		return cmdRegistry(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "mcp":
		return cmdMCP(args[1:])
	case "serve-api":
		return cmdServeAPI(args[1:])
	case "update-db":
		return cmdUpdateDB(args[1:])
	case "db":
		if len(args) > 1 && args[1] == "status" {
			return cmdDBStatus(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe db status")
	case "inventory":
		if len(args) > 1 && args[1] == "diff" {
			return cmdInventoryDiff(args[2:])
		}
		return cmdInventory(args[1:])
	case "test":
		if len(args) > 1 && args[1] == "corpus" {
			return cmdTestCorpus(args[2:])
		}
		if len(args) > 1 && args[1] == "benchmark" {
			return cmdTestBenchmark(args[2:])
		}
		if len(args) > 1 && args[1] == "rollout-readiness" {
			return cmdTestRolloutReadiness(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe test [corpus|benchmark|rollout-readiness]")
	case "ci":
		if len(args) > 1 && args[1] == "scan" {
			return cmdCIScan(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe ci scan")
	case "npm":
		return wrapInterceptError(cli.NPMIntercept(args[1:]))
	case "pip":
		return wrapInterceptError(cli.PipIntercept(args[1:]))
	case "python":
		return wrapInterceptError(cli.PythonIntercept(args[1:]))
	case "run":
		return wrapInterceptError(cli.RunIntercept(args[1:]))
	case "init":
		if len(args) > 1 && args[1] == "shell" {
			return cli.InitShell(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe init shell")
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`PkgSafe - local-first package safety CLI

Usage:
  pkgsafe scan-local-npm <dir> [--json]
  pkgsafe scan-npm-package <name> [--version <version>] [--policy <path>] [--policy-pack <name>] [--mode warn|block|audit] [--json]
  pkgsafe scan-pypi-package <name> [--version <version>] [--policy <path>] [--policy-pack <name>] [--mode warn|block|audit] [--json]
  pkgsafe scan-python-deps <requirements.txt|pyproject.toml> [--json]
  pkgsafe scan-go-deps <go.mod> [--json]
  pkgsafe scan-cargo-deps <Cargo.lock> [--json]
  pkgsafe scan-lockfile <package-lock.json> [--json]
  pkgsafe inventory <repo-path> [--json]
  pkgsafe inventory diff [--base <branch>] [--repo <path>] [--json]
  pkgsafe test corpus [--json] [--explain-misses]
  pkgsafe test benchmark [--json] [--fixtures <dir>]
  pkgsafe test rollout-readiness [--json]
  pkgsafe explain <name> [--version <version>] [--policy <path>] [--policy-pack <name>]
  pkgsafe explain-pypi <name> [--version <version>] [--policy <path>] [--policy-pack <name>]
  pkgsafe npm-install <name> [--version <version>] [--policy-pack <name>] [--mode warn|block|audit]
  pkgsafe ci scan [--lockfile <path>] [--policy <path>] [--policy-pack <name>] [--mode audit|warn|block] [--fail-on none|warn|block]
  pkgsafe policy validate <path>
  pkgsafe policy explain <path>
  pkgsafe policy pack keygen [--out <prefix>]
  pkgsafe policy pack create --name <name> --output <path> [--signing-key <key.pem>]
  pkgsafe policy pack verify [--key <pubkey.pem>] <path>
  pkgsafe policy pack install [--key <pubkey.pem>] <path>
  pkgsafe policy pack list
  pkgsafe policy pack export --output <path>
  pkgsafe registry list
  pkgsafe registry test <name>
  pkgsafe registry auth status
  pkgsafe report generate [--repo <path>] [--output <path>] [--format <format>] [--type <type>]
  pkgsafe report evidence-pack [--repo <path>] [--output <path>]
  pkgsafe report exceptions [--output <path>]
  pkgsafe report overrides [--output <path>]
  pkgsafe report policy [--policy-pack <name>] [--output <path>]
  pkgsafe report ci [--input <path>] [--output <path>]
  pkgsafe report siem-export [--output <path>]
  pkgsafe report servicenow-export [--output <path>]
  pkgsafe report azure-devops-export [--output <path>]
  pkgsafe mcp serve
  pkgsafe serve-api [--port <port>] [--token <token>] [--policy <path>] [--mode <mode>] [--offline]
  pkgsafe npm <npm-args...>
  pkgsafe pip <pip-args...>
  pkgsafe python <python-args...>
  pkgsafe run [--] <command-args...>
  pkgsafe init shell
  pkgsafe version
`)
}

func cmdScanPyPIPackage(args []string) error {
	fs := flag.NewFlagSet("scan-pypi-package", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	sandbox := fs.Bool("sandbox", false, "report that PyPI behavior analysis is unsupported")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if !*offline {
		cli.UpdateDBAsync("", "pypi", "osv", 24*time.Hour)
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.SandboxEnabled = *sandbox
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"
	res, err := scanner.ScanPackage(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanPythonDeps(args []string) error {
	fs := flag.NewFlagSet("scan-python-deps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	deps, err := pydeps.ParseFile(fs.Arg(0))
	if err != nil {
		return err
	}
	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	var results []types.ScanResult
	for _, dep := range deps {
		if !dep.Pinned {
			fmt.Fprintf(os.Stderr, "Warning: %s is unpinned in %s\n", dep.Name, fs.Arg(0))
		}
		res, err := scanner.ScanPackage(dep.Name, dep.Version)
		if err != nil {
			return fmt.Errorf("scan dependency %s: %w", dep.Name, err)
		}
		res = stripEnterprise(res, *enterpriseMode)
		_ = saveResult(res)
		results = append(results, res)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		if err := output.Write(os.Stdout, res, false); err != nil {
			return err
		}
	}
	return nil
}

func cmdScanGoDeps(args []string) error {
	fs := flag.NewFlagSet("scan-go-deps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}

	if !*offline {
		cli.UpdateDBAsync("", "Go", "osv", 24*time.Hour)
	}

	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read dependency file: %w", err)
	}

	deps, err := godeps.ParseGoMod(content)
	if err != nil {
		return fmt.Errorf("parse go.mod: %w", err)
	}

	scanner := sgolang.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.Environment = "developer"
	scanner.RequestedBy = "human"

	var results []types.ScanResult
	for _, dep := range deps {
		res, err := scanner.ScanPackage(dep.Name, dep.Version)
		if err != nil {
			return fmt.Errorf("scan dependency %s: %w", dep.Name, err)
		}
		res = stripEnterprise(res, *enterpriseMode)
		_ = saveResult(res)
		results = append(results, res)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		if err := output.Write(os.Stdout, res, false); err != nil {
			return err
		}
	}
	return nil
}

func cmdScanCargoDeps(args []string) error {
	fs := flag.NewFlagSet("scan-cargo-deps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}

	if !*offline {
		cli.UpdateDBAsync("", "crates.io", "osv", 24*time.Hour)
	}

	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read dependency file: %w", err)
	}

	deps, err := cargodeps.ParseCargoLock(content)
	if err != nil {
		return fmt.Errorf("parse Cargo.lock: %w", err)
	}

	scanner := scargo.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.Environment = "developer"
	scanner.RequestedBy = "human"

	var results []types.ScanResult
	for _, dep := range deps {
		res, err := scanner.ScanPackage(dep.Name, dep.Version)
		if err != nil {
			return fmt.Errorf("scan dependency %s: %w", dep.Name, err)
		}
		res = stripEnterprise(res, *enterpriseMode)
		_ = saveResult(res)
		results = append(results, res)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		if err := output.Write(os.Stdout, res, false); err != nil {
			return err
		}
	}
	return nil
}

func cmdScanLocalNPM(args []string) error {
	fs := flag.NewFlagSet("scan-local-npm", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	sandbox := fs.Bool("sandbox", false, "execute lifecycle scripts on the host (no isolation) for heuristic behavior analysis")
	timeout := fs.Duration("timeout", 10*time.Second, "behavior-analysis execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep the analysis working directory after execution")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	cli.UpdateDBAsync("", "npm", "osv", 24*time.Hour)
	if fs.NArg() != 1 {
		return errors.New("directory is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}

	isFlagPassed := func(name string) bool {
		found := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == name {
				found = true
			}
		})
		return found
	}

	sandboxEnabled := *sandbox
	if !isFlagPassed("sandbox") {
		sandboxEnabled = pol.Sandbox.Enabled
	}

	sandboxTimeout := *timeout
	if !isFlagPassed("timeout") {
		if pol.Sandbox.DefaultTimeoutSeconds > 0 {
			sandboxTimeout = time.Duration(pol.Sandbox.DefaultTimeoutSeconds) * time.Second
		} else {
			sandboxTimeout = 10 * time.Second
		}
	}

	networkMode := *network
	if !isFlagPassed("network") {
		if pol.Sandbox.NetworkMode != "" {
			networkMode = pol.Sandbox.NetworkMode
		} else {
			networkMode = "disabled"
		}
	}

	keepSandboxVal := *keepSandbox
	if !isFlagPassed("keep-sandbox") {
		keepSandboxVal = pol.Sandbox.KeepSandbox
	}

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.SandboxEnabled = sandboxEnabled
	scanner.SandboxTimeout = sandboxTimeout
	scanner.NetworkMode = networkMode
	scanner.KeepSandbox = keepSandboxVal

	res, err := scanner.ScanLocalPackage(fs.Arg(0))
	if err != nil {
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanNPMPackage(args []string) error {
	fs := flag.NewFlagSet("scan-npm-package", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	sandbox := fs.Bool("sandbox", false, "execute lifecycle scripts on the host (no isolation) for heuristic behavior analysis")
	timeout := fs.Duration("timeout", 10*time.Second, "behavior-analysis execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep the analysis working directory after execution")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if !*offline {
		cli.UpdateDBAsync("", "npm", "osv", 24*time.Hour)
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}

	isFlagPassed := func(name string) bool {
		found := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == name {
				found = true
			}
		})
		return found
	}

	sandboxEnabled := *sandbox
	if !isFlagPassed("sandbox") {
		sandboxEnabled = pol.Sandbox.Enabled
	}

	sandboxTimeout := *timeout
	if !isFlagPassed("timeout") {
		if pol.Sandbox.DefaultTimeoutSeconds > 0 {
			sandboxTimeout = time.Duration(pol.Sandbox.DefaultTimeoutSeconds) * time.Second
		} else {
			sandboxTimeout = 10 * time.Second
		}
	}

	networkMode := *network
	if !isFlagPassed("network") {
		if pol.Sandbox.NetworkMode != "" {
			networkMode = pol.Sandbox.NetworkMode
		} else {
			networkMode = "disabled"
		}
	}

	keepSandboxVal := *keepSandbox
	if !isFlagPassed("keep-sandbox") {
		keepSandboxVal = pol.Sandbox.KeepSandbox
	}

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.SandboxEnabled = sandboxEnabled
	scanner.SandboxTimeout = sandboxTimeout
	scanner.NetworkMode = networkMode
	scanner.KeepSandbox = keepSandboxVal
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"

	res, err := scanner.ScanPackage(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanLockfile(args []string) error {
	fs := flag.NewFlagSet("scan-lockfile", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	_ = fs.Bool("offline", false, "run scan offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("lockfile path is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	res, err := anpm.AnalyzeLockfile(fs.Arg(0), pol)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run explain offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	store, _ := cache.Load("")
	cached, hasCached := store.Get("npm", pkgName, *ver)

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"
	res, err := scanner.ScanPackage(pkgName, *ver)
	if err != nil {
		if hasCached {
			cached = stripEnterprise(cached, *enterpriseMode)
			return output.Write(os.Stdout, cached, *asJSON)
		}
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	if *asJSON {
		return output.Write(os.Stdout, res, true)
	}
	writeExplain(os.Stdout, res, cached, hasCached, pol)
	return nil
}

func cmdExplainPyPI(args []string) error {
	fs := flag.NewFlagSet("explain-pypi", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run explain offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	store, _ := cache.Load("")
	cached, hasCached := store.Get("pypi", pkgName, *ver)

	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"
	res, err := scanner.ScanPackage(pkgName, *ver)
	if err != nil {
		if hasCached {
			cached = stripEnterprise(cached, *enterpriseMode)
			return output.Write(os.Stdout, cached, *asJSON)
		}
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	if *asJSON {
		return output.Write(os.Stdout, res, true)
	}
	writeExplain(os.Stdout, res, cached, hasCached, pol)
	return nil
}

func cmdNPMInstall(args []string) error {
	fs := flag.NewFlagSet("npm-install", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	mode := fs.String("mode", "warn", "warn, block, or audit")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, *policyPack, *registryConfig)
	if err != nil {
		return err
	}
	res, err := scanRemoteNPM(pkgName, *ver, pol)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, *enterpriseMode)
	_ = saveResult(res)
	if err := output.Write(os.Stdout, res, *asJSON); err != nil {
		return err
	}

	m := pol.Mode
	if m == policy.ModeAudit {
		fmt.Println("Audit mode: npm install skipped.")
		return nil
	}
	if res.Decision == types.DecisionBlock {
		return fmt.Errorf("install blocked by policy: decision=%s score=%d", res.Decision, res.Score)
	}
	if m == policy.ModeWarn && res.Decision == types.DecisionWarn {
		fmt.Println("Warning mode: package is suspicious. Re-run with --mode audit to inspect only or --mode block to enforce.")
	}
	nameWithVersion := pkgName
	if *ver != "" {
		nameWithVersion = pkgName + "@" + *ver
	}
	cmd := exec.Command("npm", "install", nameWithVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func cmdMCP(args []string) error {
	if len(args) < 1 || args[0] != "serve" {
		return errors.New("usage: pkgsafe mcp serve [--policy <path>] [--mode <mode>] [--offline] [--log-level <level>]")
	}

	fs := flag.NewFlagSet("mcp-serve", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run mcp server offline")
	logLevel := fs.String("log-level", "", "log level (e.g. debug)")

	if err := fs.Parse(reorderFlags(args[1:])); err != nil {
		return err
	}

	config := mcp.ServerConfig{
		PolicyPath: *policyPath,
		Mode:       *mode,
		Offline:    *offline,
		LogLevel:   *logLevel,
	}

	return mcp.Serve(config, os.Stdin, os.Stdout)
}

func scanRemoteNPM(name, version string, pol policy.Policy) (types.ScanResult, error) {
	scanner := snpm.New()
	scanner.Policy = pol
	return scanner.ScanPackage(name, version)
}

func loadPolicy(path, mode, policyPack, registryConfig string) (policy.Policy, error) {
	pol, err := policy.ResolvePolicy(policyPack, "", path, mode, registryConfig)
	if err != nil {
		return policy.Policy{}, err
	}
	return pol, nil
}

func stripEnterprise(res types.ScanResult, enabled bool) types.ScanResult {
	if !enabled {
		res.PolicyInfo = nil
		res.RegistryInfo = nil
		res.TrustInfo = nil
		res.ExceptionInfo = nil
	}
	return res
}

func writeExplain(w io.Writer, res types.ScanResult, cached types.ScanResult, hasCached bool, pol policy.Policy) {
	fmt.Fprintf(w, "Package: %s/%s\n", res.Package.Ecosystem, res.Package.Name)
	fmt.Fprintf(w, "Latest Known Version: %s\n", emptyLatest(res.Package.Version))

	lastScannedVer := "none"
	lastDecision := "none"
	riskScore := res.Score

	if hasCached {
		lastScannedVer = cached.Package.Version
		lastDecision = strings.ToUpper(string(cached.Decision))
		riskScore = cached.Score
	} else {
		lastScannedVer = res.Package.Version
		lastDecision = strings.ToUpper(string(res.Decision))
	}

	fmt.Fprintf(w, "Last Scanned Version: %s\n", emptyLatest(lastScannedVer))
	fmt.Fprintf(w, "Last Decision: %s\n", lastDecision)
	fmt.Fprintf(w, "Risk Score: %d/100\n\n", riskScore)

	fmt.Fprintln(w, "Vulnerability Summary:")
	if len(res.Vulnerabilities) > 0 {
		counts := make(map[string]int)
		var fixedVersions []string
		for _, v := range res.Vulnerabilities {
			counts[v.Severity]++
			if len(v.FixedVersions) > 0 {
				fixedVersions = append(fixedVersions, v.FixedVersions...)
			}
		}
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count, ok := counts[sev]; ok && count > 0 {
				suffix := "advisory"
				if count > 1 {
					suffix = "advisories"
				}
				fmt.Fprintf(w, "- %d %s %s found\n", count, sev, suffix)
			}
		}
		if len(fixedVersions) > 0 {
			fixedVersions = uniqueStrings(fixedVersions)
			fmt.Fprintf(w, "- Fixed in: %s\n", strings.Join(fixedVersions, ", "))
		}
	} else {
		fmt.Fprintln(w, "- No known advisories found")
	}
	fmt.Fprintln(w)

	if len(res.Reasons) > 0 {
		fmt.Fprintln(w, "Top Risk Reasons:")
		for _, r := range res.Reasons {
			if r.ScoreImpact > 0 || r.ID == "trusted_package_reduction" {
				fmt.Fprintf(w, "- [%s %+d] %s: %s\n", r.Severity, r.ScoreImpact, r.ID, r.Description)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Recommended Action:\n%s\n", output.RecommendedAction(res))
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func cmdUpdateDB(args []string) error {
	fs := flag.NewFlagSet("update-db", flag.ContinueOnError)
	eco := fs.String("ecosystem", "all", "ecosystem to sync: npm, pypi, go, cargo, or all")
	src := fs.String("source", "osv", "threat database source")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return cli.UpdateDB("", *eco, *src)
}

func cmdDBStatus(args []string) error {
	return cli.DBStatus("")
}

func policyStatus(pol policy.Policy, pkg types.PackageIdentity) string {
	switch {
	case policy.IsBlocked(pol, pkg.Ecosystem, pkg.Name):
		return "blocked"
	case policy.IsTrusted(pol, pkg.Ecosystem, pkg.Name):
		return "trusted"
	default:
		return "unlisted"
	}
}

func hasReason(reasons []types.Reason, id string) bool {
	for _, reason := range reasons {
		if reason.ID == id {
			return true
		}
	}
	return false
}

func emptyLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func saveResult(res types.ScanResult) error {
	store, err := cache.Load("")
	if err != nil {
		return err
	}
	return store.Put(res)
}

func ensureAbs(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func splitPackageSpec(s string) (string, string) {
	if strings.HasPrefix(s, "@") {
		idx := strings.LastIndex(s, "@")
		if idx > 0 {
			return s[:idx], s[idx+1:]
		}
		return s, ""
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return s, ""
}

func reorderFlags(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && flagNeedsValue(arg) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func flagNeedsValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	name, _, _ = strings.Cut(name, "=")
	switch name {
	case "version", "mode", "policy", "log-level", "timeout", "network",
		"lockfile", "dependency-file", "ecosystem", "fail-on", "json-output", "sarif-output", "summary-output", "baseline", "policy-pack", "registry-config", "port", "token",
		"base", "repo", "fixtures", "definitions":
		return true
	default:
		return false
	}
}

func cmdCIScan(args []string) error {
	fs := flag.NewFlagSet("ci-scan", flag.ContinueOnError)
	lockfile := fs.String("lockfile", "package-lock.json", "path to package-lock.json")
	dependencyFile := fs.String("dependency-file", "", "path to dependency file")
	ecosystem := fs.String("ecosystem", "", "package ecosystem: npm or pypi")
	policyPath := fs.String("policy", "", "path to PkgSafe policy file")
	policyPack := fs.String("policy-pack", "", "policy pack name")
	mode := fs.String("mode", "", "PkgSafe mode: audit, warn, or block")
	failOn := fs.String("fail-on", "", "minimum decision that fails the workflow: none, warn, block")
	jsonOutput := fs.String("json-output", "", "path to write JSON report")
	sarifOutput := fs.String("sarif-output", "", "path to write SARIF report")
	summaryOutput := fs.String("summary-output", "", "path to write Markdown summary")
	changedOnly := fs.Bool("changed-only", false, "only scan changed dependencies")
	baseline := fs.String("baseline", "main", "baseline branch for diffing")
	sandbox := fs.Bool("sandbox", false, "enable lifecycle-script behavior analysis (runs scripts on host, no isolation)")
	offline := fs.Bool("offline", false, "use offline database only")
	timeout := fs.Duration("timeout", 0, "behavior-analysis timeout")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	enterpriseMode := fs.Bool("enterprise-mode", true, "Enable enterprise evidence output")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitError{code: ci.ExitUsageError, err: err}
	}

	isFlagPassed := func(name string) bool {
		found := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == name {
				found = true
			}
		})
		return found
	}

	opts := ci.ScanOptions{
		LockfilePath:         *lockfile,
		DependencyFile:       *dependencyFile,
		Ecosystem:            *ecosystem,
		PolicyPath:           *policyPath,
		Mode:                 *mode,
		FailOn:               *failOn,
		JsonOutput:           *jsonOutput,
		SarifOutput:          *sarifOutput,
		SummaryOutput:        *summaryOutput,
		ChangedOnlySpecified: isFlagPassed("changed-only"),
		ChangedOnly:          *changedOnly,
		Baseline:             *baseline,
		SandboxSpecified:     isFlagPassed("sandbox"),
		Sandbox:              *sandbox,
		Offline:              *offline,
		Timeout:              *timeout,
		PolicyPack:           *policyPack,
		RegistryConfigPath:   *registryConfig,
		EnterpriseMode:       *enterpriseMode,
	}

	res, err := ci.RunScan(opts)
	if err != nil {
		if se, ok := err.(ci.ScanError); ok {
			return exitError{code: se.ExitCode, err: se.Err}
		}
		return exitError{code: ci.ExitInternalError, err: err}
	}

	// Write human summary to stdout
	ci.WriteHumanSummary(os.Stdout, res)

	// Write reports if paths are specified
	if opts.JsonOutput != "" {
		if err := ci.WriteJSONOutput(opts.JsonOutput, res); err != nil {
			return exitError{code: ci.ExitInternalError, err: fmt.Errorf("write JSON output: %w", err)}
		}
	}
	if opts.SarifOutput != "" {
		if err := ci.WriteSarifOutput(opts.SarifOutput, res); err != nil {
			return exitError{code: ci.ExitInternalError, err: fmt.Errorf("write SARIF output: %w", err)}
		}
	}
	if opts.SummaryOutput != "" {
		if err := ci.WriteSummaryOutput(opts.SummaryOutput, res); err != nil {
			return exitError{code: ci.ExitInternalError, err: fmt.Errorf("write Markdown summary output: %w", err)}
		}
	}

	// Exit behavior based on fail-on threshold
	thresholdReached := false
	switch res.FailOn {
	case "block":
		if res.Decision == "block" {
			thresholdReached = true
		}
	case "warn":
		if res.Decision == "block" || res.Decision == "warn" {
			thresholdReached = true
		}
	}

	if thresholdReached {
		return exitError{code: ci.ExitFailThreshold, err: nil}
	}

	return nil
}

func wrapInterceptError(err error) error {
	if err == nil {
		return nil
	}
	if ie, ok := err.(intercept.InterceptError); ok {
		return exitError{code: ie.Code, err: ie.Err}
	}
	return err
}

func cmdServeAPI(args []string) error {
	fs := flag.NewFlagSet("serve-api", flag.ContinueOnError)
	port := fs.String("port", "8080", "port to listen on")
	token := fs.String("token", "", "bearer token for authorization")
	policyPath := fs.String("policy", "", "default policy path")
	mode := fs.String("mode", "", "default mode (audit, warn, block)")
	offline := fs.Bool("offline", false, "run server offline")
	bind := fs.String("bind", "127.0.0.1", "interface to bind (non-loopback requires --token and TLS)")
	tlsCert := fs.String("tls-cert", "", "path to TLS certificate (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "path to TLS private key (enables HTTPS)")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if !*offline {
		cli.UpdateDBAsync("", "npm", "osv", 24*time.Hour)
		cli.UpdateDBAsync("", "pypi", "osv", 24*time.Hour)
	}

	cfg := api.Config{
		Port:          *port,
		Token:         *token,
		DefaultPolicy: *policyPath,
		DefaultMode:   *mode,
		Offline:       *offline,
		Version:       version,
		Commit:        commit,
		BindAddress:   *bind,
		TLSCertFile:   *tlsCert,
		TLSKeyFile:    *tlsKey,
	}

	return apiServeFunc(cfg)
}

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("repository path is required")
	}
	repoPath := fs.Arg(0)

	deps, err := npminventory.ScanInventory(repoPath)
	if err != nil {
		return err
	}

	var cleanDeps []types.Dependency
	for _, d := range deps {
		if d.Name != "" {
			cleanDeps = append(cleanDeps, d)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cleanDeps)
	}

	fmt.Printf("Inventory of dependencies in %s:\n\n", repoPath)
	fmt.Printf("%-35s %-15s %-15s %-45s\n", "Package Name", "Type", "Direct/Trans", "Source File")
	fmt.Println(strings.Repeat("-", 115))
	for _, d := range cleanDeps {
		dirStr := "transitive"
		if d.Direct {
			dirStr = "direct"
		}
		fmt.Printf("%-35s %-15s %-15s %-45s\n", d.Name, d.DependencyType, dirStr, d.SourceFile)
	}
	return nil
}

func cmdTestCorpus(args []string) error {
	fs := flag.NewFlagSet("test-corpus", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	explainMisses := fs.Bool("explain-misses", false, "include detailed dependency miss explanations")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	// We use "testdata/corpus" as the directory containing test cases
	// and "testdata/corpus-golden.json" as the expected results file.
	return validation.RunCorpus("testdata/corpus", "testdata/corpus-golden.json", *asJSON, *explainMisses)
}

func cmdTestBenchmark(args []string) error {
	fs := flag.NewFlagSet("test-benchmark", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	fixturesDir := fs.String("fixtures", "testdata/benchmarks", "directory for generated benchmark fixtures")
	definitionsDir := fs.String("definitions", "benchmarks", "directory containing benchmark JSON definitions")
	update := fs.Bool("update", false, "rewrite default benchmark definitions")
	offline := fs.Bool("offline", false, "use cached package scan results only for package benchmarks")
	repoPath := fs.String("repo", "", "additional repository path to inventory without golden expectations")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	rep, err := validation.RunBenchmarkPackWithOptions(validation.BenchmarkOptions{
		FixturesDir:    *fixturesDir,
		DefinitionsDir: *definitionsDir,
		Update:         *update,
		Offline:        *offline,
		RepoPath:       *repoPath,
	})
	if err != nil {
		return err
	}
	if err := validation.WriteBenchmarkReport(os.Stdout, rep, *asJSON); err != nil {
		return err
	}
	if !rep.Pass {
		return exitError{code: 1}
	}
	return nil
}

func cmdTestRolloutReadiness(args []string) error {
	fs := flag.NewFlagSet("test-rollout-readiness", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	rep, err := validation.RunRolloutReadiness("testdata/corpus", "testdata/corpus-golden.json")
	if err != nil {
		return err
	}
	if err := validation.WriteRolloutReadiness(os.Stdout, rep, *asJSON); err != nil {
		return err
	}
	if !rep.Pass {
		return exitError{code: 1}
	}
	return nil
}

func cmdInventoryDiff(args []string) error {
	fs := flag.NewFlagSet("inventory-diff", flag.ContinueOnError)
	baseBranch := fs.String("base", "main", "base git branch to compare against")
	repoPath := fs.String("repo", ".", "path to the repository")
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	currentDeps, err := npminventory.ScanInventory(*repoPath)
	if err != nil {
		return fmt.Errorf("scan current inventory: %w", err)
	}

	baseDeps, err := npminventory.ScanInventoryGit(*repoPath, *baseBranch)
	if err != nil {
		return fmt.Errorf("scan base inventory for branch %q: %w", *baseBranch, err)
	}

	report := npminventory.DiffInventories(baseDeps, currentDeps)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Printf("Dependency Inventory Diff (Base: %s vs Working Tree: %s)\n", *baseBranch, *repoPath)
	fmt.Println(strings.Repeat("=", 80))

	fmt.Println("\nAdded Dependencies:")
	if len(report.Added) == 0 {
		fmt.Println("  (None)")
	} else {
		for _, d := range report.Added {
			fmt.Printf("  + %s (%s, direct=%t) in %s\n", d.Name, d.DependencyType, d.Direct, d.SourceFile)
		}
	}

	fmt.Println("\nRemoved Dependencies:")
	if len(report.Removed) == 0 {
		fmt.Println("  (None)")
	} else {
		for _, d := range report.Removed {
			fmt.Printf("  - %s (%s, direct=%t) from %s\n", d.Name, d.DependencyType, d.Direct, d.SourceFile)
		}
	}

	fmt.Println("\nModified/Changed Dependencies:")
	if len(report.Changed) == 0 {
		fmt.Println("  (None)")
	} else {
		for _, c := range report.Changed {
			fmt.Printf("  * %s in %s:\n", c.Name, c.SourceFile)
			if c.BaseVersion != c.CurVersion {
				fmt.Printf("    Version: %s -> %s\n", c.BaseVersion, c.CurVersion)
			}
			if c.BaseType != c.CurType {
				fmt.Printf("    Type:    %s -> %s\n", c.BaseType, c.CurType)
			}
			if c.BaseDirect != c.CurDirect {
				fmt.Printf("    Direct:  %t -> %t\n", c.BaseDirect, c.CurDirect)
			}
		}
	}

	return nil
}
