// Package cli exposes the pkgsafe command-line interface as an importable
// entry point. The public `pkgsafe` binary (cmd/pkgsafe) is a thin shim over
// this package, and downstream distributions (for example the private
// enterprise superset binary) embed the same command surface by calling
// Execute or Run.
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	anpm "github.com/sairintechnologycom/pkgsafe/internal/analyzer/npm"
	"github.com/sairintechnologycom/pkgsafe/internal/api"
	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/ci"
	"github.com/sairintechnologycom/pkgsafe/internal/cli"
	"github.com/sairintechnologycom/pkgsafe/internal/dbbundle"
	cargodeps "github.com/sairintechnologycom/pkgsafe/internal/deps/cargo"
	godeps "github.com/sairintechnologycom/pkgsafe/internal/deps/golang"
	npminventory "github.com/sairintechnologycom/pkgsafe/internal/deps/npm"
	pydeps "github.com/sairintechnologycom/pkgsafe/internal/deps/python"
	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
	"github.com/sairintechnologycom/pkgsafe/internal/mcp"
	"github.com/sairintechnologycom/pkgsafe/internal/output"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	rnpm "github.com/sairintechnologycom/pkgsafe/internal/registry/npm"
	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/audit"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
	"github.com/sairintechnologycom/pkgsafe/internal/typosquat"
	"github.com/sairintechnologycom/pkgsafe/internal/validation"
	versionpkg "github.com/sairintechnologycom/pkgsafe/internal/version"
	"github.com/sairintechnologycom/pkgsafe/pkg/license"
)

// version/commit mirror the build-injected values in internal/version so the
// existing `version` command and tests keep working. The real source of truth
// is internal/version, populated via -ldflags.
var version = versionpkg.Version
var commit = versionpkg.Commit

var apiServeFunc = api.Serve

// ciRunScanFunc is swappable in tests so dispatch-level behavior (like the
// RunConfig enterprise-mode gate) can be asserted without a live scan.
var ciRunScanFunc = ci.RunScan

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

// RunConfig customizes CLI dispatch for downstream distributions. The
// zero value is the public OSS behavior; the public pkgsafe binary always
// uses the zero value.
type RunConfig struct {
	// CIEnterpriseMode enables enterprise evidence enrichment in `ci scan`
	// output: per-finding policy/registry/trust/exception evidence plus
	// policy pack metadata and exceptions-used tracking. Reserved for the
	// private enterprise distribution.
	CIEnterpriseMode bool

	// Entitlement carries the resolved enterprise license, or nil. The public
	// pkgsafe binary always leaves it nil, which — because (*license.Entitlement)
	// methods are nil-safe and fail open — grants no premium features and
	// preserves exact OSS behavior. The private enterprise binary resolves a
	// license at startup (via license.Resolver) and populates this so feature
	// gates can call cfg.Entitlement.Allows(<feature>). A nil, expired, or
	// unverifiable entitlement must only withhold premium features; it must
	// never disable scanning.
	Entitlement *license.Entitlement
}

// Execute runs the pkgsafe CLI with the given arguments (excluding the
// program name), prints any error to stderr, and returns the process exit
// code the caller should exit with.
func Execute(args []string) int {
	return ExecuteWith(RunConfig{}, args)
}

// ExecuteWith is Execute with a downstream RunConfig.
func ExecuteWith(cfg RunConfig, args []string) int {
	if err := RunWith(cfg, args); err != nil {
		if eErr, ok := err.(exitError); ok {
			if eErr.err != nil {
				fmt.Fprintln(os.Stderr, "error:", eErr.err)
			}
			return eErr.code
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// Run dispatches a single pkgsafe CLI invocation. It returns nil on success;
// errors carrying a specific exit code are translated by Execute.
func Run(args []string) error {
	return RunWith(RunConfig{}, args)
}

// RunWith is Run with a downstream RunConfig.
func RunWith(cfg RunConfig, args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("pkgsafe %s (%s)\n", version, commit)
		return nil
	case "scan":
		return cmdScan(args[1:])
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
	case "feedback":
		return cmdFeedback(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "mcp":
		return cmdMCP(args[1:])
	case "serve-api":
		return cmdServeAPI(args[1:])
	case "update-db":
		return cmdUpdateDB(args[1:])
	case "db":
		return cmdDB(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "history":
		return cmdHistory(args[1:])
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
		if len(args) > 1 && args[1] == "production-readiness" {
			return cmdTestProductionReadiness(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe test [corpus|benchmark|rollout-readiness|production-readiness]")
	case "ci":
		if len(args) > 1 && args[1] == "scan" {
			return cmdCIScan(cfg, args[2:])
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
  pkgsafe scan [dir] [--policy <path>] [--mode warn|block|audit] [--offline] [--json]
  pkgsafe scan-local-npm <dir> [--json]
  pkgsafe scan-npm-package <name> [--version <version>] [--policy <path>] [--mode warn|block|audit] [--json]
  pkgsafe scan-pypi-package <name> [--version <version>] [--policy <path>] [--mode warn|block|audit] [--json]
  pkgsafe scan-python-deps <requirements.txt|pyproject.toml> [--json]
  pkgsafe scan-go-deps <go.mod> [--json]
  pkgsafe scan-cargo-deps <Cargo.lock> [--json]
  pkgsafe scan-lockfile <package-lock.json> [--json]
  pkgsafe inventory <repo-path> [--json]
  pkgsafe inventory diff [--base <branch>] [--repo <path>] [--json]
  pkgsafe test corpus [--json] [--explain-misses]
  pkgsafe test benchmark [--json] [--fixtures <dir>] [--offline] [--repo <path>] [--repo-list <path>]
  pkgsafe test rollout-readiness [--json]
  pkgsafe test production-readiness [--json] [--fixtures <dir>] [--repo <path>]
  pkgsafe db status [--json]
  pkgsafe db export-bundle --output <path> [--db <path>]
  pkgsafe db verify-bundle [--json] <path>
  pkgsafe db import-bundle [--db <path>] <path>
  pkgsafe doctor [--json] [--policy <path>] [--registry-config <path>] [--skip-network]
  pkgsafe explain <name> [--version <version>] [--policy <path>]
  pkgsafe explain-pypi <name> [--version <version>] [--policy <path>]
  pkgsafe npm-install <name> [--version <version>] [--mode warn|block|audit]
  pkgsafe ci scan [--lockfile <path>] [--policy <path>] [--mode audit|warn|block] [--fail-on none|warn|block]
  pkgsafe policy validate <path>
  pkgsafe policy explain <path>
  pkgsafe policy edit [--policy <path>]
  pkgsafe registry list [--policy <path>] [--registry-config <path>]
  pkgsafe registry test [--policy <path>] [--registry-config <path>] <name>
  pkgsafe registry test [--policy <path>] [--registry-config <path>] --ecosystem <npm|pypi> --package <name>
  pkgsafe registry auth status
  pkgsafe feedback create --input <scan.json> [--output-dir <dir>] [--reason <text>] [--command <command>]
  pkgsafe report generate [--repo <path>] [--output <path>] [--format <format>] [--type <type>]
  pkgsafe report evidence-pack [--repo <path>] [--output <path>]
  pkgsafe report beta-evidence [--repo <path>] [--repo-list <path>] [--output <path>] [--json-output <path>]
  pkgsafe report ga-evidence [--repo <path>] [--repo-list <path>] [--output <path>] [--json-output <path>]
  pkgsafe report ci [--input <path>] [--output <path>]
  pkgsafe mcp serve
  pkgsafe serve-api [--port <port>] [--token <token>] [--policy <path>] [--mode <mode>] [--offline]
  pkgsafe npm <npm-args...>
  pkgsafe pip <pip-args...>
  pkgsafe python <python-args...>
  pkgsafe run [--] <command-args...>
  pkgsafe init shell
  pkgsafe history [--limit <n>] [--decision <block|warn|allow>] [--clear] [--json]
  pkgsafe version
`)
}

func flagPassed(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func resolveBehaviorMode(fs *flag.FlagSet, behavior string, sandbox bool, pol policy.Policy) (types.BehaviorMode, error) {
	if flagPassed(fs, "behavior") {
		switch types.BehaviorMode(behavior) {
		case types.BehaviorDisabled, types.BehaviorHeuristic, types.BehaviorIsolated:
			return types.BehaviorMode(behavior), nil
		default:
			return "", fmt.Errorf("--behavior must be disabled, heuristic, or isolated")
		}
	}
	if flagPassed(fs, "sandbox") {
		if sandbox {
			return types.BehaviorHeuristic, nil
		}
		return types.BehaviorDisabled, nil
	}
	return types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, pol.Sandbox.Enabled), nil
}

func cmdScanPyPIPackage(args []string) error {
	fs := flag.NewFlagSet("scan-pypi-package", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	behavior := fs.String("behavior", "", "behavior analysis mode: disabled, heuristic, or isolated")
	sandbox := fs.Bool("sandbox", false, "compatibility alias for --behavior heuristic; PyPI execution remains disabled without isolated backend")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if !*offline {
		cli.UpdateDBAsync("", "pypi", "osv", 24*time.Hour)
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}
	behaviorMode, err := resolveBehaviorMode(fs, *behavior, *sandbox, pol)
	if err != nil {
		return err
	}
	scanner := spypi.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.BehaviorMode = behaviorMode
	scanner.SandboxEnabled = behaviorMode != types.BehaviorDisabled
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"
	res, err := scanner.ScanPackage(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, false)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanPythonDeps(args []string) error {
	fs := flag.NewFlagSet("scan-python-deps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
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
		res = stripEnterprise(res, false)
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
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}

	if !*offline {
		cli.UpdateDBAsync("", "Go", "osv", 24*time.Hour)
	}

	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
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
		res = stripEnterprise(res, false)
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
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("dependency file path is required")
	}

	if !*offline {
		cli.UpdateDBAsync("", "crates.io", "osv", 24*time.Hour)
	}

	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
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
		res = stripEnterprise(res, false)
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
	mode := fs.String("mode", "", "audit, warn, or block")
	behavior := fs.String("behavior", "", "behavior analysis mode: disabled, heuristic, or isolated")
	sandbox := fs.Bool("sandbox", false, "compatibility alias for --behavior heuristic")
	timeout := fs.Duration("timeout", 10*time.Second, "behavior-analysis execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep the analysis working directory after execution")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	cli.UpdateDBAsync("", "npm", "osv", 24*time.Hour)
	if fs.NArg() != 1 {
		return errors.New("directory is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}

	behaviorMode, err := resolveBehaviorMode(fs, *behavior, *sandbox, pol)
	if err != nil {
		return err
	}
	sandboxEnabled := behaviorMode != types.BehaviorDisabled

	sandboxTimeout := *timeout
	if !flagPassed(fs, "timeout") {
		if pol.Sandbox.DefaultTimeoutSeconds > 0 {
			sandboxTimeout = time.Duration(pol.Sandbox.DefaultTimeoutSeconds) * time.Second
		} else {
			sandboxTimeout = 10 * time.Second
		}
	}

	networkMode := *network
	if !flagPassed(fs, "network") {
		if pol.Sandbox.NetworkMode != "" {
			networkMode = pol.Sandbox.NetworkMode
		} else {
			networkMode = "disabled"
		}
	}

	keepSandboxVal := *keepSandbox
	if !flagPassed(fs, "keep-sandbox") {
		keepSandboxVal = pol.Sandbox.KeepSandbox
	}

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.SandboxEnabled = sandboxEnabled
	scanner.BehaviorMode = behaviorMode
	scanner.SandboxTimeout = sandboxTimeout
	scanner.NetworkMode = networkMode
	scanner.KeepSandbox = keepSandboxVal

	res, err := scanner.ScanLocalPackage(fs.Arg(0))
	if err != nil {
		return err
	}
	res = stripEnterprise(res, false)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanNPMPackage(args []string) error {
	fs := flag.NewFlagSet("scan-npm-package", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database and metadata")
	behavior := fs.String("behavior", "", "behavior analysis mode: disabled, heuristic, or isolated")
	sandbox := fs.Bool("sandbox", false, "compatibility alias for --behavior heuristic")
	timeout := fs.Duration("timeout", 10*time.Second, "behavior-analysis execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep the analysis working directory after execution")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if !*offline {
		cli.UpdateDBAsync("", "npm", "osv", 24*time.Hour)
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}

	behaviorMode, err := resolveBehaviorMode(fs, *behavior, *sandbox, pol)
	if err != nil {
		return err
	}
	sandboxEnabled := behaviorMode != types.BehaviorDisabled

	sandboxTimeout := *timeout
	if !flagPassed(fs, "timeout") {
		if pol.Sandbox.DefaultTimeoutSeconds > 0 {
			sandboxTimeout = time.Duration(pol.Sandbox.DefaultTimeoutSeconds) * time.Second
		} else {
			sandboxTimeout = 10 * time.Second
		}
	}

	networkMode := *network
	if !flagPassed(fs, "network") {
		if pol.Sandbox.NetworkMode != "" {
			networkMode = pol.Sandbox.NetworkMode
		} else {
			networkMode = "disabled"
		}
	}

	keepSandboxVal := *keepSandbox
	if !flagPassed(fs, "keep-sandbox") {
		keepSandboxVal = pol.Sandbox.KeepSandbox
	}

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.SandboxEnabled = sandboxEnabled
	scanner.BehaviorMode = behaviorMode
	scanner.SandboxTimeout = sandboxTimeout
	scanner.NetworkMode = networkMode
	scanner.KeepSandbox = keepSandboxVal
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"

	res, err := scanner.ScanPackage(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, false)
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanLockfile(args []string) error {
	fs := flag.NewFlagSet("scan-lockfile", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	_ = fs.Bool("offline", false, "run scan offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("lockfile path is required")
	}
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}
	res, err := anpm.AnalyzeLockfile(fs.Arg(0), pol)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, false)
	logLockfileToAudit(pol, fs.Arg(0), res)
	return output.Write(os.Stdout, res, *asJSON)
}

func detectEcosystem(pkgName string, pol policy.Policy, offline bool) (string, string) {
	lowerName := strings.ToLower(pkgName)
	if strings.HasPrefix(lowerName, "npm:") {
		return "npm", pkgName[4:]
	}
	if strings.HasPrefix(lowerName, "pypi:") {
		return "pypi", pkgName[5:]
	}
	if strings.HasPrefix(lowerName, "pip:") {
		return "pypi", pkgName[4:]
	}
	if strings.HasPrefix(pkgName, "@") || strings.Contains(pkgName, "/") {
		return "npm", pkgName
	}

	// Check cache
	store, err := cache.Load("")
	if err == nil {
		_, hasNpm := store.Get("npm", pkgName, "")
		_, hasPypi := store.Get("pypi", pkgName, "")
		if hasNpm && !hasPypi {
			return "npm", pkgName
		}
		if hasPypi && !hasNpm {
			return "pypi", pkgName
		}
	}

	if offline {
		return "npm", pkgName
	}

	// Probe registries concurrently
	type probeResult struct {
		eco   string
		found bool
	}
	ch := make(chan probeResult, 2)

	// NPM Probe
	go func() {
		_, regCfg := registry.ResolveRegistry("npm", pkgName, pol)
		client := rnpm.NewClient(regCfg.URL)
		if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
			client.HTTPClient = registry.NewAuthenticatedHTTPClient(regCfg)
		}
		_, err := client.FetchMetadata(pkgName)
		ch <- probeResult{eco: "npm", found: err == nil}
	}()

	// PyPI Probe
	go func() {
		_, regCfg := registry.ResolveRegistry("pypi", pkgName, pol)
		client := rpypi.NewClient(regCfg.URL)
		if regCfg.Auth.Method != "" && regCfg.Auth.Method != "none" {
			client.HTTPClient = registry.NewAuthenticatedHTTPClient(regCfg)
		}
		_, err := client.FetchMetadata(pkgName)
		ch <- probeResult{eco: "pypi", found: err == nil}
	}()

	// Wait for both with a short timeout (e.g. 1.5s)
	timeout := time.After(1500 * time.Millisecond)
	npmFound := false
	pypiFound := false
	responses := 0

	for responses < 2 {
		select {
		case res := <-ch:
			responses++
			if res.eco == "npm" {
				npmFound = res.found
			} else {
				pypiFound = res.found
			}
		case <-timeout:
			break
		}
	}

	if npmFound && !pypiFound {
		return "npm", pkgName
	}
	if pypiFound && !npmFound {
		return "pypi", pkgName
	}
	if npmFound && pypiFound {
		// Found in both! Prompt if interactive
		if isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()) {
			fmt.Printf("Package %q found in both npm and pypi registries.\n", pkgName)
			fmt.Print("Which ecosystem did you mean?\n  1) npm\n  2) PyPI\nSelect (1-2, default 1): ")
			var choice string
			fmt.Scanln(&choice)
			if choice == "2" {
				return "pypi", pkgName
			}
			return "npm", pkgName
		}
	}

	// Default fallback
	return "npm", pkgName
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run explain offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}

	eco, cleanName := detectEcosystem(pkgName, pol, *offline)

	if eco == "pypi" {
		store, _ := cache.Load("")
		cached, hasCached := store.Get("pypi", cleanName, *ver)

		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = *offline
		scanner.RequestedBy = "human"
		scanner.Environment = "developer"
		res, err := scanner.ScanPackage(cleanName, *ver)
		if err != nil {
			if hasCached {
				cached = stripEnterprise(cached, false)
				return output.Write(os.Stdout, cached, *asJSON)
			}
			// Typo suggestion check
			npmAlts := typosquat.CheckEcosystem("npm", cleanName)
			pypiAlts := typosquat.CheckEcosystem("pypi", cleanName)
			if len(npmAlts) > 0 || len(pypiAlts) > 0 {
				color := false
				if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
					color = isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
				}
				var bold, yellow, reset string
				if color {
					bold = "\033[1m"
					yellow = "\033[33m"
					reset = "\033[0m"
				}
				fmt.Fprintf(os.Stderr, "%s⚠ Package %q not found. Did you mean one of these popular packages?%s\n", yellow, cleanName, reset)
				for _, alt := range npmAlts {
					fmt.Fprintf(os.Stderr, "  • %snpm/%s%s\n", bold, alt, reset)
				}
				for _, alt := range pypiAlts {
					fmt.Fprintf(os.Stderr, "  • %spypi/%s%s\n", bold, alt, reset)
				}
				fmt.Fprintln(os.Stderr)
			}
			return err
		}
		res = stripEnterprise(res, false)
		_ = saveResult(res)
		logExplainToAudit(pol, "explain", "pypi", res)
		if *asJSON {
			return output.Write(os.Stdout, res, true)
		}
		writeExplain(os.Stdout, res, cached, hasCached, pol)
		return nil
	}

	store, _ := cache.Load("")
	cached, hasCached := store.Get("npm", cleanName, *ver)

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	scanner.RequestedBy = "human"
	scanner.Environment = "developer"
	res, err := scanner.ScanPackage(cleanName, *ver)
	if err != nil {
		if hasCached {
			cached = stripEnterprise(cached, false)
			return output.Write(os.Stdout, cached, *asJSON)
		}
		// Typo suggestion check
		npmAlts := typosquat.CheckEcosystem("npm", cleanName)
		pypiAlts := typosquat.CheckEcosystem("pypi", cleanName)
		if len(npmAlts) > 0 || len(pypiAlts) > 0 {
			color := false
			if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
				color = isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
			}
			var bold, yellow, reset string
			if color {
				bold = "\033[1m"
				yellow = "\033[33m"
				reset = "\033[0m"
			}
			fmt.Fprintf(os.Stderr, "%s⚠ Package %q not found. Did you mean one of these popular packages?%s\n", yellow, cleanName, reset)
			for _, alt := range npmAlts {
				fmt.Fprintf(os.Stderr, "  • %snpm/%s%s\n", bold, alt, reset)
			}
			for _, alt := range pypiAlts {
				fmt.Fprintf(os.Stderr, "  • %spypi/%s%s\n", bold, alt, reset)
			}
			fmt.Fprintln(os.Stderr)
		}
		return err
	}
	res = stripEnterprise(res, false)
	_ = saveResult(res)
	logExplainToAudit(pol, "explain", "npm", res)
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
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run explain offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
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
			cached = stripEnterprise(cached, false)
			return output.Write(os.Stdout, cached, *asJSON)
		}
		// Typo suggestion check
		npmAlts := typosquat.CheckEcosystem("npm", pkgName)
		pypiAlts := typosquat.CheckEcosystem("pypi", pkgName)
		if len(npmAlts) > 0 || len(pypiAlts) > 0 {
			color := false
			if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
				color = isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
			}
			var bold, yellow, reset string
			if color {
				bold = "\033[1m"
				yellow = "\033[33m"
				reset = "\033[0m"
			}
			fmt.Fprintf(os.Stderr, "%s⚠ Package %q not found. Did you mean one of these popular packages?%s\n", yellow, pkgName, reset)
			for _, alt := range npmAlts {
				fmt.Fprintf(os.Stderr, "  • %snpm/%s%s\n", bold, alt, reset)
			}
			for _, alt := range pypiAlts {
				fmt.Fprintf(os.Stderr, "  • %spypi/%s%s\n", bold, alt, reset)
			}
			fmt.Fprintln(os.Stderr)
		}
		return err
	}
	res = stripEnterprise(res, false)
	_ = saveResult(res)
	logExplainToAudit(pol, "explain-pypi", "pypi", res)
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
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}
	res, err := scanRemoteNPM(pkgName, *ver, pol)
	if err != nil {
		return err
	}
	res = stripEnterprise(res, false)
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
	if strings.TrimSpace(policyPack) != "" {
		if LoadSignedPolicyFunc != nil {
			return LoadSignedPolicyFunc(policyPack, path, mode, registryConfig)
		}
		return policy.Policy{}, fmt.Errorf("signed policy archives are private-enterprise functionality; use pkgsafe-enterprise")
	}
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
	color := false
	if f, ok := w.(*os.File); ok {
		if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
			color = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
		}
	}

	var green, yellow, red, gray, bold, reset string
	if color {
		green = "\033[32m"
		yellow = "\033[33m"
		red = "\033[31m"
		gray = "\033[90m"
		bold = "\033[1m"
		reset = "\033[0m"
	}

	fmt.Fprintf(w, "Package: %s/%s\n", res.Package.Ecosystem, res.Package.Name)
	fmt.Fprintf(w, "Latest Known Version: %s\n", emptyLatest(res.Package.Version))

	var lastScannedVer, lastDecision string
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

	decisionColor := reset
	if color {
		switch lastDecision {
		case "ALLOW":
			decisionColor = bold + green
		case "BLOCK":
			decisionColor = bold + red
		default:
			decisionColor = bold + yellow
		}
	}
	fmt.Fprintf(w, "Last Decision: %s%s%s\n", decisionColor, lastDecision, reset)

	scoreColor := reset
	scoreLevel := "Low Risk"
	if riskScore >= 70 {
		if color {
			scoreColor = bold + red
		}
		scoreLevel = "High Risk"
	} else if riskScore >= 30 {
		if color {
			scoreColor = bold + yellow
		}
		scoreLevel = "Medium Risk"
	} else {
		if color {
			scoreColor = bold + green
		}
	}

	var scoreLegend string
	if color {
		scoreLegend = fmt.Sprintf(" %s[Scale: 0-29 %sLow%s, 30-69 %sMed%s, 70-100 %sHigh%s]%s",
			gray, green, gray, yellow, gray, red, gray, reset)
	} else {
		scoreLegend = " [Scale: 0-29 Low, 30-69 Med, 70-100 High]"
	}

	fmt.Fprintf(w, "Risk Score: %s%d/100 (%s)%s%s\n\n", scoreColor, riskScore, scoreLevel, reset, scoreLegend)

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
				sevColor := reset
				if color {
					switch sev {
					case "critical", "high":
						sevColor = red
					case "medium":
						sevColor = yellow
					default:
						sevColor = green
					}
				}
				fmt.Fprintf(w, "- %d %s%s%s %s found\n", count, sevColor, sev, reset, suffix)
			}
		}
		if len(fixedVersions) > 0 {
			fixedVersions = uniqueStrings(fixedVersions)
			fmt.Fprintf(w, "- Fixed in: %s\n", strings.Join(fixedVersions, ", "))
		}
	} else {
		summaryPrefix := "- "
		if color {
			summaryPrefix += green + "✓ " + reset
		}
		fmt.Fprintf(w, "%sNo known advisories found\n", summaryPrefix)
	}
	fmt.Fprintln(w)

	if len(res.Reasons) > 0 {
		fmt.Fprintln(w, "Top Risk Reasons:")
		for _, r := range res.Reasons {
			if r.ScoreImpact > 0 || r.ID == "trusted_package_reduction" {
				impactColor := reset
				if color {
					switch r.Severity {
					case "critical", "high":
						impactColor = red
					case "medium":
						impactColor = yellow
					default:
						impactColor = green
					}
				}
				fmt.Fprintf(w, "- [%s%s %+d%s] %s: %s\n", impactColor, r.Severity, r.ScoreImpact, reset, r.ID, r.Description)
			}
		}
		fmt.Fprintln(w)
	}

	recAction := output.RecommendedAction(res)
	recColor := reset
	if color {
		switch res.Decision {
		case "allow":
			recColor = green
		case "block":
			recColor = red
		default:
			recColor = yellow
		}
	}
	fmt.Fprintf(w, "Recommended Action:\n%s%s%s\n", recColor, recAction, reset)

	// Suggested next steps
	fmt.Fprintln(w)
	var cmdColor, suggestBold, suggestReset string
	if color {
		cmdColor = "\033[36m"
		suggestBold = "\033[1m"
		suggestReset = "\033[0m"
	}
	fmt.Fprintf(w, "%sSuggested Next Steps:%s\n", suggestBold, suggestReset)
	if res.Decision == "allow" {
		if res.Package.Ecosystem == "npm" {
			fmt.Fprintf(w, "  • Install this package safely:    %spkgsafe npm-install %s%s\n", cmdColor, res.Package.Name, suggestReset)
			fmt.Fprintf(w, "  • Try explain for Python:        %spkgsafe explain-pypi %s%s\n", cmdColor, res.Package.Name, suggestReset)
		} else if res.Package.Ecosystem == "pypi" {
			fmt.Fprintf(w, "  • Install this package safely:    %spkgsafe pip install %s%s\n", cmdColor, res.Package.Name, suggestReset)
			fmt.Fprintf(w, "  • Try explain for npm:           %spkgsafe explain %s%s\n", cmdColor, res.Package.Name, suggestReset)
		}
	} else {
		fmt.Fprintf(w, "  • Review active scanning policy:  %spkgsafe policy explain <policy-path>%s\n", cmdColor, suggestReset)
		fmt.Fprintf(w, "  • Check registry configurations:  %spkgsafe registry list%s\n", cmdColor, suggestReset)
	}
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
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	return cli.UpdateDB("", *eco, *src)
}

func cmdDB(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown subcommand. usage: pkgsafe db [status|export-bundle|verify-bundle|import-bundle]")
	}
	switch args[0] {
	case "status":
		return cmdDBStatus(args[1:])
	case "export-bundle":
		return cmdDBExportBundle(args[1:])
	case "verify-bundle":
		return cmdDBVerifyBundle(args[1:])
	case "import-bundle":
		return cmdDBImportBundle(args[1:])
	default:
		return fmt.Errorf("unknown db subcommand %q", args[0])
	}
}

func cmdDBStatus(args []string) error {
	fs := flag.NewFlagSet("db-status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	return cli.DBStatusWithOptions("", *asJSON)
}

func cmdDBExportBundle(args []string) error {
	fs := flag.NewFlagSet("db-export-bundle", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to PkgSafe SQLite database")
	outputPath := fs.String("output", "", "path to write offline intelligence bundle")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if *outputPath == "" {
		return fmt.Errorf("usage: pkgsafe db export-bundle --output <path> [--db <path>]")
	}
	manifest, err := dbbundle.Export(*dbPath, *outputPath)
	if err != nil {
		return err
	}
	fmt.Println("Offline intelligence bundle exported.")
	fmt.Printf("Output: %s\n", *outputPath)
	fmt.Printf("Vulnerability records: %d\n", manifest.VulnerabilityCount)
	fmt.Printf("Indexed packages: %d\n", manifest.IndexedPackageCount)
	fmt.Printf("Signed: %s\n", boolEnabled(manifest.Signature.Present))
	return nil
}

func cmdDBVerifyBundle(args []string) error {
	fs := flag.NewFlagSet("db-verify-bundle", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pkgsafe db verify-bundle [--json] <path>")
	}
	res, err := dbbundle.Verify(fs.Arg(0))
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	fmt.Println("Offline intelligence bundle verified.")
	fmt.Printf("Bundle: %s\n", fs.Arg(0))
	fmt.Printf("Checksum: %s\n", boolEnabled(res.ChecksumOK))
	fmt.Printf("Signature present: %s\n", boolEnabled(res.SignaturePresent))
	fmt.Printf("Signature verified: %s\n", boolEnabled(res.SignatureVerified))
	fmt.Printf("Vulnerability records: %d\n", res.Manifest.VulnerabilityCount)
	fmt.Printf("Indexed packages: %d\n", res.Manifest.IndexedPackageCount)
	fmt.Printf("Generated at: %s\n", res.Manifest.GeneratedAt)
	printBundleFreshness(res)
	return nil
}

func printBundleFreshness(res dbbundle.VerifyResult) {
	for _, key := range dbbundle.LastUpdateKeys {
		if status, ok := res.FreshnessAtVerify[key]; ok {
			fmt.Printf("Freshness (%s): %s\n", key, status)
		}
	}
	if res.Stale {
		fmt.Println("Bundle advisory data is stale: export a fresher bundle from a recently synced database.")
	}
}

func cmdDBImportBundle(args []string) error {
	fs := flag.NewFlagSet("db-import-bundle", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to write PkgSafe SQLite database")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pkgsafe db import-bundle [--db <path>] <path>")
	}
	res, err := dbbundle.Import(fs.Arg(0), *dbPath)
	if err != nil {
		return err
	}
	fmt.Println("Offline intelligence bundle imported.")
	fmt.Printf("Bundle: %s\n", fs.Arg(0))
	fmt.Printf("Checksum: %s\n", boolEnabled(res.ChecksumOK))
	fmt.Printf("Signature verified: %s\n", boolEnabled(res.SignatureVerified))
	fmt.Printf("Vulnerability records: %d\n", res.Manifest.VulnerabilityCount)
	printBundleFreshness(res)
	return nil
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	skipNetwork := fs.Bool("skip-network", false, "skip OSV network availability check")
	fix := fs.Bool("fix", false, "attempt to automatically fix warning or failing states")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	return cli.Doctor(cli.DoctorOptions{
		PolicyPath:     *policyPath,
		RegistryConfig: *registryConfig,
		SkipNetwork:    *skipNetwork,
		JSON:           *asJSON,
		Fix:            *fix,
	})
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
	case "version", "mode", "policy", "log-level", "timeout", "network", "behavior",
		"lockfile", "dependency-file", "ecosystem", "fail-on", "json-output", "sarif-output", "summary-output", "baseline", "registry-config", "port", "token",
		"base", "repo", "repo-list", "fixtures", "definitions", "db", "output", "signing-key", "key",
		"decision", "limit":
		return true
	default:
		return false
	}
}

func cmdCIScan(cfg RunConfig, args []string) error {
	fs := flag.NewFlagSet("ci-scan", flag.ContinueOnError)
	lockfile := fs.String("lockfile", "package-lock.json", "path to package-lock.json")
	dependencyFile := fs.String("dependency-file", "", "path to dependency file")
	ecosystem := fs.String("ecosystem", "", "package ecosystem: npm or pypi")
	policyPath := fs.String("policy", "", "path to PkgSafe policy file")
	mode := fs.String("mode", "", "PkgSafe mode: audit, warn, or block")
	failOn := fs.String("fail-on", "", "minimum decision that fails the workflow: none, warn, block")
	jsonOutput := fs.String("json-output", "", "path to write JSON report")
	sarifOutput := fs.String("sarif-output", "", "path to write SARIF report")
	summaryOutput := fs.String("summary-output", "", "path to write Markdown summary")
	changedOnly := fs.Bool("changed-only", false, "only scan changed dependencies")
	baseline := fs.String("baseline", "main", "baseline Git ref or package-lock JSON file for diffing")
	behavior := fs.String("behavior", "", "behavior analysis mode: disabled, heuristic, or isolated")
	sandbox := fs.Bool("sandbox", false, "compatibility alias for --behavior heuristic")
	offline := fs.Bool("offline", false, "use offline database only")
	timeout := fs.Duration("timeout", 0, "behavior-analysis timeout")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")

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
		BehaviorMode:         *behavior,
		Offline:              *offline,
		Timeout:              *timeout,
		PolicyPack:           "",
		RegistryConfigPath:   *registryConfig,
		EnterpriseMode:       cfg.CIEnterpriseMode,
	}

	res, err := ciRunScanFunc(opts)
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
	repoList := fs.String("repo-list", "", "JSON file listing real repositories to validate")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	rep, err := validation.RunBenchmarkPackWithOptions(validation.BenchmarkOptions{
		FixturesDir:    *fixturesDir,
		DefinitionsDir: *definitionsDir,
		Update:         *update,
		Offline:        *offline,
		RepoPath:       *repoPath,
		RepoListPath:   *repoList,
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

func cmdTestProductionReadiness(args []string) error {
	fs := flag.NewFlagSet("test-production-readiness", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	fixturesDir := fs.String("fixtures", "testdata/benchmarks", "directory for benchmark fixtures")
	repo := fs.String("repo", "", "optional real repository path to validate (feeds real_repo_validation_count)")
	repoList := fs.String("repo-list", "", "JSON file listing real repositories to validate")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	opts := validation.ProductionReadinessOptions{
		CorpusDir:    "testdata/corpus",
		GoldenFile:   "testdata/corpus-golden.json",
		BenchmarkDir: *fixturesDir,
	}
	if *repo != "" {
		opts.RealRepos = []string{*repo}
	}
	if *repoList != "" {
		opts.RepoListPath = *repoList
	}
	rep, err := validation.RunProductionReadinessWithOptions(opts)
	if err != nil {
		return err
	}
	if err := validation.WriteProductionReadiness(os.Stdout, rep, *asJSON); err != nil {
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

func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "limit number of history entries shown")
	decision := fs.String("decision", "", "filter by decision (allow, warn, block)")
	clear := fs.Bool("clear", false, "clear history logs")
	asJSON := fs.Bool("json", false, "write output as JSON")
	policyPath := fs.String("policy", "", "policy YAML path")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	pol, _ := loadPolicy(*policyPath, "", "", *registryConfig)
	logPath := "~/.pkgsafe/audit.log"
	if pol.InstallInterception.AuditLogPath != "" {
		logPath = pol.InstallInterception.AuditLogPath
	}
	absPath := audit.ExpandHome(logPath)

	if *clear {
		err := os.Remove(absPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear history: %w", err)
		}
		fmt.Println("PkgSafe audit history cleared.")
		return nil
	}

	entries, err := audit.ReadAuditLog(logPath)
	if err != nil {
		return err
	}

	filtered := []audit.AuditEntry{}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if *decision != "" {
			matches := false
			for _, pkg := range entry.Packages {
				if strings.EqualFold(pkg.Decision, *decision) {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}
		filtered = append(filtered, entry)
		if len(filtered) >= *limit {
			break
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(filtered)
	}

	if len(filtered) == 0 {
		fmt.Println("No history entries found.")
		return nil
	}

	var bold, green, red, yellow, reset string
	color := false
	if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		color = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	}
	if color {
		bold = "\033[1m"
		green = "\033[32m"
		red = "\033[31m"
		yellow = "\033[33m"
		reset = "\033[0m"
	}

	fmt.Printf("%sPkgSafe Audit History (newest first):%s\n", bold, reset)
	fmt.Printf("  %-20s %-32s %-8s %-16s\n", "TIMESTAMP", "COMMAND / ACTION", "DECISION", "PACKAGES")
	fmt.Println(strings.Repeat("-", 90))

	for _, entry := range filtered {
		aggDecision := "ALLOW"
		for _, p := range entry.Packages {
			if strings.EqualFold(p.Decision, "block") {
				aggDecision = "BLOCK"
				break
			}
			if strings.EqualFold(p.Decision, "warn") {
				aggDecision = "WARN"
			}
		}

		decColor := green
		if aggDecision == "BLOCK" {
			decColor = red
		} else if aggDecision == "WARN" {
			decColor = yellow
		}

		cmd := entry.Command
		if len(cmd) > 32 {
			cmd = cmd[:29] + "..."
		}

		var pkgNames []string
		for _, p := range entry.Packages {
			pName := p.Name
			if p.Version != "" {
				pName = pName + "@" + p.Version
			}
			pkgNames = append(pkgNames, pName)
		}
		pkgStr := strings.Join(pkgNames, ", ")
		if len(pkgStr) > 24 {
			pkgStr = pkgStr[:21] + "..."
		}
		if pkgStr == "" {
			pkgStr = "-"
		}

		tStr := entry.Timestamp
		if len(tStr) >= 19 {
			tStr = strings.Replace(tStr[:19], "T", " ", 1)
		}

		fmt.Printf("  %-20s %-32s %s%-8s%s %-16s\n", 
			tStr, 
			cmd, 
			decColor, aggDecision, reset, 
			pkgStr,
		)
	}
	fmt.Println()

	return nil
}

func logExplainToAudit(pol policy.Policy, cmd, eco string, res types.ScanResult) {
	auditPkg := intercept.AuditPackage{
		Name:      res.Package.Name,
		Version:   res.Package.Version,
		Decision:  string(res.Decision),
		RiskScore: res.Score,
	}
	auditEntry := intercept.AuditEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Command:         "pkgsafe " + cmd + " " + res.Package.Name,
		Ecosystem:       eco,
		Packages:        []intercept.AuditPackage{auditPkg},
		Mode:            string(pol.Mode),
		InstallExecuted: false,
	}
	_ = intercept.LogAudit(pol, auditEntry)
}

func logLockfileToAudit(pol policy.Policy, path string, res types.ScanResult) {
	var auditPkgs []intercept.AuditPackage
	for _, r := range res.Reasons {
		if r.ID == "lockfile_summary" || r.ID == "score_clamped" || r.ID == "large_dependency_graph" || r.ID == "empty_lockfile" {
			continue
		}
		dec := "ALLOW"
		score := 0
		if r.ID == "blocked_package" || r.ID == "known_malware_indicator" || strings.HasPrefix(r.ID, "known_vulnerability_high") || strings.HasPrefix(r.ID, "known_vulnerability_critical") {
			dec = "BLOCK"
			score = 100
		} else {
			dec = "WARN"
			score = 30
		}
		name := r.Evidence
		version := ""
		if strings.Contains(name, "@") {
			parts := strings.SplitN(name, "@", 2)
			name = parts[0]
			version = parts[1]
		}
		auditPkgs = append(auditPkgs, intercept.AuditPackage{
			Name:      name,
			Version:   version,
			Decision:  dec,
			RiskScore: score,
		})
	}

	auditEntry := intercept.AuditEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Command:         "pkgsafe scan-lockfile " + path,
		Ecosystem:       "npm-lock",
		Packages:        auditPkgs,
		Mode:            string(pol.Mode),
		InstallExecuted: false,
	}
	_ = intercept.LogAudit(pol, auditEntry)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run scan offline using cached database")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	} else if fs.NArg() > 1 {
		return errors.New("usage: pkgsafe scan [dir]")
	}

	pol, err := loadPolicy(*policyPath, *mode, "", *registryConfig)
	if err != nil {
		return err
	}

	if !*offline {
		cli.UpdateDBAsync("", "", "osv", 24*time.Hour)
	}

	type fileScanResult struct {
		file     string
		eco      string
		decision string
		score    int
		findings string
	}

	var results []fileScanResult
	var jsonResults []interface{}

	// 1. package-lock.json
	lockfilePath := filepath.Join(dir, "package-lock.json")
	if _, err := os.Stat(lockfilePath); err == nil {
		res, err := anpm.AnalyzeLockfile(lockfilePath, pol)
		if err == nil {
			res = stripEnterprise(res, false)
			logLockfileToAudit(pol, lockfilePath, res)
			jsonResults = append(jsonResults, res)
			
			findings := "clean"
			if len(res.Reasons) > 0 {
				var fList []string
				for _, r := range res.Reasons {
					if r.ID != "lockfile_summary" && r.ID != "score_clamped" && r.ID != "large_dependency_graph" && r.ID != "empty_lockfile" {
						fList = append(fList, r.ID)
					}
				}
				if len(fList) > 0 {
					findings = strings.Join(unique(fList), ", ")
				}
			}
			results = append(results, fileScanResult{
				file:     "package-lock.json",
				eco:      "npm",
				decision: string(res.Decision),
				score:    res.Score,
				findings: findings,
			})
		}
	} else {
		pkgJsonPath := filepath.Join(dir, "package.json")
		if _, err := os.Stat(pkgJsonPath); err == nil {
			scanner := snpm.New()
			scanner.Policy = pol
			res, err := scanner.ScanLocalPackage(dir)
			if err == nil {
				res = stripEnterprise(res, false)
				_ = saveResult(res)
				logExplainToAudit(pol, "scan-local-npm", "npm", res)
				jsonResults = append(jsonResults, res)
				
				findings := "clean"
				if len(res.Reasons) > 0 {
					var fList []string
					for _, r := range res.Reasons {
						if r.ID != "score_clamped" {
							fList = append(fList, r.ID)
						}
					}
					findings = strings.Join(unique(fList), ", ")
				}
				results = append(results, fileScanResult{
					file:     "package.json",
					eco:      "npm",
					decision: string(res.Decision),
					score:    res.Score,
					findings: findings,
				})
			}
		}
	}

	// 2. Cargo.lock
	cargoPath := filepath.Join(dir, "Cargo.lock")
	if _, err := os.Stat(cargoPath); err == nil {
		b, err := os.ReadFile(cargoPath)
		if err == nil {
			deps, err := cargodeps.ParseCargoLock(b)
			if err == nil {
				scanner := scargo.New()
				scanner.Policy = pol
				scanner.Offline = *offline
				
				var subResults []types.ScanResult
				worstScore := 0
				aggDecision := "ALLOW"
				var fList []string
				
				for _, dep := range deps {
					res, err := scanner.ScanPackage(dep.Name, dep.Version)
					if err == nil {
						res = stripEnterprise(res, false)
						_ = saveResult(res)
						subResults = append(subResults, res)
						if res.Score > worstScore {
							worstScore = res.Score
						}
						if res.Decision == types.DecisionBlock {
							aggDecision = "BLOCK"
						} else if res.Decision == types.DecisionWarn && aggDecision != "BLOCK" {
							aggDecision = "WARN"
						}
						for _, r := range res.Reasons {
							fList = append(fList, r.ID)
						}
					}
				}
				logDependenciesToAudit(pol, "pkgsafe scan-cargo-deps "+cargoPath, "cargo-lock", subResults)
				jsonResults = append(jsonResults, map[string]interface{}{
					"file":    "Cargo.lock",
					"results": subResults,
				})
				
				findings := "clean"
				if len(fList) > 0 {
					findings = strings.Join(unique(fList), ", ")
				}
				results = append(results, fileScanResult{
					file:     "Cargo.lock",
					eco:      "cargo",
					decision: aggDecision,
					score:    worstScore,
					findings: findings,
				})
			}
		}
	}

	// 3. go.mod
	goModPath := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		b, err := os.ReadFile(goModPath)
		if err == nil {
			deps, err := godeps.ParseGoMod(b)
			if err == nil {
				scanner := sgolang.New()
				scanner.Policy = pol
				scanner.Offline = *offline
				
				var subResults []types.ScanResult
				worstScore := 0
				aggDecision := "ALLOW"
				var fList []string
				
				for _, dep := range deps {
					res, err := scanner.ScanPackage(dep.Name, dep.Version)
					if err == nil {
						res = stripEnterprise(res, false)
						_ = saveResult(res)
						subResults = append(subResults, res)
						if res.Score > worstScore {
							worstScore = res.Score
						}
						if res.Decision == types.DecisionBlock {
							aggDecision = "BLOCK"
						} else if res.Decision == types.DecisionWarn && aggDecision != "BLOCK" {
							aggDecision = "WARN"
						}
						for _, r := range res.Reasons {
							fList = append(fList, r.ID)
						}
					}
				}
				logDependenciesToAudit(pol, "pkgsafe scan-go-deps "+goModPath, "go-mod", subResults)
				jsonResults = append(jsonResults, map[string]interface{}{
					"file":    "go.mod",
					"results": subResults,
				})
				
				findings := "clean"
				if len(fList) > 0 {
					findings = strings.Join(unique(fList), ", ")
				}
				results = append(results, fileScanResult{
					file:     "go.mod",
					eco:      "golang",
					decision: aggDecision,
					score:    worstScore,
					findings: findings,
				})
			}
		}
	}

	// 4. requirements.txt
	reqPath := filepath.Join(dir, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		deps, err := pydeps.ParseFile(reqPath)
		if err == nil {
			scanner := spypi.New()
			scanner.Policy = pol
			scanner.Offline = *offline
			
			var subResults []types.ScanResult
			worstScore := 0
			aggDecision := "ALLOW"
			var fList []string
			
			for _, dep := range deps {
				res, err := scanner.ScanPackage(dep.Name, dep.Version)
				if err == nil {
					res = stripEnterprise(res, false)
					_ = saveResult(res)
					subResults = append(subResults, res)
					if res.Score > worstScore {
						worstScore = res.Score
					}
					if res.Decision == types.DecisionBlock {
						aggDecision = "BLOCK"
					} else if res.Decision == types.DecisionWarn && aggDecision != "BLOCK" {
						aggDecision = "WARN"
					}
					for _, r := range res.Reasons {
						fList = append(fList, r.ID)
					}
				}
			}
			logDependenciesToAudit(pol, "pkgsafe scan-python-deps "+reqPath, "python-requirements", subResults)
			jsonResults = append(jsonResults, map[string]interface{}{
				"file":    "requirements.txt",
				"results": subResults,
			})
			
			findings := "clean"
			if len(fList) > 0 {
				findings = strings.Join(unique(fList), ", ")
			}
			results = append(results, fileScanResult{
				file:     "requirements.txt",
				eco:      "pypi",
				decision: aggDecision,
				score:    worstScore,
				findings: findings,
			})
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonResults)
	}

	var bold, green, red, yellow, reset string
	color := false
	if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		color = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	}
	if color {
		bold = "\033[1m"
		green = "\033[32m"
		red = "\033[31m"
		yellow = "\033[33m"
		reset = "\033[0m"
	}

	absDir, _ := filepath.Abs(dir)
	fmt.Printf("%sPkgSafe Workspace Scan%s\n", bold, reset)
	fmt.Printf("======================\n")
	fmt.Printf("Directory: %s\n\n", absDir)

	if len(results) == 0 {
		fmt.Println("No supported project files found to scan.")
		return nil
	}

	fmt.Printf("%sScan Results:%s\n", bold, reset)
	fmt.Printf("  %-20s %-8s %-12s %-24s\n", "FILE", "DECISION", "WORST SCORE", "FINDINGS")
	fmt.Println(strings.Repeat("-", 76))

	for _, r := range results {
		decColor := green
		if strings.EqualFold(r.decision, "BLOCK") {
			decColor = red
		} else if strings.EqualFold(r.decision, "WARN") {
			decColor = yellow
		}
		
		findingsStr := r.findings
		if len(findingsStr) > 24 {
			findingsStr = findingsStr[:21] + "..."
		}

		fmt.Printf("  %-20s %s%-8s%s %-12d %-24s\n", 
			r.file, 
			decColor, r.decision, reset, 
			r.score, 
			findingsStr,
		)
	}
	fmt.Println()

	hasBlock := false
	for _, r := range results {
		if strings.EqualFold(r.decision, "BLOCK") {
			hasBlock = true
		}
	}
	if hasBlock {
		return fmt.Errorf("scan failed: one or more project files violate policy")
	}

	return nil
}

func unique(in []string) []string {
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

func logDependenciesToAudit(pol policy.Policy, cmd, ecosystem string, subResults []types.ScanResult) {
	var auditPkgs []intercept.AuditPackage
	for _, res := range subResults {
		auditPkgs = append(auditPkgs, intercept.AuditPackage{
			Name:      res.Package.Name,
			Version:   res.Package.Version,
			Decision:  string(res.Decision),
			RiskScore: res.Score,
		})
	}
	auditEntry := intercept.AuditEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Command:         cmd,
		Ecosystem:       ecosystem,
		Packages:        auditPkgs,
		Mode:            string(pol.Mode),
		InstallExecuted: false,
	}
	_ = intercept.LogAudit(pol, auditEntry)
}

func cmdPolicyEdit(args []string) error {
	fs := flag.NewFlagSet("policy-edit", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy YAML path")
	registryConfig := fs.String("registry-config", "", "path to registries.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	polPath := "~/.pkgsafe/policy.yaml"
	if *policyPath != "" {
		polPath = *policyPath
	}
	absPath := audit.ExpandHome(polPath)

	pol, err := loadPolicy(polPath, "", "", *registryConfig)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
			fmt.Printf("Policy file %s not found. Creating default policy...\n", polPath)
			err = os.MkdirAll(filepath.Dir(absPath), 0755)
			if err != nil {
				return err
			}
			err = writePolicyToYAML(absPath, policy.Default())
			if err != nil {
				return err
			}
			pol, err = loadPolicy(polPath, "", "", *registryConfig)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n========================================")
		fmt.Printf("      PkgSafe Policy Editor Wizard      \n")
		fmt.Printf("  Editing: %s\n", absPath)
		fmt.Println("========================================")
		fmt.Printf("  1) Change Mode (current: %s)\n", pol.Mode)
		fmt.Printf("  2) Manage Trusted Packages (NPM: %d, PyPI: %d)\n", len(pol.TrustedPackages.NPM), len(pol.TrustedPackages.PyPI))
		fmt.Printf("  3) Manage Blocked Packages (NPM: %d, PyPI: %d)\n", len(pol.BlockedPackages.NPM), len(pol.BlockedPackages.PyPI))
		fmt.Printf("  4) Change Threat Score Thresholds (Allow Max: %d, Warn Max: %d, Block Min: %d)\n",
			pol.Thresholds.AllowMaxScore, pol.Thresholds.WarnMaxScore, pol.Thresholds.BlockMinScore)
		fmt.Printf("  5) Toggle Ecosystems (NPM: %t, PyPI: %t)\n", pol.Ecosystems.NPM.Enabled, pol.Ecosystems.PyPI.Enabled)
		fmt.Println("  6) Save Changes and Exit")
		fmt.Println("  7) Cancel and Exit without Saving")
		fmt.Print("\nChoose an option (1-7): ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Print("\nEnter new mode (warn, block, audit): ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(strings.ToLower(val))
			if val == "warn" || val == "block" || val == "audit" {
				pol.Mode = policy.Mode(val)
				fmt.Printf("Mode updated to: %s\n", pol.Mode)
			} else {
				fmt.Println("Invalid mode. Choose from: warn, block, audit")
			}

		case "2":
			fmt.Println("\n--- Manage Trusted Packages ---")
			fmt.Println("  1) Add NPM Package")
			fmt.Println("  2) Remove NPM Package")
			fmt.Println("  3) Add PyPI Package")
			fmt.Println("  4) Remove PyPI Package")
			fmt.Println("  5) Back")
			fmt.Print("Choose an option: ")
			subChoice, _ := reader.ReadString('\n')
			subChoice = strings.TrimSpace(subChoice)

			switch subChoice {
			case "1":
				fmt.Print("Enter NPM package name to TRUST: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				if pkg != "" {
					pol.TrustedPackages.NPM = append(pol.TrustedPackages.NPM, pkg)
					fmt.Printf("Added NPM package to Trusted List: %s\n", pkg)
				}
			case "2":
				fmt.Print("Enter NPM package name to REMOVE from Trust: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				found := false
				var newList []string
				for _, p := range pol.TrustedPackages.NPM {
					if p != pkg {
						newList = append(newList, p)
					} else {
						found = true
					}
				}
				if found {
					pol.TrustedPackages.NPM = newList
					fmt.Printf("Removed NPM package from Trusted List: %s\n", pkg)
				} else {
					fmt.Println("Package not found in list.")
				}
			case "3":
				fmt.Print("Enter PyPI package name to TRUST: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				if pkg != "" {
					pol.TrustedPackages.PyPI = append(pol.TrustedPackages.PyPI, pkg)
					fmt.Printf("Added PyPI package to Trusted List: %s\n", pkg)
				}
			case "4":
				fmt.Print("Enter PyPI package name to REMOVE from Trust: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				found := false
				var newList []string
				for _, p := range pol.TrustedPackages.PyPI {
					if p != pkg {
						newList = append(newList, p)
					} else {
						found = true
					}
				}
				if found {
					pol.TrustedPackages.PyPI = newList
					fmt.Printf("Removed PyPI package from Trusted List: %s\n", pkg)
				} else {
					fmt.Println("Package not found in list.")
				}
			}

		case "3":
			fmt.Println("\n--- Manage Blocked Packages ---")
			fmt.Println("  1) Add NPM Package")
			fmt.Println("  2) Remove NPM Package")
			fmt.Println("  3) Add PyPI Package")
			fmt.Println("  4) Remove PyPI Package")
			fmt.Println("  5) Back")
			fmt.Print("Choose an option: ")
			subChoice, _ := reader.ReadString('\n')
			subChoice = strings.TrimSpace(subChoice)

			switch subChoice {
			case "1":
				fmt.Print("Enter NPM package name to BLOCK: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				if pkg != "" {
					pol.BlockedPackages.NPM = append(pol.BlockedPackages.NPM, pkg)
					fmt.Printf("Added NPM package to Block List: %s\n", pkg)
				}
			case "2":
				fmt.Print("Enter NPM package name to REMOVE from Block list: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				found := false
				var newList []string
				for _, p := range pol.BlockedPackages.NPM {
					if p != pkg {
						newList = append(newList, p)
					} else {
						found = true
					}
				}
				if found {
					pol.BlockedPackages.NPM = newList
					fmt.Printf("Removed NPM package from Block List: %s\n", pkg)
				} else {
					fmt.Println("Package not found in list.")
				}
			case "3":
				fmt.Print("Enter PyPI package name to BLOCK: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				if pkg != "" {
					pol.BlockedPackages.PyPI = append(pol.BlockedPackages.PyPI, pkg)
					fmt.Printf("Added PyPI package to Block List: %s\n", pkg)
				}
			case "4":
				fmt.Print("Enter PyPI package name to REMOVE from Block list: ")
				pkg, _ := reader.ReadString('\n')
				pkg = strings.TrimSpace(pkg)
				found := false
				var newList []string
				for _, p := range pol.BlockedPackages.PyPI {
					if p != pkg {
						newList = append(newList, p)
					} else {
						found = true
					}
				}
				if found {
					pol.BlockedPackages.PyPI = newList
					fmt.Printf("Removed PyPI package from Block List: %s\n", pkg)
				} else {
					fmt.Println("Package not found in list.")
				}
			}

		case "4":
			fmt.Println("\n--- Change Threat Score Thresholds ---")
			fmt.Printf("Current: Allow Max = %d, Warn Max = %d, Block Min = %d\n",
				pol.Thresholds.AllowMaxScore, pol.Thresholds.WarnMaxScore, pol.Thresholds.BlockMinScore)
			
			fmt.Print("Enter new Allow Max Score (e.g. 29): ")
			allowStr, _ := reader.ReadString('\n')
			allowVal, err1 := strconv.Atoi(strings.TrimSpace(allowStr))

			fmt.Print("Enter new Warn Max Score (e.g. 69): ")
			warnStr, _ := reader.ReadString('\n')
			warnVal, err2 := strconv.Atoi(strings.TrimSpace(warnStr))

			fmt.Print("Enter new Block Min Score (e.g. 70): ")
			blockStr, _ := reader.ReadString('\n')
			blockVal, err3 := strconv.Atoi(strings.TrimSpace(blockStr))

			if err1 == nil && err2 == nil && err3 == nil {
				pol.Thresholds.AllowMaxScore = allowVal
				pol.Thresholds.WarnMaxScore = warnVal
				pol.Thresholds.BlockMinScore = blockVal
				fmt.Println("Thresholds updated successfully!")
			} else {
				fmt.Println("Invalid input. All scores must be integers.")
			}

		case "5":
			fmt.Println("\n--- Toggle Ecosystems ---")
			fmt.Printf("  1) Toggle NPM (current: %t)\n", pol.Ecosystems.NPM.Enabled)
			fmt.Printf("  2) Toggle PyPI (current: %t)\n", pol.Ecosystems.PyPI.Enabled)
			fmt.Print("Choose an option (1-2): ")
			subChoice, _ := reader.ReadString('\n')
			subChoice = strings.TrimSpace(subChoice)
			if subChoice == "1" {
				pol.Ecosystems.NPM.Enabled = !pol.Ecosystems.NPM.Enabled
				fmt.Printf("NPM enabled set to: %t\n", pol.Ecosystems.NPM.Enabled)
			} else if subChoice == "2" {
				pol.Ecosystems.PyPI.Enabled = !pol.Ecosystems.PyPI.Enabled
				fmt.Printf("PyPI enabled set to: %t\n", pol.Ecosystems.PyPI.Enabled)
			}

		case "6":
			err := writePolicyToYAML(absPath, pol)
			if err != nil {
				return fmt.Errorf("save policy: %w", err)
			}
			fmt.Printf("\nPolicy changes saved successfully to %s\n", absPath)
			return nil

		case "7":
			fmt.Println("\nExited without saving.")
			return nil
		}
	}
}

func writePolicyToYAML(path string, pol policy.Policy) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("schema_version: %q\n\n", pol.SchemaVersion))
	sb.WriteString(fmt.Sprintf("mode: %s\n\n", pol.Mode))

	sb.WriteString("thresholds:\n")
	sb.WriteString(fmt.Sprintf("  allow_max_score: %d\n", pol.Thresholds.AllowMaxScore))
	sb.WriteString(fmt.Sprintf("  warn_max_score: %d\n", pol.Thresholds.WarnMaxScore))
	sb.WriteString(fmt.Sprintf("  block_min_score: %d\n\n", pol.Thresholds.BlockMinScore))

	sb.WriteString("ecosystems:\n")
	sb.WriteString(fmt.Sprintf("  npm:\n    enabled: %t\n", pol.Ecosystems.NPM.Enabled))
	sb.WriteString(fmt.Sprintf("  pypi:\n    enabled: %t\n\n", pol.Ecosystems.PyPI.Enabled))

	sb.WriteString("sandbox:\n")
	sb.WriteString(fmt.Sprintf("  enabled: %t\n", pol.Sandbox.Enabled))
	sb.WriteString(fmt.Sprintf("  behavior_mode: %q\n", pol.Sandbox.BehaviorMode))
	sb.WriteString(fmt.Sprintf("  default_timeout_seconds: %d\n", pol.Sandbox.DefaultTimeoutSeconds))
	sb.WriteString(fmt.Sprintf("  network_mode: %q\n", pol.Sandbox.NetworkMode))
	sb.WriteString(fmt.Sprintf("  keep_sandbox: %t\n", pol.Sandbox.KeepSandbox))
	sb.WriteString(fmt.Sprintf("  fail_open_when_unavailable: %t\n\n", pol.Sandbox.FailOpenWhenUnavailable))

	if len(pol.ProtectedPaths) > 0 {
		sb.WriteString("protected_paths:\n")
		for _, p := range pol.ProtectedPaths {
			sb.WriteString(fmt.Sprintf("  - %q\n", p))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("trusted_packages:\n")
	if len(pol.TrustedPackages.NPM) > 0 {
		sb.WriteString("  npm:\n")
		for _, p := range pol.TrustedPackages.NPM {
			sb.WriteString(fmt.Sprintf("    - %s\n", p))
		}
	} else {
		sb.WriteString("  npm: []\n")
	}
	if len(pol.TrustedPackages.PyPI) > 0 {
		sb.WriteString("  pypi:\n")
		for _, p := range pol.TrustedPackages.PyPI {
			sb.WriteString(fmt.Sprintf("    - %s\n", p))
		}
	} else {
		sb.WriteString("  pypi: []\n")
	}
	sb.WriteString("\n")

	sb.WriteString("blocked_packages:\n")
	if len(pol.BlockedPackages.NPM) > 0 {
		sb.WriteString("  npm:\n")
		for _, p := range pol.BlockedPackages.NPM {
			sb.WriteString(fmt.Sprintf("    - %s\n", p))
		}
	} else {
		sb.WriteString("  npm: []\n")
	}
	if len(pol.BlockedPackages.PyPI) > 0 {
		sb.WriteString("  pypi:\n")
		for _, p := range pol.BlockedPackages.PyPI {
			sb.WriteString(fmt.Sprintf("    - %s\n", p))
		}
	} else {
		sb.WriteString("  pypi: []\n")
	}
	sb.WriteString("\n")

	if len(pol.Rules) > 0 {
		sb.WriteString("rules:\n")
		var keys []string
		for k := range pol.Rules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r := pol.Rules[k]
			sb.WriteString(fmt.Sprintf("  %s:\n", k))
			sb.WriteString(fmt.Sprintf("    enabled: %t\n", r.Enabled))
			sb.WriteString(fmt.Sprintf("    severity: %s\n", r.Severity))
			sb.WriteString(fmt.Sprintf("    score: %d\n", r.Score))
			if r.MaxAgeDays > 0 {
				sb.WriteString(fmt.Sprintf("    max_age_days: %d\n", r.MaxAgeDays))
			}
			if r.BlockInStrictMode {
				sb.WriteString(fmt.Sprintf("    block_in_strict_mode: %t\n", r.BlockInStrictMode))
			}
			sb.WriteString("\n")
		}
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
