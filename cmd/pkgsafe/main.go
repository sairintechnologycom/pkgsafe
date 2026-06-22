package main

import (
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
	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/ci"
	"github.com/niyam-ai/pkgsafe/internal/cli"
	"github.com/niyam-ai/pkgsafe/internal/mcp"
	"github.com/niyam-ai/pkgsafe/internal/output"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

var version = "0.1.0"
var commit = "local"

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
	case "scan-lockfile":
		return cmdScanLockfile(args[1:])
	case "explain":
		return cmdExplain(args[1:])
	case "npm-install":
		return cmdNPMInstall(args[1:])
	case "mcp":
		return cmdMCP(args[1:])
	case "update-db":
		return cmdUpdateDB(args[1:])
	case "db":
		if len(args) > 1 && args[1] == "status" {
			return cmdDBStatus(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe db status")
	case "ci":
		if len(args) > 1 && args[1] == "scan" {
			return cmdCIScan(args[2:])
		}
		return fmt.Errorf("unknown subcommand. usage: pkgsafe ci scan")
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`PkgSafe - local-first package safety CLI

Usage:
  pkgsafe scan-local-npm <dir> [--json]
  pkgsafe scan-npm-package <name> [--version <version>] [--policy <path>] [--mode warn|block|audit] [--json]
  pkgsafe scan-lockfile <package-lock.json> [--json]
  pkgsafe explain <name> [--version <version>] [--policy <path>]
  pkgsafe npm-install <name> [--version <version>] [--mode warn|block|audit]
  pkgsafe ci scan [--lockfile <path>] [--policy <path>] [--mode audit|warn|block] [--fail-on none|warn|block]
  pkgsafe mcp serve
  pkgsafe version
`)
}

func cmdScanLocalNPM(args []string) error {
	fs := flag.NewFlagSet("scan-local-npm", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	sandbox := fs.Bool("sandbox", false, "run lifecycle scripts in a sandbox")
	timeout := fs.Duration("timeout", 10*time.Second, "sandbox execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep sandbox directory after execution")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("directory is required")
	}
	pol, err := loadPolicy(*policyPath, *mode)
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
	sandbox := fs.Bool("sandbox", false, "run lifecycle scripts in a sandbox")
	timeout := fs.Duration("timeout", 10*time.Second, "sandbox execution timeout")
	network := fs.String("network", "disabled", "network mode (disabled, limited, host)")
	keepSandbox := fs.Bool("keep-sandbox", false, "keep sandbox directory after execution")

	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pol, err := loadPolicy(*policyPath, *mode)
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

	res, err := scanner.ScanPackage(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanLockfile(args []string) error {
	fs := flag.NewFlagSet("scan-lockfile", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	_ = fs.Bool("offline", false, "run scan offline using cached database")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("lockfile path is required")
	}
	pol, err := loadPolicy(*policyPath, *mode)
	if err != nil {
		return err
	}
	res, err := anpm.AnalyzeLockfile(fs.Arg(0), pol)
	if err != nil {
		return err
	}
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	policyPath := fs.String("policy", "", "policy YAML path")
	mode := fs.String("mode", "", "audit, warn, or block")
	offline := fs.Bool("offline", false, "run explain offline using cached database")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode)
	if err != nil {
		return err
	}
	store, _ := cache.Load("")
	cached, hasCached := store.Get("npm", pkgName, *ver)

	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = *offline
	res, err := scanner.ScanPackage(pkgName, *ver)
	if err != nil {
		if hasCached {
			return output.Write(os.Stdout, cached, *asJSON)
		}
		return err
	}
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
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	pol, err := loadPolicy(*policyPath, *mode)
	if err != nil {
		return err
	}
	res, err := scanRemoteNPM(pkgName, *ver, pol)
	if err != nil {
		return err
	}
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

func loadPolicy(path, mode string) (policy.Policy, error) {
	pol, err := policy.Load(path)
	if err != nil {
		return policy.Policy{}, err
	}
	return policy.ApplyMode(pol, mode)
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
	eco := fs.String("ecosystem", "npm", "package ecosystem")
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
		"lockfile", "fail-on", "json-output", "sarif-output", "summary-output", "baseline":
		return true
	default:
		return false
	}
}

func cmdCIScan(args []string) error {
	fs := flag.NewFlagSet("ci-scan", flag.ContinueOnError)
	lockfile := fs.String("lockfile", "package-lock.json", "path to package-lock.json")
	policyPath := fs.String("policy", "", "path to PkgSafe policy file")
	mode := fs.String("mode", "", "PkgSafe mode: audit, warn, or block")
	failOn := fs.String("fail-on", "", "minimum decision that fails the workflow: none, warn, block")
	jsonOutput := fs.String("json-output", "", "path to write JSON report")
	sarifOutput := fs.String("sarif-output", "", "path to write SARIF report")
	summaryOutput := fs.String("summary-output", "", "path to write Markdown summary")
	changedOnly := fs.Bool("changed-only", false, "only scan changed dependencies")
	baseline := fs.String("baseline", "main", "baseline branch for diffing")
	sandbox := fs.Bool("sandbox", false, "enable sandbox execution")
	offline := fs.Bool("offline", false, "use offline database only")
	timeout := fs.Duration("timeout", 0, "sandbox timeout")

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
