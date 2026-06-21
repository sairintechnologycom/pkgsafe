package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	anpm "github.com/niyam-ai/pkgsafe/internal/analyzer/npm"
	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/mcp"
	"github.com/niyam-ai/pkgsafe/internal/output"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

var version = "0.1.0"
var commit = "local"

func main() {
	if err := run(os.Args[1:]); err != nil {
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
		fmt.Println("Local DB update placeholder: OSV/malware feed ingestion will be added in Phase 2.")
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`PkgSafe - local-first package safety CLI

Usage:
  pkgsafe scan-local-npm <dir> [--json]
  pkgsafe scan-npm-package <name> [--version <version>] [--json]
  pkgsafe scan-lockfile <package-lock.json> [--json]
  pkgsafe explain <name> [--version <version>]
  pkgsafe npm-install <name> [--version <version>] [--mode warn|block|audit]
  pkgsafe mcp serve
  pkgsafe version
`)
}

func cmdScanLocalNPM(args []string) error {
	fs := flag.NewFlagSet("scan-local-npm", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("directory is required")
	}
	res, err := anpm.AnalyzePackageDir(fs.Arg(0), policy.Default())
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
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	res, err := scanRemoteNPM(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdScanLockfile(args []string) error {
	fs := flag.NewFlagSet("scan-lockfile", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("lockfile path is required")
	}
	res, err := anpm.AnalyzeLockfile(fs.Arg(0), policy.Default())
	if err != nil {
		return err
	}
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	store, _ := cache.Load("")
	if res, ok := store.Get("npm", fs.Arg(0), *ver); ok {
		return output.Write(os.Stdout, res, *asJSON)
	}
	res, err := scanRemoteNPM(fs.Arg(0), *ver)
	if err != nil {
		return err
	}
	_ = saveResult(res)
	return output.Write(os.Stdout, res, *asJSON)
}

func cmdNPMInstall(args []string) error {
	fs := flag.NewFlagSet("npm-install", flag.ContinueOnError)
	ver := fs.String("version", "", "package version")
	mode := fs.String("mode", "warn", "warn, block, or audit")
	asJSON := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("package name is required")
	}
	pkgName := fs.Arg(0)
	res, err := scanRemoteNPM(pkgName, *ver)
	if err != nil {
		return err
	}
	_ = saveResult(res)
	if err := output.Write(os.Stdout, res, *asJSON); err != nil {
		return err
	}

	m := policy.ParseMode(*mode)
	if m == policy.ModeAudit {
		fmt.Println("Audit mode: npm install skipped.")
		return nil
	}
	if res.Decision == types.DecisionBlock || (m == policy.ModeBlock && res.Decision == types.DecisionWarn) {
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
	if len(args) != 1 || args[0] != "serve" {
		return errors.New("usage: pkgsafe mcp serve")
	}
	return mcp.Serve(os.Stdin, os.Stdout)
}

func scanRemoteNPM(name, version string) (types.ScanResult, error) {
	return snpm.ScanPackage(name, version)
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
	case "version", "mode":
		return true
	default:
		return false
	}
}
