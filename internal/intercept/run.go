package intercept

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// delegate runs the real package manager binary with the given args.
// It centralizes the resolve → execute → error-wrap pattern used across
// three places in RunIntercept.
func delegate(ctx context.Context, executor PackageManagerExecutor, pm string, args []string, pol policy.Policy) error {
	binaryPath, err := executor.Resolve(pm, pol)
	if err != nil {
		return InterceptError{Code: ExitPackageManagerNotFound, Err: err}
	}
	exitCode, err := executor.Execute(ctx, binaryPath, args, nil, ".")
	if err != nil {
		return InterceptError{Code: ExitInstallFailed, Err: err}
	}
	if exitCode != 0 {
		return InterceptError{Code: exitCode, Err: fmt.Errorf("package manager exited with code %d", exitCode)}
	}
	return nil
}

// debugEnabled reports whether PKGSAFE_DEBUG=1 is set.
func debugEnabled() bool {
	return os.Getenv("PKGSAFE_DEBUG") == "1"
}

func RunIntercept(ctx context.Context, pm string, rawArgs []string, executor PackageManagerExecutor) error {
	// 1. Prevent infinite recursion
	if os.Getenv("PKGSAFE_INTERCEPT_ACTIVE") == "1" {
		return delegate(ctx, executor, pm, rawArgs, policy.Default())
	}

	// 2. Extract PkgSafe safety flags from arguments
	cleanArgs, sf := ExtractSafetyFlags(rawArgs)

	// 3. Load policy configuration
	pol, err := policy.ResolvePolicy("", "", sf.PolicyPath, sf.Mode, sf.RegistryConfig)
	if err != nil {
		return InterceptError{Code: ExitPolicyError, Err: err}
	}

	// 4. Handle bypassed interception (global or per-ecosystem disable)
	bypassed := !pol.InstallInterception.Enabled ||
		((pm == "npm" || pm == "pnpm" || pm == "yarn") && !pol.PackageManagers.NPM.Enabled) ||
		((pm == "pip" || pm == "python" || pm == "uv") && !pol.PackageManagers.Pip.Enabled)

	if bypassed {
		return delegate(ctx, executor, pm, cleanArgs, pol)
	}

	// 5. Parse command to extract target packages/files
	cmd, err := ParseCommand(pm, cleanArgs)
	if err != nil {
		if ie, ok := err.(InterceptError); ok && ie.Code == ExitUnsupportedCommand {
			// Transparent pass-through for unsupported/non-install commands
			// Only log when debug mode is on to avoid spamming user stderr
			if debugEnabled() {
				fmt.Fprintf(os.Stderr, "PkgSafe: Pass-through for unsupported/non-install command: %s %s. Delegating to real package manager...\n", pm, strings.Join(cleanArgs, " "))
			}
			return delegate(ctx, executor, pm, cleanArgs, pol)
		}
		if ie, ok := err.(InterceptError); ok {
			return ie
		}
		return InterceptError{Code: ExitUnsupportedCommand, Err: err}
	}

	// 6. Validate/Scan package dependencies
	results, overallDecision, err := Validate(ctx, cmd, sf, pol, ".")
	if err != nil {
		if ie, ok := err.(InterceptError); ok {
			return ie
		}
		return InterceptError{Code: ExitInternalError, Err: err}
	}

	// 7. Check if command execution is allowed to proceed
	canProceed, reason, code := CanProceed(results, overallDecision, sf, pol)

	// 8. Log the interception attempt to local audit log
	auditPackages := make([]AuditPackage, len(results))
	for i, res := range results {
		auditPackages[i] = AuditPackage{
			Name:      res.Package.Name,
			Version:   res.Package.Version,
			Decision:  string(res.Decision),
			RiskScore: res.Score,
		}
	}
	_ = LogAudit(pol, AuditEntry{
		Command:         strings.Join(rawArgs, " "),
		Ecosystem:       cmd.Ecosystem,
		Packages:        auditPackages,
		Mode:            string(pol.Mode),
		InstallExecuted: canProceed && !sf.DryRun,
		OverrideUsed:    sf.ForceRiskAccept && canProceed,
		Reason:          sf.Reason,
	})

	// 9. Format outputs (JSON vs human-readable)
	if sf.JSON {
		if err := PrintJSONOutput(os.Stdout, cmd, results, overallDecision, sf, canProceed && !sf.DryRun); err != nil {
			return InterceptError{Code: ExitInternalError, Err: err}
		}
		if !canProceed {
			return InterceptError{Code: code, Err: fmt.Errorf("%s", reason)}
		}
	} else {
		PrintHumanOutput(cmd, results, overallDecision)
		if !canProceed {
			fmt.Fprintln(os.Stderr, reason)
			return InterceptError{Code: code, Err: fmt.Errorf("%s", reason)}
		}
	}

	// 10. Dry-run early exit
	if sf.DryRun {
		fmt.Printf("Dry run enabled. PkgSafe completed validation but did not execute %s %s.\n", cmd.PackageManager, cmd.Operation)
		return nil
	}

	// 11. Execute real package manager
	fmt.Printf("Proceeding with %s %s...\n", cmd.PackageManager, strings.Join(cmd.RawCommand, " "))
	return delegate(ctx, executor, cmd.PackageManager, cmd.RawCommand, pol)
}
