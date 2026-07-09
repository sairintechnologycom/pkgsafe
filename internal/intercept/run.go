package intercept

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

func RunIntercept(ctx context.Context, pm string, rawArgs []string, executor PackageManagerExecutor) error {
	// 1. Prevent infinite recursion
	if os.Getenv("PKGSAFE_INTERCEPT_ACTIVE") == "1" {
		// Bypass validation and delegate directly to avoid recursion loops
		binaryPath, err := executor.Resolve(pm, policy.Default())
		if err != nil {
			return InterceptError{Code: ExitPackageManagerNotFound, Err: err}
		}
		exitCode, err := executor.Execute(ctx, binaryPath, rawArgs, nil, ".")
		if err != nil {
			return InterceptError{Code: ExitInstallFailed, Err: err}
		}
		if exitCode != 0 {
			return InterceptError{Code: exitCode, Err: fmt.Errorf("package manager exited with code %d", exitCode)}
		}
		return nil
	}

	// 2. Extract PkgSafe safety flags from arguments
	cleanArgs, sf := ExtractSafetyFlags(rawArgs)

	// 3. Load policy configuration
	pol, err := policy.ResolvePolicy("", "", sf.PolicyPath, sf.Mode, sf.RegistryConfig)
	if err != nil {
		return InterceptError{Code: ExitPolicyError, Err: err}
	}

	// 4. Handle bypassed interception situations (global disable or per-ecosystem disable)
	bypassed := false
	if !pol.InstallInterception.Enabled {
		bypassed = true
	} else if pm == "npm" && !pol.PackageManagers.NPM.Enabled {
		bypassed = true
	} else if (pm == "pip" || pm == "python") && !pol.PackageManagers.Pip.Enabled {
		bypassed = true
	}

	if bypassed {
		// Directly delegate to real package manager without scanning
		binaryPath, err := executor.Resolve(pm, pol)
		if err != nil {
			return InterceptError{Code: ExitPackageManagerNotFound, Err: err}
		}
		exitCode, err := executor.Execute(ctx, binaryPath, cleanArgs, nil, ".")
		if err != nil {
			return InterceptError{Code: ExitInstallFailed, Err: err}
		}
		if exitCode != 0 {
			return InterceptError{Code: exitCode, Err: fmt.Errorf("package manager exited with code %d", exitCode)}
		}
		return nil
	}

	// 5. Parse command to extract target packages/files
	cmd, err := ParseCommand(pm, cleanArgs)
	if err != nil {
		if ie, ok := err.(InterceptError); ok && ie.Code == ExitUnsupportedCommand {
			// Transparent pass-through for unsupported/non-install commands to avoid breaking user workflows (e.g. npm run build, npm test)
			if !sf.JSON {
				fmt.Fprintf(os.Stderr, "PkgSafe: Pass-through for unsupported/non-install command: %s %s. Delegating to real package manager...\n", pm, strings.Join(cleanArgs, " "))
			}
			binaryPath, errResolve := executor.Resolve(pm, pol)
			if errResolve != nil {
				return InterceptError{Code: ExitPackageManagerNotFound, Err: errResolve}
			}
			exitCode, errExec := executor.Execute(ctx, binaryPath, cleanArgs, nil, ".")
			if errExec != nil {
				return InterceptError{Code: ExitInstallFailed, Err: errExec}
			}
			if exitCode != 0 {
				return InterceptError{Code: exitCode, Err: fmt.Errorf("package manager exited with code %d", exitCode)}
			}
			return nil
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
	auditEntry := AuditEntry{
		Command:         strings.Join(rawArgs, " "),
		Ecosystem:       cmd.Ecosystem,
		Packages:        auditPackages,
		Mode:            string(pol.Mode),
		InstallExecuted: canProceed && !sf.DryRun,
		OverrideUsed:    sf.ForceRiskAccept && canProceed,
		Reason:          sf.Reason,
	}
	_ = LogAudit(pol, auditEntry)

	// 9. Format outputs (JSON vs Human readable formats)
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
	binaryPath, err := executor.Resolve(cmd.PackageManager, pol)
	if err != nil {
		return InterceptError{Code: ExitPackageManagerNotFound, Err: err}
	}

	fmt.Printf("Proceeding with %s %s...\n", cmd.PackageManager, strings.Join(cmd.RawCommand, " "))
	exitCode, err := executor.Execute(ctx, binaryPath, cmd.RawCommand, nil, ".")
	if err != nil {
		return InterceptError{Code: ExitInstallFailed, Err: err}
	}
	if exitCode != 0 {
		return InterceptError{Code: exitCode, Err: fmt.Errorf("package manager exited with code %d", exitCode)}
	}

	return nil
}
