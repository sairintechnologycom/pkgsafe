package ci

const (
	ExitSuccess        = 0 // Scan completed, no failure threshold reached
	ExitFailThreshold  = 1 // Failure threshold reached (warn/block packages found)
	ExitUsageError     = 2 // Usage or configuration error
	ExitInternalError  = 3 // Scanner or internal error
	ExitPolicyError    = 4 // Policy loading or validation error
	ExitLockfileError  = 5 // Lockfile or package.json parsing error
)
