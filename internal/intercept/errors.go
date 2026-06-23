package intercept

import "fmt"

const (
	ExitSuccess             = 0
	ExitBlocked             = 1
	ExitDeclined            = 2
	ExitInstallFailed       = 3
	ExitUsageError          = 4
	ExitInternalError       = 5
	ExitPolicyError         = 6
	ExitUnsupportedCommand  = 7
	ExitPackageManagerNotFound = 8
)

type InterceptError struct {
	Code int
	Err  error
}

func (e InterceptError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}
