package cli

import (
	"os"

	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
)

func InitShell(args []string) error {
	// PkgSafe init shell prints the alias instructions to stdout.
	intercept.PrintShellAliases(os.Stdout)
	return nil
}
