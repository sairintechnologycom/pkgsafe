// Command pkgsafe is the public OSS PkgSafe binary. All command dispatch
// lives in the importable pkg/cli package so downstream distributions can
// embed the same command surface.
package main

import (
	"os"

	"github.com/sairintechnologycom/pkgsafe/pkg/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
