package intercept

import (
	"fmt"
	"io"
)

func PrintShellAliases(w io.Writer) {
	fmt.Fprintln(w, "Add the following aliases to your shell profile:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# PkgSafe package install guard")
	fmt.Fprintln(w, `alias npm="pkgsafe npm"`)
	fmt.Fprintln(w, `alias pip="pkgsafe pip"`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To disable temporarily:")
	fmt.Fprintln(w, "unalias npm")
	fmt.Fprintln(w, "unalias pip")
}
