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
	fmt.Fprintln(w, `alias pnpm="pkgsafe pnpm"`)
	fmt.Fprintln(w, `alias yarn="pkgsafe yarn"`)
	fmt.Fprintln(w, `alias pip="pkgsafe pip"`)
	fmt.Fprintln(w, `alias uv="pkgsafe uv"`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To disable temporarily:")
	fmt.Fprintln(w, "unalias npm pnpm yarn pip uv")
}
