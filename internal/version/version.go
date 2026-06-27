// Package version exposes the pkgsafe build version as a single source of
// truth. Values are injected at build time via -ldflags (see Makefile and
// .goreleaser.yaml); unbuilt/dev binaries report "dev".
package version

// Version is the semantic version of this build, e.g. "0.1.0". It defaults to
// "dev" for `go run`/`go build` without ldflags.
var Version = "dev"

// Commit is the short git SHA of this build, or "none" when unset.
var Commit = "none"

// IsDev reports whether this is an unversioned development build.
func IsDev() bool {
	return Version == "dev" || Version == ""
}
