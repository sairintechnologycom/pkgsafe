// Package version exposes the pkgsafe build version as a single source of
// truth. Values are injected at build time via -ldflags (see Makefile and
// .goreleaser.yaml); unbuilt binaries report the development line of the
// current release series.
package version

import "strings"

// Version is the semantic version of this build. Real release builds inject the
// clean tag (e.g. "v0.2.0-beta.1") via -ldflags. Unbuilt `go run`/`go build`
// binaries fall back to the development line of the current release series so
// they report something honest rather than a bare "dev".
var Version = "v1.0.2-dev"

// Commit is the short git SHA of this build, or "none" when unset.
var Commit = "none"

// IsDev reports whether this is an unversioned development build (no clean tag
// injected via ldflags). The "-dev" suffix marks the local development line.
func IsDev() bool {
	return Version == "" || Version == "dev" || strings.HasSuffix(Version, "-dev")
}
