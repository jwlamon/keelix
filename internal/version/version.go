// Package version holds the build version of the keelix binary. The values
// are overridable at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/jakelamon/keelix/internal/version.Version=1.2.3"
package version

// Version is the semantic version of this build. "dev" for local builds.
var Version = "dev"

// Commit is the git commit the binary was built from, if injected.
var Commit = "none"

// Date is the build date, if injected.
var Date = "unknown"

// String returns a human-friendly version string.
func String() string {
	s := Version
	if Commit != "none" && Commit != "" {
		s += " (" + Commit + ")"
	}
	return s
}
