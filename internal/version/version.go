// Package version carries the build-stamped version string.
package version

// Version is overridden at build time via -ldflags "-X .../version.Version=...".
var Version = "dev"

// String returns the build version.
func String() string { return Version }
