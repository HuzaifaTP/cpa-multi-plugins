//go:build !linux && !darwin

package main

// osRelease returns empty on platforms without a stdlib equivalent of
// Node's os.release() (Windows reads its version from the registry; Go
// stdlib cannot without golang.org/x/sys) — X-Os-Version is omitted,
// matching the client's own behavior when the value is non-printable.
func osRelease() string {
	return ""
}
