//go:build darwin

package main

import "syscall"

// osRelease returns the Darwin kernel release (e.g. "24.1.0") the way
// Node's os.release() does — kern.osrelease is the same sysctl Node reads,
// and a real ZCode desktop on macOS always carries the header (0.2.4:
// darwin builds previously omitted X-Os-Version entirely).
func osRelease() string {
	rel, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return ""
	}
	return normalizePrintableHeaderValue(rel)
}
