//go:build linux

package main

import "os"

// osRelease returns the kernel release the way Node's os.release() does on
// Linux (uname -r) — the value ZCode's buildZCodeSourceHeadersFromContext
// sends as X-Os-Version (magpie packages/zcode 0.1.22). /proc/sys/kernel/
// osrelease is authoritative and always present on the server deployments
// CPA targets.
func osRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return normalizePrintableHeaderValue(string(b))
}
