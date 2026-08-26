//go:build !linux && !darwin && !windows

package hardening

// BenchmarkName identifies the builtin check set reported to the server.
const BenchmarkName = "unsupported"

// Assess is a no-op fallback on unsupported platforms.
func Assess() []Check { return nil }
