//go:build !linux && !darwin && !windows

package encryption

// Probe is a no-op fallback on unsupported platforms.
func Probe() Status {
	return Status{Encrypted: false, Method: "unknown", Details: "unsupported platform"}
}
