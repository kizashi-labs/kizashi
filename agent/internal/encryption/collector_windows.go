//go:build windows

package encryption

import (
	"os/exec"
	"strings"
)

// Probe detects BitLocker full-disk encryption on Windows via manage-bde.
//
// `manage-bde -status C:` reports "Protection Status: Protection On" and a
// "Conversion Status: Fully Encrypted" line when the system drive is encrypted.
func Probe() Status {
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		return Status{Encrypted: false, Method: "BitLocker", Details: "manage-bde unavailable"}
	}
	lower := strings.ToLower(string(out))
	on := strings.Contains(lower, "protection on") ||
		strings.Contains(lower, "fully encrypted")
	details := "Protection Off"
	if on {
		details = "Protection On"
	}
	return Status{
		Encrypted: on,
		Method:    "BitLocker",
		Details:   details,
	}
}
