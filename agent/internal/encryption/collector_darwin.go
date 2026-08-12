//go:build darwin

package encryption

import (
	"os/exec"
	"strings"
)

// Probe detects FileVault full-disk encryption on macOS via fdesetup.
//
// `fdesetup status` prints "FileVault is On." when encryption is enabled.
func Probe() Status {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return Status{Encrypted: false, Method: "FileVault", Details: "fdesetup unavailable"}
	}
	text := strings.TrimSpace(string(out))
	on := strings.Contains(strings.ToLower(text), "filevault is on")
	return Status{
		Encrypted: on,
		Method:    "FileVault",
		Details:   text,
	}
}
