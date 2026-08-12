//go:build darwin

package hardening

import (
	"os/exec"
	"strings"
)

// BenchmarkName identifies the builtin check set reported to the server.
const BenchmarkName = "CIS macOS (agent builtin) v1"

// Assess runs the builtin macOS hardening checks via read-only status commands.
func Assess() []Check {
	return []Check{
		filevaultEnabled(),
		gatekeeperEnabled(),
		sipEnabled(),
	}
}

func filevaultEnabled() Check {
	c := Check{ID: "filevault", Title: "FileVault enabled"}
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		c.Passed = false
		c.Details = "fdesetup unavailable"
		return c
	}
	c.Passed = strings.Contains(strings.ToLower(string(out)), "filevault is on")
	c.Details = strings.TrimSpace(string(out))
	return c
}

func gatekeeperEnabled() Check {
	c := Check{ID: "gatekeeper", Title: "Gatekeeper enabled"}
	out, err := exec.Command("spctl", "--status").Output()
	if err != nil {
		c.Passed = false
		c.Details = "spctl unavailable"
		return c
	}
	c.Passed = strings.Contains(strings.ToLower(string(out)), "assessments enabled")
	c.Details = strings.TrimSpace(string(out))
	return c
}

func sipEnabled() Check {
	c := Check{ID: "sip", Title: "System Integrity Protection enabled"}
	out, err := exec.Command("csrutil", "status").Output()
	if err != nil {
		c.Passed = false
		c.Details = "csrutil unavailable"
		return c
	}
	c.Passed = strings.Contains(strings.ToLower(string(out)), "enabled")
	c.Details = strings.TrimSpace(string(out))
	return c
}
