//go:build windows

package hardening

import (
	"os/exec"
	"strings"
)

// BenchmarkName identifies the builtin check set reported to the server.
const BenchmarkName = "CIS Windows (agent builtin) v1"

// Assess runs the builtin Windows hardening checks via read-only commands.
func Assess() []Check {
	return []Check{
		firewallEnabled(),
		bitlockerEnabled(),
	}
}

func firewallEnabled() Check {
	c := Check{ID: "firewall", Title: "Windows Firewall enabled (all profiles)"}
	out, err := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		c.Passed = false
		c.Details = "netsh unavailable"
		return c
	}
	text := strings.ToLower(string(out))
	// Compliant only when no profile reports "state off".
	c.Passed = !strings.Contains(text, "state                                 off") &&
		!strings.Contains(text, "state off")
	if c.Passed {
		c.Details = "all profiles ON"
	} else {
		c.Details = "one or more profiles OFF"
	}
	return c
}

func bitlockerEnabled() Check {
	c := Check{ID: "bitlocker", Title: "BitLocker protection on system drive"}
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		c.Passed = false
		c.Details = "manage-bde unavailable"
		return c
	}
	lower := strings.ToLower(string(out))
	c.Passed = strings.Contains(lower, "protection on") || strings.Contains(lower, "fully encrypted")
	if c.Passed {
		c.Details = "Protection On"
	} else {
		c.Details = "Protection Off"
	}
	return c
}
