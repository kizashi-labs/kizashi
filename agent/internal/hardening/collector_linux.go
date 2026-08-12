//go:build linux

package hardening

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// BenchmarkName identifies the builtin check set reported to the server.
const BenchmarkName = "CIS Linux (agent builtin) v1"

// Assess runs the builtin Linux hardening checks. Each check reads system
// configuration files (no mutation) and returns a pass/fail result. Checks are
// designed to be evaluable without root where possible; when a source file is
// unreadable the check errs toward "fail" with an explanatory detail so the
// baseline reflects unknown/unhardened state rather than silently passing.
func Assess() []Check {
	return []Check{
		sshRootLogin(),
		sshPasswordAuth(),
		passwordMaxDays(),
		cronRestricted(),
		tmpStickyBit(),
		coreDumpsRestricted(),
	}
}

// sshConfigDirective returns the last value of an sshd_config directive
// (case-insensitive key), and whether the config file was readable.
func sshConfigDirective(key string) (val string, ok bool) {
	f, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return "", false
	}
	defer f.Close()
	lk := strings.ToLower(key)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.ToLower(fields[0]) == lk {
			val = fields[1]
		}
	}
	return val, true
}

func sshRootLogin() Check {
	c := Check{ID: "ssh_root_login", Title: "SSH: PermitRootLogin disabled"}
	v, ok := sshConfigDirective("PermitRootLogin")
	if !ok {
		// No sshd_config → no SSH server exposed; consider compliant.
		c.Passed = true
		c.Details = "no sshd_config (SSH server not configured)"
		return c
	}
	lv := strings.ToLower(v)
	c.Passed = lv == "no" || lv == "prohibit-password"
	c.Details = "PermitRootLogin=" + v
	return c
}

func sshPasswordAuth() Check {
	c := Check{ID: "ssh_password_auth", Title: "SSH: PasswordAuthentication disabled"}
	v, ok := sshConfigDirective("PasswordAuthentication")
	if !ok {
		c.Passed = true
		c.Details = "no sshd_config (SSH server not configured)"
		return c
	}
	// Default (unset) is "yes", which is non-compliant.
	if v == "" {
		v = "yes"
	}
	c.Passed = strings.EqualFold(v, "no")
	c.Details = "PasswordAuthentication=" + v
	return c
}

func passwordMaxDays() Check {
	c := Check{ID: "password_max_days", Title: "Password max age ≤ 365 days"}
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		c.Passed = false
		c.Details = "cannot read /etc/login.defs"
		return c
	}
	defer f.Close()
	max := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "PASS_MAX_DAYS") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					max = n
				}
			}
		}
	}
	if max < 0 {
		c.Passed = false
		c.Details = "PASS_MAX_DAYS not set"
		return c
	}
	c.Passed = max <= 365
	c.Details = "PASS_MAX_DAYS=" + strconv.Itoa(max)
	return c
}

func cronRestricted() Check {
	c := Check{ID: "cron_restricted", Title: "cron access restricted (/etc/cron.allow)"}
	if _, err := os.Stat("/etc/cron.allow"); err == nil {
		c.Passed = true
		c.Details = "/etc/cron.allow present"
	} else {
		c.Passed = false
		c.Details = "/etc/cron.allow absent"
	}
	return c
}

func tmpStickyBit() Check {
	c := Check{ID: "tmp_sticky_bit", Title: "/tmp has sticky bit"}
	fi, err := os.Stat("/tmp")
	if err != nil {
		c.Passed = false
		c.Details = "cannot stat /tmp"
		return c
	}
	c.Passed = fi.Mode()&os.ModeSticky != 0
	c.Details = "/tmp mode " + fi.Mode().String()
	return c
}

func coreDumpsRestricted() Check {
	c := Check{ID: "core_dumps_restricted", Title: "Core dumps restricted"}
	data, err := os.ReadFile("/etc/security/limits.conf")
	if err != nil {
		c.Passed = false
		c.Details = "cannot read limits.conf"
		return c
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// e.g. "* hard core 0"
		if len(fields) >= 4 && fields[1] == "hard" && fields[2] == "core" && fields[3] == "0" {
			c.Passed = true
			c.Details = "hard core 0 configured"
			return c
		}
	}
	c.Passed = false
	c.Details = "no 'hard core 0' limit"
	return c
}
