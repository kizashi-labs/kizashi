package sync

import "strings"

// Canonical agents.os_type values. The column carries a CHECK constraint
// (migration 001, relaxed to accept 'unknown' by migration 357) that permits
// exactly these four — writing anything else fails with 23514 check_violation
// and, on the Wazuh paths, silently drops the event.
const (
	OSTypeWindows = "windows"
	OSTypeLinux   = "linux"
	OSTypeDarwin  = "darwin"
	OSTypeUnknown = "unknown"
)

// linuxPlatforms are the exact values Wazuh reports in agent.os.platform for
// the Linux distributions it supports. Wazuh also manages AIX / Solaris /
// HP-UX; those deliberately fall through to OSTypeUnknown rather than being
// mislabelled as Linux, since os_type is joined against for agent updates
// (autoupdate) and config profiles.
var linuxPlatforms = map[string]bool{
	"linux": true, "ubuntu": true, "debian": true, "centos": true,
	"rhel": true, "redhat": true, "red hat": true, "fedora": true,
	"amzn": true, "amazon": true, "ol": true, "oracle": true,
	"rocky": true, "almalinux": true, "alma": true, "sles": true,
	"suse": true, "opensuse": true, "opensuse-leap": true,
	"opensuse-tumbleweed": true, "alpine": true, "arch": true,
	"gentoo": true, "raspbian": true, "raspbian-gnu": true, "busybox": true,
}

// linuxNameHints are substrings matched against the free-form agent.os.name
// when os.platform is absent or unrecognised. Only unambiguous names are
// listed — short platform codes such as "ol" or "alma" are exact-match only
// (map above) because "Solaris" contains "ol".
var linuxNameHints = []string{
	"linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
	"amazon", "oracle linux", "rocky", "almalinux", "suse", "alpine",
	"arch", "raspbian", "gentoo",
}

// NormalizeOSType maps a Wazuh agent's os.platform / os.name onto one of the
// canonical os_type values. Wazuh's platform field is a distribution id
// ("ubuntu", "centos", "amzn", …), not an OS family, so passing it straight
// into agents.os_type violates the CHECK constraint for every Linux host.
//
// platform is authoritative when recognised; otherwise the free-form os.name
// is scanned. Unrecognised input yields OSTypeUnknown — a legal value since
// migration 357, and preferable to guessing.
func NormalizeOSType(platform, osName string) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case p == "windows" || p == "win32" || p == "win64":
		return OSTypeWindows
	case p == "darwin" || p == "macos" || p == "mac os x" || p == "osx":
		return OSTypeDarwin
	case linuxPlatforms[p]:
		return OSTypeLinux
	}

	n := strings.ToLower(strings.TrimSpace(osName))
	if n == "" {
		return OSTypeUnknown
	}
	switch {
	case strings.Contains(n, "windows"):
		return OSTypeWindows
	case strings.Contains(n, "mac os"), strings.Contains(n, "macos"),
		strings.Contains(n, "darwin"):
		return OSTypeDarwin
	}
	for _, hint := range linuxNameHints {
		if strings.Contains(n, hint) {
			return OSTypeLinux
		}
	}
	return OSTypeUnknown
}

// windowsGroups / darwinGroups / linuxGroups are Wazuh rule groups that pin an
// alert to an OS family. Checked most-specific-first: a Windows alert can
// carry generic groups too, so the Windows and macOS sets win over Linux.
var (
	windowsGroups = map[string]bool{
		"windows": true, "windows_security": true, "sysmon": true,
		"windows_eventchannel": true, "wineventlog": true,
	}
	darwinGroups = map[string]bool{
		"macos": true, "darwin": true, "macos_security": true,
	}
	linuxGroups = map[string]bool{
		"linux": true, "syslog": true, "sshd": true, "pam": true,
		"sudo": true, "systemd": true, "auditd": true, "audit": true,
		"selinux": true, "apparmor": true, "su": true, "cron": true,
	}
)

// OSTypeFromAlert best-effort derives a canonical os_type from a Wazuh webhook
// alert. The webhook payload carries no OS field at all (its agent object is
// id/name/ip only), so this reads the indirect signals Wazuh does include:
// the rule groups, the decoder location, and the presence of the Windows
// eventchannel data block.
//
// Returns OSTypeUnknown when nothing matches. That is the documented default:
// the row is created with a truthful "not yet known" OS and upgraded in place
// once a later alert — or the Wazuh API agent sync — reveals the real one.
func OSTypeFromAlert(p *WazuhAlertPayload) string {
	if p == nil {
		return OSTypeUnknown
	}

	// data.win is only ever emitted by the Windows eventchannel decoder.
	if _, ok := p.Data["win"]; ok {
		return OSTypeWindows
	}

	loc := strings.ToLower(p.Location)
	if strings.Contains(loc, "eventchannel") || strings.Contains(loc, "wineventlog") ||
		strings.Contains(loc, `\`) {
		return OSTypeWindows
	}

	var sawLinuxGroup bool
	for _, g := range p.Rule.Groups {
		g = strings.ToLower(strings.TrimSpace(g))
		switch {
		case windowsGroups[g]:
			return OSTypeWindows
		case darwinGroups[g]:
			return OSTypeDarwin
		case linuxGroups[g]:
			sawLinuxGroup = true
		}
	}
	if sawLinuxGroup {
		return OSTypeLinux
	}

	// Unix decoders report an absolute log path ("/var/log/auth.log");
	// Windows ones never do (handled above).
	if strings.HasPrefix(loc, "/") {
		return OSTypeLinux
	}
	return OSTypeUnknown
}

// SanitizeIP coerces a Wazuh-supplied address into something the inet cast
// accepts. Wazuh reports "any" for agents registered without a fixed address
// and may append a CIDR suffix; both make `$1::inet` fail with 22P02, which on
// the sync path discards the whole agent row.
func SanitizeIP(ip string) string {
	ip = strings.TrimSpace(strings.Split(ip, "/")[0])
	if ip == "" || strings.EqualFold(ip, "any") {
		return "0.0.0.0"
	}
	return ip
}
