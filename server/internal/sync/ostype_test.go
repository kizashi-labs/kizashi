package sync

import "testing"

// canonical is the exact value set accepted by agents_os_type_check
// (migration 001 + 329). Anything outside it fails the INSERT with 23514.
var canonical = map[string]bool{
	OSTypeWindows: true, OSTypeLinux: true, OSTypeDarwin: true, OSTypeUnknown: true,
}

func TestNormalizeOSType(t *testing.T) {
	cases := []struct {
		name     string
		platform string
		osName   string
		want     string
	}{
		// Wazuh reports the distribution id in os.platform — the values that
		// used to be written straight into agents.os_type.
		{"ubuntu platform", "ubuntu", "Ubuntu", OSTypeLinux},
		{"centos platform", "centos", "CentOS Linux", OSTypeLinux},
		{"amazon linux platform", "amzn", "Amazon Linux", OSTypeLinux},
		{"debian platform", "debian", "Debian GNU/Linux", OSTypeLinux},
		{"rocky platform", "rocky", "Rocky Linux", OSTypeLinux},
		{"opensuse platform", "opensuse-leap", "openSUSE Leap", OSTypeLinux},
		{"generic linux platform", "linux", "", OSTypeLinux},

		{"windows platform", "windows", "Microsoft Windows 11", OSTypeWindows},
		{"darwin platform", "darwin", "Mac OS X", OSTypeDarwin},
		{"macos platform alias", "macos", "", OSTypeDarwin},

		// Case / whitespace tolerance.
		{"mixed case platform", "  Ubuntu  ", "", OSTypeLinux},
		{"upper windows", "WINDOWS", "", OSTypeWindows},

		// platform absent — fall back to the free-form os.name.
		{"name only windows", "", "Microsoft Windows Server 2022", OSTypeWindows},
		{"name only linux", "", "Ubuntu 22.04.3 LTS", OSTypeLinux},
		{"name only darwin", "", "macOS Sonoma", OSTypeDarwin},
		{"name only generic linux", "", "Some Linux Distro", OSTypeLinux},

		// Unknown rather than a wrong guess. Wazuh manages these too, and
		// mislabelling them as Linux would silently misroute agent updates
		// and config-profile matching.
		{"empty both", "", "", OSTypeUnknown},
		{"aix", "aix", "AIX", OSTypeUnknown},
		{"solaris must not match the ol distro code", "sunos", "Solaris 11", OSTypeUnknown},
		{"hpux", "hp-ux", "HP-UX", OSTypeUnknown},
		{"garbage", "!!!", "???", OSTypeUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeOSType(tc.platform, tc.osName)
			if got != tc.want {
				t.Errorf("NormalizeOSType(%q, %q) = %q, want %q",
					tc.platform, tc.osName, got, tc.want)
			}
			if !canonical[got] {
				t.Errorf("NormalizeOSType(%q, %q) returned %q, which violates agents_os_type_check",
					tc.platform, tc.osName, got)
			}
		})
	}
}

func TestOSTypeFromAlert(t *testing.T) {
	winData := func() *WazuhAlertPayload {
		p := &WazuhAlertPayload{Data: map[string]interface{}{"win": map[string]interface{}{}}}
		return p
	}
	withGroups := func(loc string, groups ...string) *WazuhAlertPayload {
		p := &WazuhAlertPayload{Location: loc}
		p.Rule.Groups = groups
		return p
	}

	cases := []struct {
		name    string
		payload *WazuhAlertPayload
		want    string
	}{
		{"nil payload", nil, OSTypeUnknown},
		{"windows eventchannel data block", winData(), OSTypeWindows},
		{"eventchannel location", withGroups("EventChannel"), OSTypeWindows},
		{"windows file location", withGroups(`C:\Windows\System32\x.log`), OSTypeWindows},
		{"windows rule group", withGroups("", "windows", "authentication_success"), OSTypeWindows},
		{"sysmon rule group", withGroups("", "sysmon"), OSTypeWindows},
		{"macos rule group", withGroups("", "macos"), OSTypeDarwin},
		{"linux rule group", withGroups("", "syslog", "sshd"), OSTypeLinux},
		{"unix log path", withGroups("/var/log/auth.log"), OSTypeLinux},
		// Windows wins over a co-occurring generic group.
		{"windows beats generic group", withGroups("", "authentication_failed", "windows"), OSTypeWindows},
		// Nothing identifying at all — the documented default.
		{"no signal", withGroups(""), OSTypeUnknown},
		{"unrelated groups only", withGroups("", "attack", "gdpr_IV_35.7.d"), OSTypeUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OSTypeFromAlert(tc.payload)
			if got != tc.want {
				t.Errorf("OSTypeFromAlert() = %q, want %q", got, tc.want)
			}
			if !canonical[got] {
				t.Errorf("OSTypeFromAlert() returned %q, which violates agents_os_type_check", got)
			}
		})
	}
}

func TestSanitizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.5", "10.0.0.5"},
		{"10.0.0.0/24", "10.0.0.0"},
		{"", "0.0.0.0"},
		{"   ", "0.0.0.0"},
		{"any", "0.0.0.0"}, // Wazuh's placeholder for agents with no fixed address
		{"ANY", "0.0.0.0"},
		{"/24", "0.0.0.0"},
		{" 192.168.1.1 ", "192.168.1.1"},
	}
	for _, tc := range cases {
		if got := SanitizeIP(tc.in); got != tc.want {
			t.Errorf("SanitizeIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
