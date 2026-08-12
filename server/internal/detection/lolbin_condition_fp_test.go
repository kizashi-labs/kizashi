package detection

import "testing"

// These guard a family of built-in LOLBin rules whose selection OR-ed in a token
// that is present in essentially EVERY invocation of the binary, benign or not.
// Because a Sigma selection list is an OR, such a token is an independently
// sufficient match, so the rule fires on ordinary administration while its title
// and severity claim an attack technique. A high-severity rule that cries wolf on
// routine work is worse than no rule: analysts learn to dismiss it, and the true
// positive it was written for goes with it.
//
// Each subtest pins BOTH directions — the benign invocation must stay silent and
// the real technique must still fire — because the cheap way to kill a false
// positive is to over-narrow until the rule detects nothing.

func lolbinFires(t *testing.T, ev *SigmaEvaluator, title, image, cmdline string) bool {
	t.Helper()
	event := map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"command_line": cmdline,
	}
	addPipelineSigmaAliases(event)
	for _, m := range ev.EvaluateEvent(event) {
		if m.RuleTitle == title {
			return true
		}
	}
	return false
}

// .inf is a mandatory argument for every cmstp.exe invocation, so it cannot
// distinguish a malicious silent install from a routine profile install.
func TestCMSTPRequiresSilentInstallFlag(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)
	const title = "CMSTP Suspicious Execution"
	const image = `C:\Windows\System32\cmstp.exe`

	if lolbinFires(t, ev, title, image, `cmstp.exe C:\Users\v\profile.inf`) {
		t.Error("FALSE POSITIVE: an ordinary cmstp.exe profile install (no /s or /ns) fired the CMSTP rule")
	}
	if !lolbinFires(t, ev, title, image, `cmstp.exe /s /ns C:\Users\v\evil.inf`) {
		t.Error("MISSED true positive: cmstp.exe /s /ns evil.inf did not fire the CMSTP rule")
	}
}

// /u is an everyday .NET service uninstall. The technique this rule describes
// ("while suppressing output") always carries the log-suppression options, so
// keying on those loses nothing and drops the routine case.
func TestInstallUtilRequiresLogSuppression(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)
	const title = "InstallUtil Proxy Execution"
	const image = `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`

	if lolbinFires(t, ev, title, image, `InstallUtil.exe /u MyService.exe`) {
		t.Error("FALSE POSITIVE: bare 'InstallUtil.exe /u' (ordinary uninstall) fired the InstallUtil rule")
	}
	// The LOLBAS invocation — /U is present, but so is the log suppression.
	if !lolbinFires(t, ev, title, image, `InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll`) {
		t.Error("MISSED true positive: the LOLBAS InstallUtil invocation did not fire the InstallUtil rule")
	}
}

// /a and .dll are standard syntax for EVERY odbcconf action, not just REGSVR.
// REGSVR is the action that actually loads and executes the DLL.
func TestOdbcconfRequiresRegsvrAction(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)
	const title = "Odbcconf Proxy Execution"
	const image = `C:\Windows\System32\odbcconf.exe`

	if lolbinFires(t, ev, title, image, `odbcconf.exe /a {CONFIGSYSDSN "SQL Server" "DSN=Prod|Driver=sqlncli.dll"}`) {
		t.Error("FALSE POSITIVE: a routine odbcconf CONFIGSYSDSN (which carries both /a and .dll) fired the Odbcconf rule")
	}
	if !lolbinFires(t, ev, title, image, `odbcconf.exe /a {REGSVR "C:\Users\v\evil.dll"}`) {
		t.Error("MISSED true positive: odbcconf /a {REGSVR ...} did not fire the Odbcconf rule")
	}
}
