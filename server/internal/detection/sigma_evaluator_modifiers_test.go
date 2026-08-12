package detection

import (
	"encoding/base64"
	"testing"
)

// These modifiers previously fell through to the equality default and silently
// never matched, so any rule using them was inert. Each test drives a real rule
// through the evaluator and asserts the malicious value fires and a benign one
// does not.

func TestSigmaModifier_CIDR(t *testing.T) {
	e := loadOne(t, `
title: C2 in suspicious range
level: high
detection:
  selection:
    dst_ip|cidr: 10.0.0.0/8
  condition: selection
`)
	if !matched(e, map[string]interface{}{"dst_ip": "10.13.37.2"}) {
		t.Error("10.13.37.2 should match 10.0.0.0/8")
	}
	if matched(e, map[string]interface{}{"dst_ip": "192.168.1.5"}) {
		t.Error("192.168.1.5 must not match 10.0.0.0/8")
	}
}

func TestSigmaModifier_Numeric(t *testing.T) {
	e := loadOne(t, `
title: High port
level: low
detection:
  selection:
    dst_port|gt: 1024
  condition: selection
`)
	if !matched(e, map[string]interface{}{"dst_port": float64(8080)}) {
		t.Error("8080 should be > 1024")
	}
	if matched(e, map[string]interface{}{"dst_port": float64(80)}) {
		t.Error("80 must not be > 1024")
	}
	// String-encoded numbers (some agents emit ports as strings) still compare.
	if !matched(e, map[string]interface{}{"dst_port": "5000"}) {
		t.Error(`"5000" should be > 1024`)
	}
}

func TestSigmaModifier_Base64Offset(t *testing.T) {
	e := loadOne(t, `
title: Encoded PowerShell download cradle
level: high
detection:
  selection:
    CommandLine|base64offset|contains: Invoke-Mimikatz
  condition: selection
`)
	full := "IEX (New-Object Net.WebClient).DownloadString('h'); Invoke-Mimikatz -DumpCreds"
	blob := base64.StdEncoding.EncodeToString([]byte(full))
	cmd := `powershell.exe -nop -w hidden -enc ` + blob
	if !matched(e, map[string]interface{}{"CommandLine": cmd}) {
		t.Error("base64offset|contains should match the encoded Invoke-Mimikatz payload")
	}
	if matched(e, map[string]interface{}{"CommandLine": `powershell.exe -nop Get-ChildItem`}) {
		t.Error("a benign encoded-free command must not match")
	}
}

func TestSigmaModifier_Windash(t *testing.T) {
	e := loadOne(t, `
title: Encoded command flag
level: medium
detection:
  selection:
    CommandLine|windash|contains: -encodedcommand
  condition: selection
`)
	// The "/" dash variant is the classic bypass of a "-" signature.
	if !matched(e, map[string]interface{}{"CommandLine": `powershell /encodedcommand ZQBjAGgAbwA=`}) {
		t.Error("windash should match the /encodedcommand variant")
	}
	if !matched(e, map[string]interface{}{"CommandLine": `powershell -encodedcommand ZQBjAGgAbwA=`}) {
		t.Error("windash should still match the literal -encodedcommand")
	}
	if matched(e, map[string]interface{}{"CommandLine": `powershell -command Get-Date`}) {
		t.Error("an unrelated flag must not match")
	}
}

func TestSigmaCondition_OfThem(t *testing.T) {
	oneOf := loadOne(t, `
title: one of them
level: low
detection:
  selection_a:
    Image|endswith: \a.exe
  selection_b:
    Image|endswith: \b.exe
  condition: 1 of them
`)
	if !matched(oneOf, map[string]interface{}{"Image": `C:\x\b.exe`}) {
		t.Error("`1 of them` should fire when selection_b matches")
	}
	if matched(oneOf, map[string]interface{}{"Image": `C:\x\c.exe`}) {
		t.Error("`1 of them` must not fire when no selection matches")
	}

	allOf := loadOne(t, `
title: all of them
level: low
detection:
  selection_img:
    Image|endswith: \p.exe
  selection_cmd:
    CommandLine|contains: dump
  condition: all of them
`)
	if !matched(allOf, map[string]interface{}{"Image": `C:\p.exe`, "CommandLine": "p.exe --dump"}) {
		t.Error("`all of them` should fire when both selections match")
	}
	if matched(allOf, map[string]interface{}{"Image": `C:\p.exe`, "CommandLine": "p.exe --list"}) {
		t.Error("`all of them` must not fire when only one selection matches")
	}
}
