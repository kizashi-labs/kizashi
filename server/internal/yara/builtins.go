package yara

import "log/slog"

// BuiltinRules returns the 10 built-in detection rules loaded at startup.
func BuiltinRules() []*Rule {
	return []*Rule{
		// 1. Mimikatz detection
		{
			ID:        "builtin-001-mimikatz",
			Name:      "Mimikatz Credential Dumper",
			Tags:      []string{"mimikatz", "credential-dumping", "T1003"},
			Condition: "any",
			Severity:  9,
			Meta: map[string]string{
				"description": "Detects Mimikatz credential dumping tool by process name or strings",
				"author":      "EDR Platform",
				"mitre":       "T1003.001",
			},
			Strings: []YaraString{
				{ID: "$proc", Type: "text", Value: "mimikatz", Modifiers: []string{"nocase"}},
				{ID: "$s1", Type: "text", Value: "sekurlsa", Modifiers: []string{"nocase"}},
				{ID: "$s2", Type: "text", Value: "lsadump", Modifiers: []string{"nocase"}},
				{ID: "$s3", Type: "text", Value: "privilege::debug", Modifiers: []string{"nocase"}},
			},
		},
		// 2. Meterpreter shell
		{
			ID:        "builtin-002-meterpreter",
			Name:      "Meterpreter Shell Payload",
			Tags:      []string{"meterpreter", "c2", "T1059"},
			Condition: "any",
			Severity:  9,
			Meta: map[string]string{
				"description": "Detects common Meterpreter shell indicators",
				"author":      "EDR Platform",
				"mitre":       "T1059.001",
			},
			Strings: []YaraString{
				// Common meterpreter payload header bytes: FC E8 82 00 00 00
				{ID: "$hex1", Type: "hex", Value: "FCE88200000060"},
				// metsrv.dll marker
				{ID: "$s1", Type: "text", Value: "metsrv", Modifiers: []string{"nocase"}},
				// ReflectiveLoader export common in meterpreter
				{ID: "$s2", Type: "text", Value: "ReflectiveLoader", Modifiers: []string{"ascii"}},
			},
		},
		// 3. PowerShell encoded commands
		{
			ID:        "builtin-003-ps-encoded",
			Name:      "PowerShell Encoded Command Execution",
			Tags:      []string{"powershell", "encoded", "T1059.001"},
			Condition: "any",
			Severity:  6,
			Meta: map[string]string{
				"description": "Detects PowerShell executing base64-encoded commands",
				"author":      "EDR Platform",
				"mitre":       "T1059.001",
			},
			Strings: []YaraString{
				{ID: "$enc1", Type: "text", Value: " -enc ", Modifiers: []string{"nocase"}},
				{ID: "$enc2", Type: "text", Value: " -encodedcommand ", Modifiers: []string{"nocase"}},
				{ID: "$enc3", Type: "text", Value: "-EncodedCommand", Modifiers: []string{"nocase"}},
				{ID: "$enc4", Type: "text", Value: "powershell.exe -e ", Modifiers: []string{"nocase"}},
			},
		},
		// 4. Cobalt Strike beacon
		{
			ID:        "builtin-004-cobalt-strike",
			Name:      "Cobalt Strike Beacon",
			Tags:      []string{"cobalt-strike", "c2", "T1071"},
			Condition: "any",
			Severity:  9,
			Meta: map[string]string{
				"description": "Detects Cobalt Strike beacon indicators",
				"author":      "EDR Platform",
				"mitre":       "T1071.001",
			},
			Strings: []YaraString{
				{ID: "$s1", Type: "text", Value: "beacon.dll", Modifiers: []string{"nocase"}},
				{ID: "$s2", Type: "text", Value: "cobaltstrike", Modifiers: []string{"nocase"}},
				{ID: "$s3", Type: "text", Value: "beacon_http_get", Modifiers: []string{"nocase"}},
				// CS config watermark bytes
				{ID: "$hex1", Type: "hex", Value: "2E2E2E"},
			},
		},
		// 5. Ransomware extension patterns
		{
			ID:        "builtin-005-ransomware",
			Name:      "Ransomware File Extension Patterns",
			Tags:      []string{"ransomware", "T1486"},
			Condition: "any",
			Severity:  10,
			Meta: map[string]string{
				"description": "Detects ransomware by characteristic file extension patterns",
				"author":      "EDR Platform",
				"mitre":       "T1486",
			},
			Strings: []YaraString{
				{ID: "$ext1", Type: "text", Value: ".locked", Modifiers: []string{"nocase"}},
				{ID: "$ext2", Type: "text", Value: ".encrypted", Modifiers: []string{"nocase"}},
				{ID: "$ext3", Type: "text", Value: ".crypto", Modifiers: []string{"nocase"}},
				{ID: "$ext4", Type: "text", Value: ".pay2decrypt", Modifiers: []string{"nocase"}},
				{ID: "$note1", Type: "text", Value: "HOW_TO_DECRYPT", Modifiers: []string{"nocase"}},
				{ID: "$note2", Type: "text", Value: "RANSOM_NOTE", Modifiers: []string{"nocase"}},
			},
		},
		// 6. Credential harvesting
		{
			ID:        "builtin-006-credential-harvest",
			Name:      "Credential Harvesting Activity",
			Tags:      []string{"credential-access", "T1555"},
			Condition: "any",
			Severity:  8,
			Meta: map[string]string{
				"description": "Detects credential harvesting patterns in process memory or files",
				"author":      "EDR Platform",
				"mitre":       "T1555",
			},
			Strings: []YaraString{
				{ID: "$s1", Type: "text", Value: "hashdump", Modifiers: []string{"nocase"}},
				{ID: "$s2", Type: "text", Value: "credential_harvester", Modifiers: []string{"nocase"}},
				{ID: "$s3", Type: "regex", Value: `password\s*=\s*["'][^"']{4,}["']`},
				{ID: "$s4", Type: "text", Value: "LaZagne", Modifiers: []string{"nocase"}},
				{ID: "$s5", Type: "text", Value: "get-credential", Modifiers: []string{"nocase"}},
			},
		},
		// 7. Process injection
		{
			ID:        "builtin-007-process-injection",
			Name:      "Process Injection Indicators",
			Tags:      []string{"process-injection", "T1055"},
			Condition: "any",
			Severity:  8,
			Meta: map[string]string{
				"description": "Detects API calls used for classic process injection",
				"author":      "EDR Platform",
				"mitre":       "T1055.001",
			},
			Strings: []YaraString{
				{ID: "$s1", Type: "text", Value: "VirtualAllocEx", Modifiers: []string{"ascii"}},
				{ID: "$s2", Type: "text", Value: "WriteProcessMemory", Modifiers: []string{"ascii"}},
				{ID: "$s3", Type: "text", Value: "CreateRemoteThread", Modifiers: []string{"ascii"}},
				{ID: "$s4", Type: "text", Value: "NtCreateThreadEx", Modifiers: []string{"ascii"}},
				{ID: "$s5", Type: "text", Value: "QueueUserAPC", Modifiers: []string{"ascii"}},
			},
		},
		// 8. LOLBin abuse
		{
			ID:        "builtin-008-lolbin",
			Name:      "LOLBin Abuse (Living Off The Land)",
			Tags:      []string{"lolbin", "defense-evasion", "T1218"},
			Condition: "any",
			Severity:  7,
			Meta: map[string]string{
				"description": "Detects abuse of legitimate Windows binaries to execute malicious code",
				"author":      "EDR Platform",
				"mitre":       "T1218",
			},
			Strings: []YaraString{
				{ID: "$lol1", Type: "regex", Value: `(?i)certutil\.exe.*(urlcache|decode|-f)`},
				{ID: "$lol2", Type: "regex", Value: `(?i)regsvr32\.exe.*/s.*/u.*/i:`},
				{ID: "$lol3", Type: "regex", Value: `(?i)mshta\.exe.*http`},
				{ID: "$lol4", Type: "regex", Value: `(?i)wscript\.exe.*(http|ftp)`},
				{ID: "$lol5", Type: "regex", Value: `(?i)rundll32\.exe.*,.*#`},
			},
		},
		// 9. Webshell patterns
		{
			ID:        "builtin-009-webshell",
			Name:      "Webshell Detection",
			Tags:      []string{"webshell", "T1505.003"},
			Condition: "any",
			Severity:  9,
			Meta: map[string]string{
				"description": "Detects common webshell code patterns in web files",
				"author":      "EDR Platform",
				"mitre":       "T1505.003",
			},
			Strings: []YaraString{
				{ID: "$s1", Type: "text", Value: "eval(", Modifiers: []string{"nocase"}},
				{ID: "$s2", Type: "text", Value: "system(", Modifiers: []string{"nocase"}},
				{ID: "$s3", Type: "text", Value: "exec(", Modifiers: []string{"nocase"}},
				{ID: "$s4", Type: "regex", Value: `(?i)eval\s*\(\s*(base64_decode|gzinflate|str_rot13)`},
				{ID: "$s5", Type: "text", Value: "passthru(", Modifiers: []string{"nocase"}},
				{ID: "$s6", Type: "text", Value: "shell_exec(", Modifiers: []string{"nocase"}},
			},
		},
		// 10. Persistence via registry
		{
			ID:        "builtin-010-persistence-registry",
			Name:      "Persistence via Registry Run Keys",
			Tags:      []string{"persistence", "registry", "T1547.001"},
			Condition: "any",
			Severity:  6,
			Meta: map[string]string{
				"description": "Detects malware establishing persistence through Windows registry Run keys",
				"author":      "EDR Platform",
				"mitre":       "T1547.001",
			},
			Strings: []YaraString{
				{ID: "$reg1", Type: "text", Value: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Modifiers: []string{"nocase"}},
				{ID: "$reg2", Type: "text", Value: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Modifiers: []string{"nocase"}},
				{ID: "$reg3", Type: "text", Value: `CurrentVersion\RunOnce`, Modifiers: []string{"nocase"}},
				{ID: "$reg4", Type: "text", Value: `CurrentVersion\RunServices`, Modifiers: []string{"nocase"}},
			},
		},
	}
}

// LoadBuiltins loads all built-in rules into the engine.
// Failures are logged and skipped rather than crashing the process.
func LoadBuiltins(e *Engine) {
	for _, rule := range BuiltinRules() {
		if err := e.LoadRule(rule); err != nil {
			slog.Error("組み込みYARAルールの読み込みに失敗しました",
				"rule_id", rule.ID, "error", err)
		}
	}
}
