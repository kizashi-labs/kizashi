package detection

import (
	"strings"
	"testing"
)

// TestSigmaFieldNormalizationCompleteness verifies the alias layer maps our
// native telemetry onto the Sysmon/SigmaHQ field names those rules require —
// without which the auto-synced SigmaHQ rules (P1) silently never fire. Covers
// the parent-pid and combined-Hashes mappings added for SigmaHQ compatibility.
func TestSigmaFieldNormalizationCompleteness(t *testing.T) {
	// A process event with our native field names (as ingestion flattens them;
	// numbers arrive as float64 after JSON round-trip).
	event := map[string]interface{}{
		"type":         "process",
		"image_path":   `C:\Windows\Temp\evil.exe`,
		"command_line": "evil.exe -enc ZQBjAGgAbwA=",
		"ppid":         float64(4242),
		"md5":          "d41d8cd98f00b204e9800998ecf8427e",
		"sha256":       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	addPipelineSigmaAliases(event)

	// ppid → ParentProcessId (SigmaHQ parent-pid correlation).
	if event["ParentProcessId"] != float64(4242) {
		t.Errorf("ParentProcessId not aliased from ppid: got %v", event["ParentProcessId"])
	}
	// Image/CommandLine still present (pre-existing aliases not regressed).
	if event["Image"] != `C:\Windows\Temp\evil.exe` || event["CommandLine"] == nil {
		t.Errorf("Image/CommandLine alias regressed: Image=%v CommandLine=%v", event["Image"], event["CommandLine"])
	}
	// md5/sha256 → combined Sysmon-style Hashes string.
	h, _ := event["Hashes"].(string)
	if !strings.Contains(h, "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") ||
		!strings.Contains(h, "MD5=d41d8cd98f00b204e9800998ecf8427e") {
		t.Errorf("combined Hashes not synthesized from md5/sha256: %q", h)
	}

	// End-to-end: a SigmaHQ-style hash rule now fires — it would NOT have before,
	// since `Hashes` did not exist on our events.
	ev := NewSigmaEvaluator()
	rule := `
title: Known-bad SHA256 (SigmaHQ style)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Hashes|contains: 'SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  condition: selection
`
	if err := ev.LoadRule(rule); err != nil {
		t.Fatalf("load SigmaHQ-style rule: %v", err)
	}
	if len(ev.EvaluateEvent(event)) == 0 {
		t.Error("SigmaHQ-style Hashes|contains rule did not fire after field normalization")
	}
}

// TestSigmaNormalizationPEVersionInfo covers the PE VERSIONINFO mappings
// (OriginalFileName/Description/Product/Company) the Windows agent lifts off an
// executable's version resource. These drive the large class of renamed-binary /
// LOLBin SigmaHQ process_creation rules that identify a binary by its embedded
// metadata rather than its (renamable) path — measured 2026-07-02 as the largest
// enabled-but-inert cause (OriginalFileName alone, 74 rules).
func TestSigmaNormalizationPEVersionInfo(t *testing.T) {
	// A process event as ingestion flattens it: the agent renamed procdump.exe to
	// svchost.exe on disk, but the PE version resource still says procdump.
	event := map[string]interface{}{
		"type":               "process",
		"image_path":         `C:\Users\v\svchost.exe`,
		"command_line":       `svchost.exe -accepteula -ma lsass.exe out.dmp`,
		"original_file_name": "procdump",
		"file_description":   "Sysinternals process dump utility",
		"product_name":       "Sysinternals ProcDump",
		"company_name":       "Sysinternals - www.sysinternals.com",
	}
	addPipelineSigmaAliases(event)

	for field, want := range map[string]interface{}{
		"OriginalFileName": "procdump",
		"Description":      "Sysinternals process dump utility",
		"Product":          "Sysinternals ProcDump",
		"Company":          "Sysinternals - www.sysinternals.com",
	} {
		if event[field] != want {
			t.Errorf("PE versioninfo %s = %v, want %v", field, event[field], want)
		}
	}

	// The four fields must also count as field-supported so curate can enable the
	// SigmaHQ rules that select on them (otherwise they stay "false green": on but
	// inert). This is the whole point of carrying the telemetry.
	supported := SupportedSigmaFields()
	for _, f := range []string{"OriginalFileName", "Description", "Product", "Company"} {
		if !supported[f] {
			t.Errorf("Sigma field %q not in SupportedSigmaFields — rule would be a false green", f)
		}
	}

	// End-to-end: a SigmaHQ-style renamed-binary rule now fires despite the path
	// being disguised — it matches on OriginalFileName, which survives the rename.
	ev := NewSigmaEvaluator()
	rule := `
title: Renamed ProcDump Execution (SigmaHQ style)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    OriginalFileName: 'procdump'
  filter:
    Image|endswith: '\procdump.exe'
  condition: selection and not filter
`
	if err := ev.LoadRule(rule); err != nil {
		t.Fatalf("load renamed-binary rule: %v", err)
	}
	if len(ev.EvaluateEvent(event)) == 0 {
		t.Error("renamed-binary OriginalFileName rule did not fire after PE versioninfo normalization")
	}
}

// TestSigmaNormalizationIntegrityLevel covers the token integrity-level mapping
// (integrity_level → IntegrityLevel) the Windows agent now emits. SigmaHQ
// UAC-bypass / privilege-escalation rules gate on IntegrityLevel (e.g. a
// werfault.exe spawned by consent.exe at High/System integrity).
func TestSigmaNormalizationIntegrityLevel(t *testing.T) {
	event := map[string]interface{}{
		"type":              "process",
		"image_path":        `C:\Windows\System32\werfault.exe`,
		"parent_image_path": `C:\Windows\System32\consent.exe`,
		"integrity_level":   "High",
	}
	addPipelineSigmaAliases(event)

	if event["IntegrityLevel"] != "High" {
		t.Errorf("IntegrityLevel not aliased from integrity_level: got %v", event["IntegrityLevel"])
	}

	// Must count as field-supported so curate can enable IntegrityLevel rules.
	if !SupportedSigmaFields()["IntegrityLevel"] {
		t.Error("IntegrityLevel not in SupportedSigmaFields — rule would be a false green")
	}

	// LogonId (Sysmon hex LUID) aliased from logon_id — elevated-shell rules gate
	// on it (e.g. LogonId '0x3e7' = SYSTEM session).
	le := map[string]interface{}{"type": "process", "logon_id": "0x3e7"}
	addPipelineSigmaAliases(le)
	if le["LogonId"] != "0x3e7" {
		t.Errorf("LogonId not aliased from logon_id: got %v", le["LogonId"])
	}
	if !SupportedSigmaFields()["LogonId"] {
		t.Error("LogonId not in SupportedSigmaFields")
	}

	// End-to-end: the SigmaHQ "UAC Bypass Using Consent and Comctl32" rule shape.
	ev := NewSigmaEvaluator()
	rule := `
title: UAC Bypass via consent.exe (SigmaHQ style)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\consent.exe'
    Image|endswith: '\werfault.exe'
    IntegrityLevel:
      - 'High'
      - 'System'
  condition: selection
`
	if err := ev.LoadRule(rule); err != nil {
		t.Fatalf("load UAC-bypass rule: %v", err)
	}
	if len(ev.EvaluateEvent(event)) == 0 {
		t.Error("UAC-bypass IntegrityLevel rule did not fire after normalization")
	}
}

// TestSigmaNormalizationDerivedDNSNetwork covers server-derived fields that need
// no extra agent telemetry: SourceIsIpv6 (from src_ip), and the SigmaHQ dns
// category's record_type / answer (from our query_type / answers). These unlock
// the WinRM remote-PowerShell and DNS-TXT-execution rules.
func TestSigmaNormalizationDerivedDNSNetwork(t *testing.T) {
	// Network: IPv4 source → SourceIsIpv6 false; the WinRM remote-PowerShell rule.
	net := map[string]interface{}{
		"type": "network", "src_ip": "192.168.1.5", "dst_ip": "10.0.0.9",
		"dst_port": float64(5985), "direction": "outbound", "protocol": "tcp",
	}
	addPipelineSigmaAliases(net)
	if net["SourceIsIpv6"] != "false" {
		t.Errorf("SourceIsIpv6 = %v, want \"false\" for IPv4 source", net["SourceIsIpv6"])
	}
	v6 := map[string]interface{}{"type": "network", "src_ip": "fe80::1"}
	addPipelineSigmaAliases(v6)
	if v6["SourceIsIpv6"] != "true" {
		t.Errorf("SourceIsIpv6 = %v, want \"true\" for IPv6 source", v6["SourceIsIpv6"])
	}
	for _, f := range []string{"SourceIsIpv6", "record_type", "answer"} {
		if !SupportedSigmaFields()[f] {
			t.Errorf("derived field %q not in SupportedSigmaFields", f)
		}
	}

	ev := NewSigmaEvaluator()
	winrm := `
title: Remote PowerShell Session (SigmaHQ style)
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort:
      - 5985
      - 5986
    Initiated: 'true'
    SourceIsIpv6: 'false'
  condition: selection
`
	if err := ev.LoadRule(winrm); err != nil {
		t.Fatalf("load winrm rule: %v", err)
	}
	if len(ev.EvaluateEvent(net)) == 0 {
		t.Error("WinRM remote-PowerShell rule did not fire after SourceIsIpv6 derivation")
	}

	// DNS: record_type (from query_type) + answer (joined from answers array).
	dns := map[string]interface{}{
		"type": "dns", "query": "evil.example", "query_type": "TXT",
		"answers": []interface{}{"IEX(New-Object Net.WebClient)"},
	}
	addPipelineSigmaAliases(dns)
	if dns["record_type"] != "TXT" {
		t.Errorf("record_type = %v, want TXT", dns["record_type"])
	}
	if s, _ := dns["answer"].(string); !strings.Contains(s, "IEX") {
		t.Errorf("answer = %v, want it to contain IEX", dns["answer"])
	}
	ev2 := NewSigmaEvaluator()
	dnsRule := `
title: DNS TXT Answer with Execution Strings (SigmaHQ style)
logsource:
  category: dns
detection:
  selection:
    record_type: 'TXT'
    answer|contains:
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection
`
	if err := ev2.LoadRule(dnsRule); err != nil {
		t.Fatalf("load dns rule: %v", err)
	}
	if len(ev2.EvaluateEvent(dns)) == 0 {
		t.Error("DNS TXT answer rule did not fire after record_type/answer derivation")
	}
}

// TestSigmaNormalizationRegistryEventID covers the Sysmon registry EventID
// derivation (operation → 12/13) that a few registry rules gate on (e.g. the
// Azorult localNETService persistence rule). It must be set only for registry
// events (key_path present), never for a file event that also carries operation.
func TestSigmaNormalizationRegistryEventID(t *testing.T) {
	reg := map[string]interface{}{
		"type": "registry", "key_path": `HKLM\SYSTEM\CurrentControlSet\services\localNETService`,
		"operation": "modify",
	}
	addPipelineSigmaAliases(reg)
	if reg["EventID"] != "13" {
		t.Errorf("registry EventID = %v, want \"13\" for a value-set", reg["EventID"])
	}
	if !SupportedSigmaFields()["EventID"] {
		t.Error("EventID not in SupportedSigmaFields")
	}

	// A file event carries `operation` too but must NOT get a registry EventID.
	file := map[string]interface{}{"type": "file", "path": `C:\a.exe`, "operation": "modify"}
	addPipelineSigmaAliases(file)
	if _, exists := file["EventID"]; exists {
		t.Errorf("file event wrongly got a registry EventID: %v", file["EventID"])
	}

	// End-to-end: the Azorult-style registry rule fires.
	ev := NewSigmaEvaluator()
	rule := `
title: Azorult localNETService (SigmaHQ style)
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventID:
      - 12
      - 13
    TargetObject|contains: 'SYSTEM\'
    TargetObject|endswith: '\services\localNETService'
  condition: selection
`
	if err := ev.LoadRule(rule); err != nil {
		t.Fatalf("load azorult rule: %v", err)
	}
	if len(ev.EvaluateEvent(reg)) == 0 {
		t.Error("Azorult registry EventID rule did not fire after derivation")
	}
}

// TestSigmaNormalizationNetworkImageLoadRegistry covers the network / image-load /
// registry field mappings SigmaHQ rules in those categories rely on.
func TestSigmaNormalizationNetworkImageLoadRegistry(t *testing.T) {
	// Network (Sysmon EID 3) — process_name (no image_path) must back-fill Image.
	net := map[string]interface{}{
		"type": "network", "process_name": "beacon.exe",
		"dst_ip": "10.0.0.9", "dst_port": float64(443),
		"src_ip": "192.168.1.5", "src_port": float64(51000),
		"protocol": "tcp", "hostname": "c2.evil.example",
	}
	addPipelineSigmaAliases(net)
	for field, want := range map[string]interface{}{
		"DestinationHostname": "c2.evil.example", "Protocol": "tcp",
		// Image is back-filled from process_name and normalized with a leading
		// separator so `Image|endswith: \beacon.exe` rules match basename telemetry.
		"SourceIp": "192.168.1.5", "Image": `\beacon.exe`, "DestinationIp": "10.0.0.9",
	} {
		if net[field] != want {
			t.Errorf("network %s = %v, want %v", field, net[field], want)
		}
	}

	// Image-load (Sysmon EID 7) — unsigned DLL sideload.
	il := map[string]interface{}{
		"type": "image_load", "process_name": "legit.exe",
		"image_loaded": `C:\Users\v\AppData\Local\Temp\evil.dll`,
		"signed":       false, "signer": "", "signature_status": "unsigned",
	}
	addPipelineSigmaAliases(il)
	if il["ImageLoaded"] != `C:\Users\v\AppData\Local\Temp\evil.dll` || il["Image"] != `\legit.exe` {
		t.Errorf("image_load ImageLoaded/Image wrong: %v / %v", il["ImageLoaded"], il["Image"])
	}
	if il["Signed"] != false || il["SignatureStatus"] != "unsigned" {
		t.Errorf("image_load Signed/SignatureStatus wrong: %v / %v", il["Signed"], il["SignatureStatus"])
	}

	// Registry — operation translated to Sysmon EventType vocabulary.
	for op, want := range map[string]string{"modify": "SetValue", "create": "CreateKey", "delete": "DeleteValue"} {
		reg := map[string]interface{}{
			"type": "registry", "key_path": `HKLM\SOFTWARE\...\Run`, "operation": op,
		}
		addPipelineSigmaAliases(reg)
		if reg["EventType"] != want {
			t.Errorf("registry operation %q -> EventType %v, want %v", op, reg["EventType"], want)
		}
		if reg["TargetObject"] != `HKLM\SOFTWARE\...\Run` {
			t.Errorf("registry TargetObject not aliased: %v", reg["TargetObject"])
		}
	}
}
