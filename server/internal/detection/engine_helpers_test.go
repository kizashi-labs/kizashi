package detection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── engine.go pure helpers ─────────────────────────────────────────────────

func TestSeverityStringToInt(t *testing.T) {
	cases := map[string]int{
		"critical": 10, "high": 8, "medium": 5, "low": 3,
		"": 5, "bogus": 5, // unknown → default 5
	}
	for in, want := range cases {
		if got := severityStringToInt(in); got != want {
			t.Errorf("severityStringToInt(%q): got %d, want %d", in, got, want)
		}
	}
}

func TestGenerateAlertID(t *testing.T) {
	a := generateAlertID()
	b := generateAlertID()
	if len(a) != 36 {
		t.Errorf("alert id should be a 36-char UUID, got %q (len %d)", a, len(a))
	}
	if a == b {
		t.Error("generateAlertID should produce unique values")
	}
}

func TestEventEnvelope_FlatMap_ProtoJSON(t *testing.T) {
	env := EventEnvelope{
		AgentID:  "a1",
		Hostname: "host-1",
		Platform: "windows",
		Type:     "process_creation",
		Data:     json.RawMessage(`{"process":{"image_path":"C:\\powershell.exe","command_line":"-enc AAA"}}`),
	}
	flat := env.FlatMap()
	if flat["agent_id"] != "a1" || flat["hostname"] != "host-1" {
		t.Errorf("metadata not copied: %+v", flat)
	}
	// snake_case proto fields should be aliased to Sigma field names.
	if flat["Image"] != `C:\powershell.exe` {
		t.Errorf("image_path should alias to Image: %v", flat["Image"])
	}
	if flat["CommandLine"] != "-enc AAA" {
		t.Errorf("command_line should alias to CommandLine: %v", flat["CommandLine"])
	}
}

func TestEventEnvelope_FlatMap_FlatData(t *testing.T) {
	env := EventEnvelope{
		AgentID: "a2",
		Data:    json.RawMessage(`{"some_field":"v","count":3}`),
	}
	flat := env.FlatMap()
	if flat["some_field"] != "v" {
		t.Errorf("flat data field should be copied: %+v", flat)
	}
	if flat["agent_id"] != "a2" {
		t.Errorf("metadata should remain: %+v", flat)
	}
}

func TestEventEnvelope_FlatMap_InvalidData(t *testing.T) {
	env := EventEnvelope{AgentID: "a3", Data: json.RawMessage(`{not valid`)}
	flat := env.FlatMap()
	// Invalid inner JSON is ignored; metadata still present.
	if flat["agent_id"] != "a3" {
		t.Errorf("metadata should survive invalid data: %+v", flat)
	}
}

func TestAddSigmaAliases(t *testing.T) {
	flat := map[string]interface{}{"commandLine": "x", "pid": 42}
	addSigmaAliases(flat)
	if flat["CommandLine"] != "x" {
		t.Errorf("commandLine should alias to CommandLine: %+v", flat)
	}
	if flat["ProcessId"] != 42 {
		t.Errorf("pid should alias to ProcessId: %+v", flat)
	}
	// Existing target keys must not be overwritten.
	flat2 := map[string]interface{}{"commandLine": "new", "CommandLine": "original"}
	addSigmaAliases(flat2)
	if flat2["CommandLine"] != "original" {
		t.Errorf("existing CommandLine must not be overwritten: %v", flat2["CommandLine"])
	}
}

// TestAddSigmaAliases_DetectionParity locks the detection-engine alias layer to
// the API-pipeline superset (roadmap P1 Phase A). These fields were absent from
// the old engine-local alias map, so SigmaHQ registry/image_load/powershell rules
// silently never matched on the detection server even when enabled. If addSigmaAliases
// drifts from addPipelineSigmaAliases again, this fails.
func TestAddSigmaAliases_DetectionParity(t *testing.T) {
	// Registry (run-key persistence shape): key/value → TargetObject/Details, and
	// operation → Sysmon EventType vocabulary.
	reg := map[string]interface{}{
		"key_path":   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"value_name": "Updater",
		"value_data": `C:\Users\v\AppData\Local\Temp\evil.exe`,
		"operation":  "modify",
	}
	addSigmaAliases(reg)
	if reg["TargetObject"] == nil {
		t.Error("registry: TargetObject must be derived from key_path[+value_name]")
	}
	if reg["Details"] != `C:\Users\v\AppData\Local\Temp\evil.exe` {
		t.Errorf("registry: Details must alias value_data, got %v", reg["Details"])
	}
	if reg["EventType"] != "SetValue" {
		t.Errorf("registry: operation=modify must map to EventType=SetValue, got %v", reg["EventType"])
	}

	// image_load (DLL sideloading shape).
	img := map[string]interface{}{"image_loaded": `C:\Temp\evil.dll`, "signed": "false"}
	addSigmaAliases(img)
	if img["ImageLoaded"] != `C:\Temp\evil.dll` {
		t.Errorf("image_load: ImageLoaded must alias image_loaded, got %v", img["ImageLoaded"])
	}
	if img["Signed"] != "false" {
		t.Errorf("image_load: Signed must alias signed, got %v", img["Signed"])
	}

	// script (obfuscated PowerShell shape).
	scr := map[string]interface{}{"script_block_text": "IEX (New-Object Net.WebClient)"}
	addSigmaAliases(scr)
	if scr["ScriptBlockText"] == nil {
		t.Error("script: ScriptBlockText must alias script_block_text")
	}

	// Hashes synthesis (process_creation / image_load hash-IOC rules).
	h := map[string]interface{}{"sha256": "abc123"}
	addSigmaAliases(h)
	if hs, _ := h["Hashes"].(string); !strings.Contains(hs, "SHA256=abc123") {
		t.Errorf("Hashes must be synthesized in labelled form, got %v", h["Hashes"])
	}
}

// ─── alert_pipeline.go pure helpers ─────────────────────────────────────────

func TestIOCSeverity_ConfidenceWeighting(t *testing.T) {
	// 高信頼(多ソース合意)IOC は severity を1段上げる。低信頼は据え置き。上限10。
	cases := []struct {
		sev, conf, want int
	}{
		{5, 50, 5},    // 単一ソース(既定信頼) → 据え置き
		{5, 74, 5},    // 閾値未満 → 据え置き
		{5, 75, 6},    // 多ソース合意 → +1
		{5, 100, 6},   // 高信頼 → +1
		{10, 100, 10}, // 上限で据え置き
	}
	for _, c := range cases {
		got := iocSeverity(IOCRecord{Severity: c.sev, Confidence: c.conf})
		if got != c.want {
			t.Errorf("iocSeverity(sev=%d,conf=%d) = %d, want %d", c.sev, c.conf, got, c.want)
		}
	}
}

func TestParseMITRETechFromTags(t *testing.T) {
	cases := []struct {
		tags []string
		want string
	}{
		{[]string{"attack.t1059"}, "T1059"},
		{[]string{"attack.t1059.001"}, "T1059.001"},
		{[]string{"attack.execution", "attack.t1003"}, "T1003"},
		{[]string{"attack.execution"}, ""}, // tactic, not a technique
		{nil, ""},
	}
	for _, tc := range cases {
		if got := parseMITRETechFromTags(tc.tags); got != tc.want {
			t.Errorf("parseMITRETechFromTags(%v): got %q, want %q", tc.tags, got, tc.want)
		}
	}
}

// TestIsCloudTechnique locks the cloud attack-surface classification used to
// stamp the _attack_surface marker that feeds the corr-006 cloud takeover chain.
// It exercises the real Sigma tag → primary technique → cloud path so a renamed
// rule tag or a dropped technique surfaces here.
func TestIsCloudTechnique(t *testing.T) {
	cloud := [][]string{
		{"attack.t1526", "attack.discovery"}, // Cloud Service/IAM Discovery
		{"attack.t1619", "attack.discovery"}, // Cloud Storage Object Discovery
		{"attack.t1136.003", "attack.persistence"},
		{"attack.t1098.001", "attack.persistence"},
		{"attack.t1098.003", "attack.privilege_escalation"},
		{"attack.t1562.008", "attack.defense_evasion"}, // Cloud log tampering
		{"attack.t1562.007", "attack.defense_evasion"}, // Cloud firewall opening
		{"attack.t1578", "attack.defense_evasion"},
	}
	for _, tags := range cloud {
		if tech := parseMITRETechFromTags(tags); !isCloudTechnique(tech) {
			t.Errorf("technique %q from %v should be classified cloud", tech, tags)
		}
	}
	// Non-cloud techniques must NOT mark the surface as cloud (else corr-006 noise).
	nonCloud := [][]string{
		{"attack.t1562.001"}, // Windows Defender tampering (impair defenses, not cloud)
		{"attack.t1059.001"}, // PowerShell execution
		{"attack.t1003.001"}, // LSASS dump
		{"attack.t1069.002"}, // Domain group discovery (AD, not cloud)
	}
	for _, tags := range nonCloud {
		if tech := parseMITRETechFromTags(tags); isCloudTechnique(tech) {
			t.Errorf("technique %q from %v must NOT be classified cloud", tech, tags)
		}
	}
}

// TestIsADTechnique locks the on-prem AD attack-surface classification that feeds
// the corr-007 domain compromise chain, and guards that cloud and AD surfaces stay
// disjoint (no technique classified as both).
func TestIsADTechnique(t *testing.T) {
	adTags := [][]string{
		{"attack.t1482", "attack.discovery"}, // Domain Trust Discovery
		{"attack.t1087.002", "attack.discovery"},
		{"attack.t1018", "attack.discovery"},
		{"attack.t1069.002", "attack.discovery"},
		{"attack.t1558.003", "attack.credential_access"}, // Kerberoasting
		{"attack.t1558.004", "attack.credential_access"}, // AS-REP Roasting
		{"attack.t1558.001", "attack.credential_access"}, // Golden/Silver
		{"attack.t1550.002", "attack.lateral_movement"},  // Pass-the-Hash
		{"attack.t1649", "attack.credential_access"},     // AD CS abuse (Certipy)
		{"attack.t1187", "attack.credential_access"},     // Authentication coercion
		{"attack.t1557.001", "attack.credential_access"}, // LLMNR/relay
	}
	for _, tags := range adTags {
		tech := parseMITRETechFromTags(tags)
		if !isADTechnique(tech) {
			t.Errorf("technique %q from %v should be classified AD", tech, tags)
		}
		if isCloudTechnique(tech) {
			t.Errorf("technique %q classified as BOTH AD and cloud — surfaces must be disjoint", tech)
		}
	}
	// Cloud techniques must not be classified AD.
	for _, tags := range [][]string{{"attack.t1526"}, {"attack.t1578"}, {"attack.t1562.008"}} {
		if tech := parseMITRETechFromTags(tags); isADTechnique(tech) {
			t.Errorf("cloud technique %q must NOT be classified AD", tech)
		}
	}
	// A plain execution technique is neither.
	if tech := parseMITRETechFromTags([]string{"attack.t1059.001"}); isADTechnique(tech) {
		t.Errorf("T1059.001 must not be classified AD")
	}
}

// TestIsRansomwarePrecursor locks the destructive pre-encryption classification
// that feeds the corr-008 ransomware-preparation rule.
func TestIsRansomwarePrecursor(t *testing.T) {
	precursors := [][]string{
		{"attack.t1490", "attack.impact"},              // Inhibit System Recovery
		{"attack.t1489", "attack.impact"},              // Service Stop
		{"attack.t1562.001", "attack.defense_evasion"}, // Disable Security Tools
		{"attack.t1485", "attack.impact"},              // Data Destruction
		{"attack.t1561", "attack.impact"},              // Disk Wipe
		{"attack.t1070.001", "attack.defense_evasion"}, // Clear Windows Event Logs
	}
	for _, tags := range precursors {
		if tech := parseMITRETechFromTags(tags); !isRansomwarePrecursor(tech) {
			t.Errorf("technique %q from %v should be a ransomware precursor", tech, tags)
		}
	}
	// Non-precursor techniques must not be flagged.
	for _, tags := range [][]string{{"attack.t1059.001"}, {"attack.t1526"}, {"attack.t1087.002"}, {"attack.t1486"}} {
		if tech := parseMITRETechFromTags(tags); isRansomwarePrecursor(tech) {
			t.Errorf("technique %q from %v must NOT be a ransomware precursor", tech, tags)
		}
	}
}

// TestIsExfilTechnique locks the collection/exfiltration classification that feeds
// the corr-009 data-exfiltration-in-progress rule.
func TestIsExfilTechnique(t *testing.T) {
	exfil := [][]string{
		{"attack.t1560.001", "attack.collection"},          // Archive Collected Data
		{"attack.t1071.002", "attack.exfiltration"},        // FTP exfil
		{"attack.t1071.003", "attack.exfiltration"},        // Mail exfil
		{"attack.t1071.004", "attack.command_and_control"}, // DNS tunneling
		{"attack.t1048", "attack.exfiltration"},            // Alt-protocol exfil
		{"attack.t1567.002", "attack.exfiltration"},        // Exfil to cloud storage
	}
	for _, tags := range exfil {
		if tech := parseMITRETechFromTags(tags); !isExfilTechnique(tech) {
			t.Errorf("technique %q from %v should be classified exfil", tech, tags)
		}
	}
	for _, tags := range [][]string{{"attack.t1059.001"}, {"attack.t1526"}, {"attack.t1490"}} {
		if tech := parseMITRETechFromTags(tags); isExfilTechnique(tech) {
			t.Errorf("technique %q from %v must NOT be classified exfil", tech, tags)
		}
	}
}

// TestIsContainerEscalation locks the technique→container-escalation marker
// mapping that feeds the corr-010 container-breakout rule.
func TestIsContainerEscalation(t *testing.T) {
	escalation := [][]string{
		{"attack.t1610", "attack.execution"},             // Deploy privileged container
		{"attack.t1611", "attack.privilege_escalation"},  // Escape to host
		{"attack.t1609", "attack.execution"},             // Container exec
		{"attack.t1552.007", "attack.credential_access"}, // K8s SA token
		{"attack.t1613", "attack.discovery"},             // Container discovery
	}
	for _, tags := range escalation {
		if tech := parseMITRETechFromTags(tags); !isContainerEscalation(tech) {
			t.Errorf("technique %q from %v should be classified container-escalation", tech, tags)
		}
	}
	for _, tags := range [][]string{{"attack.t1059.001"}, {"attack.t1078.004"}, {"attack.t1567.002"}} {
		if tech := parseMITRETechFromTags(tags); isContainerEscalation(tech) {
			t.Errorf("technique %q from %v must NOT be classified container-escalation", tech, tags)
		}
	}
}

// TestIsCredentialTheft locks the technique→credential-theft marker mapping that
// feeds the corr-011 multi-source credential-theft rule.
func TestIsCredentialTheft(t *testing.T) {
	theft := [][]string{
		{"attack.t1003.001", "attack.credential_access"}, // LSASS
		{"attack.t1003.003", "attack.credential_access"}, // NTDS.dit
		{"attack.t1555.003", "attack.credential_access"}, // Browser creds
		{"attack.t1552.006", "attack.credential_access"}, // GPP password
		{"attack.t1558.003", "attack.credential_access"}, // Kerberoasting
	}
	for _, tags := range theft {
		if tech := parseMITRETechFromTags(tags); !isCredentialTheft(tech) {
			t.Errorf("technique %q from %v should be classified credential-theft", tech, tags)
		}
	}
	for _, tags := range [][]string{{"attack.t1059.001"}, {"attack.t1021.001"}, {"attack.t1486"}} {
		if tech := parseMITRETechFromTags(tags); isCredentialTheft(tech) {
			t.Errorf("technique %q from %v must NOT be classified credential-theft", tech, tags)
		}
	}
}

// TestIsDiscoveryRecon locks the technique→discovery-recon marker mapping that
// feeds the corr-012 reconnaissance-burst rule.
func TestIsDiscoveryRecon(t *testing.T) {
	recon := [][]string{
		{"attack.t1087.002", "attack.discovery"}, // Domain account discovery
		{"attack.t1082", "attack.discovery"},     // System information
		{"attack.t1018", "attack.discovery"},     // Remote system discovery
		{"attack.t1482", "attack.discovery"},     // Domain trust
		{"attack.t1518.001", "attack.discovery"}, // Security software discovery
	}
	for _, tags := range recon {
		if tech := parseMITRETechFromTags(tags); !isDiscoveryRecon(tech) {
			t.Errorf("technique %q from %v should be classified discovery-recon", tech, tags)
		}
	}
	for _, tags := range [][]string{{"attack.t1059.001"}, {"attack.t1003.001"}, {"attack.t1486"}} {
		if tech := parseMITRETechFromTags(tags); isDiscoveryRecon(tech) {
			t.Errorf("technique %q from %v must NOT be classified discovery-recon", tech, tags)
		}
	}
}

func TestSeverityIntToLabel(t *testing.T) {
	cases := map[int]string{10: "critical", 9: "critical", 8: "high", 7: "high", 6: "medium", 4: "medium", 3: "low", 1: "low"}
	for sev, want := range cases {
		if got := severityIntToLabel(sev); got != want {
			t.Errorf("severityIntToLabel(%d): got %q, want %q", sev, got, want)
		}
	}
}

func TestSigmaLevelToInt(t *testing.T) {
	cases := map[string]int{"critical": 10, "high": 8, "medium": 5, "low": 3, "informational": 1, "unknown": 3}
	for level, want := range cases {
		if got := sigmaLevelToInt(level); got != want {
			t.Errorf("sigmaLevelToInt(%q): got %d, want %d", level, got, want)
		}
	}
}

func TestToFloat64(t *testing.T) {
	oks := []interface{}{float64(1.5), float32(2), int(3), int64(4), int32(5)}
	for _, v := range oks {
		if _, ok := toFloat64(v); !ok {
			t.Errorf("toFloat64(%T) should succeed", v)
		}
	}
	if _, ok := toFloat64("nope"); ok {
		t.Error("toFloat64(string) should fail")
	}
	if f, _ := toFloat64(int(7)); f != 7.0 {
		t.Errorf("toFloat64(int 7) should be 7.0, got %v", f)
	}
}

func TestNilStr(t *testing.T) {
	if nilStr("") != nil {
		t.Error("empty string should map to nil")
	}
	if nilStr("x") != "x" {
		t.Error("non-empty string should pass through")
	}
}

func TestFlattenNormalizedEvent(t *testing.T) {
	env := map[string]interface{}{
		"agent_id": "a1",
		"hostname": "h1",
		"data": map[string]interface{}{
			"file": map[string]interface{}{"path": "/etc/passwd"},
		},
	}
	flat := flattenNormalizedEvent(env)
	if flat["agent_id"] != "a1" {
		t.Errorf("metadata not copied: %+v", flat)
	}
	if flat["path"] != "/etc/passwd" {
		t.Errorf("nested file.path not flattened: %+v", flat)
	}
	// path aliases to TargetFilename / FilePath
	if flat["TargetFilename"] != "/etc/passwd" {
		t.Errorf("path should alias to TargetFilename: %+v", flat)
	}
}

func TestAlertPipeline_IsDuplicate(t *testing.T) {
	p := &AlertPipeline{dedupCache: make(map[string]time.Time)}
	if p.isDuplicate("k1", time.Minute) {
		t.Error("first occurrence must not be a duplicate")
	}
	if !p.isDuplicate("k1", time.Minute) {
		t.Error("immediate repeat within window must be a duplicate")
	}
	if p.isDuplicate("k2", time.Minute) {
		t.Error("a different key must not be a duplicate")
	}
	// Zero window means the previous timestamp is never "within" the window.
	if p.isDuplicate("k1", 0) {
		t.Error("with a zero window nothing should be considered duplicate")
	}
}

// addPipelineSigmaAliases must expose the proto file action as Operation, the
// DNS query type as QueryType, and parent fields under the standard Sigma names.
// Missing aliases silently disable any rule that selects on those fields.
func TestAddPipelineSigmaAliases_Coverage(t *testing.T) {
	flat := map[string]interface{}{
		"action":         "modify",
		"queryType":      "TXT",
		"parent_process": "wmiprvse.exe",
		"keyPath":        `HKLM\Software\Run`,
	}
	addPipelineSigmaAliases(flat)
	checks := map[string]string{
		"Operation": "modify",
		"QueryType": "TXT",
		// basename ParentImage is normalized with a leading separator so
		// `ParentImage|endswith: \wmiprvse.exe` rules match basename telemetry.
		"ParentImage":  `\wmiprvse.exe`,
		"TargetObject": `HKLM\Software\Run`,
	}
	for field, want := range checks {
		if flat[field] != want {
			t.Errorf("%s should be aliased to %q, got %v", field, want, flat[field])
		}
	}
}

// Regression guard for the field-mapping audit: the /etc/passwd-write rule
// selects on `Operation|contains`, so before action→Operation was aliased it
// could never fire even though file events carry the action. This drives the
// real production path (addPipelineSigmaAliases + SigmaEvaluator.EvaluateEvent).
func TestBuiltinRule_PasswdWrite_FiresWithOperationAlias(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)

	evt := map[string]interface{}{
		"type":   "file",
		"path":   "/etc/passwd",
		"action": "modify",
	}
	addPipelineSigmaAliases(evt)
	matches := e.EvaluateEvent(evt)
	if len(matches) == 0 {
		t.Fatal("/etc/passwd write should be detected once action is aliased to Operation")
	}
}

// ─── built-in detection content ─────────────────────────────────────────────

// TestLoadBuiltinRules guards the shipped Sigma rules: every built-in rule must
// be valid YAML that compiles, otherwise the engine silently ships fewer rules.
func TestLoadBuiltinRules_AllCompile(t *testing.T) {
	e := NewSigmaEvaluator()
	loaded := LoadBuiltinRules(e)
	if loaded == 0 {
		t.Fatal("expected built-in Sigma rules to load")
	}
	if loaded != len(builtinSigmaRules) {
		t.Errorf("%d of %d built-in rules failed to compile", len(builtinSigmaRules)-loaded, len(builtinSigmaRules))
	}
	if e.RuleCount() != loaded {
		t.Errorf("RuleCount %d != loaded %d", e.RuleCount(), loaded)
	}
}

func TestBuiltinIOCLoader(t *testing.T) {
	iocs, err := BuiltinIOCLoader().ListActiveIOCs(context.Background())
	if err != nil {
		t.Fatalf("BuiltinIOCLoader.ListActiveIOCs: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatal("expected built-in IOCs")
	}
	for _, ioc := range iocs {
		if ioc.Type == "" || ioc.Value == "" {
			t.Errorf("built-in IOC missing Type/Value: %+v", ioc)
		}
	}
}
