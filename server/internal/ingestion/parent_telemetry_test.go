package ingestion

import (
	"encoding/json"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// The parent of a process was the largest single gap in the event vocabulary:
// 16 read sites across 5 files, all reading a key ProcessEvent did not carry.
//
//	compliance/scorer.go        parent_name          Office-spawns-script check
//	processtree/builder.go      parent_name/_image   every node's parent
//	memforensics/analyzer.go    parent_process_name  unusual-parent detection
//	agents_handler.go           parent_image         endpoint process list
//	alerts_handler.go           parent_image         alert detail
//
// None could work. ProcessEvent had pid, ppid and nothing else about the
// parent, so raw_data never contained a parent under any spelling and every one
// of those reads returned NULL. Worse, processtree fed the empty value to
// mitreFromParentChild(), so the whole parent/child technique table — Office
// spawning a shell, a browser spawning PowerShell — was evaluated with an empty
// parent on every row and could not match. The same held on the detection side:
// SupportedSigmaFields listed the parent fields, but the only thing that ever
// filled them was a server-side reconstruction from ppid that is bounded by the
// correlation window.
//
// ppid alone was never going to be enough. It is a number the kernel reuses,
// and by the time any of the above runs the parent has usually exited. The
// agent now resolves it on the endpoint, while the parent is still alive
// (collector.ParentResolver), and it arrives as parent_name / parent_image.

// The headline: a process event carrying a parent produces raw_data keys the
// readers ask for, under exactly those names.
func TestTheParentReachesRawDataUnderTheNameReadersUse(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 4243, Ppid: 4242,
			ProcessName: "powershell.exe",
			ParentName:  "winword.exe",
			ParentImage: `C:\Program Files\Microsoft Office\winword.exe`,
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}

	if got, _ := m["parent_name"].(string); got != "winword.exe" {
		t.Errorf("raw_data.parent_name = %q, want winword.exe。"+
			"compliance の Office 由来スクリプト判定と、プロセスツリーの"+
			"親子テクニック表がこのキーを読みます", got)
	}
	if got, _ := m["parent_image"].(string); got == "" {
		t.Error("raw_data.parent_image が空です。" +
			"アラート詳細・端末詳細・プロセスツリーがこのキーを読みます")
	}
}

// An unknown parent is absent, not an empty string. A reader can then tell
// "the agent could not name it" from "there is no parent", and a
// `raw_data ? 'parent_name'` filter still means what it says.
func TestAnUnknownParentIsAbsentRatherThanEmpty(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 1, Ppid: 0, ProcessName: "init",
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	for _, k := range []string{"parent_name", "parent_image"} {
		if _, present := m[k]; present {
			t.Errorf("親が不明なのに %q キーが存在します (値: %v)。"+
				"空文字と「親がいない」は別の事実です", k, m[k])
		}
	}
}

// The parent belongs to process events only. Emitting it elsewhere would put a
// key in raw_data that the vocabulary gate has no producer for.
func TestTheParentIsOnlyEmittedForProcessEvents(t *testing.T) {
	for _, tc := range []struct {
		name string
		evt  *v1.Event
	}{
		{"file", &v1.Event{Type: v1.EventType_EVENT_TYPE_FILE,
			Payload: &v1.Event_File{File: &v1.FileEvent{Path: "/etc/passwd"}}}},
		{"network", &v1.Event{Type: v1.EventType_EVENT_TYPE_NETWORK,
			Payload: &v1.Event_Network{Network: &v1.NetworkEvent{DstIp: "1.1.1.1"}}}},
	} {
		var m map[string]interface{}
		if err := json.Unmarshal(normalizeEventData(tc.evt), &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, k := range []string{"parent_name", "parent_image"} {
			if _, present := m[k]; present {
				t.Errorf("%s イベントに %q が出ています", tc.name, k)
			}
		}
	}
}

// ─── Kerberos service tickets ────────────────────────────────────────────────

// AuthEvent carried username, action, success, source_ip, auth_method,
// failure_reason and logon_type — nothing Kerberos-specific and no Windows
// event ID. ldap.DetectKerberoasting keys on target_spn,
// ticket_encryption_type and event_id, so every branch of its WHERE clause was
// dead and it returned an empty slice on every deployment.

func TestAKerberosTicketReachesRawData(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_AUTH,
		Payload: &v1.Event_Auth{Auth: &v1.AuthEvent{
			Username:             "alice@CORP.LOCAL",
			Action:               v1.AuthEvent_AUTH_ACTION_SERVICE_TICKET,
			AuthMethod:           "kerberos",
			EventId:              4769,
			TargetSpn:            "MSSQLSvc/db01.corp.local:1433",
			TicketEncryptionType: "0x17",
			SourceIp:             "10.1.2.3",
			Success:              true,
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	// event_id は数値なので、文字列の表とは別に見る。読む側 (auth_attack /
	// SID-History の門) が toFloat64 を通しており、文字列を受け取らない。
	if got, _ := m["event_id"].(float64); got != 4769 {
		t.Errorf("raw_data.event_id = %v, want 4769", got)
	}
	for k, want := range map[string]string{
		"target_spn":             "MSSQLSvc/db01.corp.local:1433",
		"ticket_encryption_type": "0x17",
		"action":                 "kerberos_service_ticket",
	} {
		if got, _ := m[k].(string); got != want {
			t.Errorf("raw_data.%s = %q, want %q。"+
				"Kerberoasting 検知はこの3つのキーだけで判定します", k, got, want)
		}
	}
}

// A logon is not a ticket request. Emitting empty Kerberos keys on every auth
// event would put keys in raw_data that mean nothing and would make a
// presence filter meaningless.
func TestAnOrdinaryLogonCarriesNoKerberosKeys(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_AUTH,
		Payload: &v1.Event_Auth{Auth: &v1.AuthEvent{
			Username: "bob", Action: v1.AuthEvent_AUTH_ACTION_FAILED,
			EventId: 4625, LogonType: "3",
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	for _, k := range []string{"target_spn", "ticket_encryption_type"} {
		if _, present := m[k]; present {
			t.Errorf("通常のログオンに %q キーが出ています (値: %v)", k, m[k])
		}
	}
	// The event ID is still carried — password-spray detection reads it.
	if got, _ := m["event_id"].(float64); got != 4625 {
		t.Errorf("raw_data.event_id = %v, want 4625", got)
	}
}

// The service-ticket action must have its own name rather than falling through
// to "unknown", which is what an unmapped enum value produces.
func TestTheServiceTicketActionHasItsOwnName(t *testing.T) {
	if got := authActionString(v1.AuthEvent_AUTH_ACTION_SERVICE_TICKET); got != "kerberos_service_ticket" {
		t.Errorf("authActionString(SERVICE_TICKET) = %q。"+
			"サービスチケット要求がログオンとして、あるいは unknown として"+
			"記録されます", got)
	}
}

// ─── Container containment ───────────────────────────────────────────────────

// cloudruntime read container_id, privileged and host_network off process
// events and the agent collected none of them, so privileged-container and
// host-network detection were structurally zero and the "containers monitored"
// figure was always 0. It also selected container_event / container_process,
// two types events_event_type_check does not permit, so those rows could not
// exist either. A container's processes arrive as ordinary process events.

func TestContainmentReachesRawData(t *testing.T) {
	const id = "3f2b1c8a9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 100, ProcessName: "bash",
			ContainerId: id, ContainerPrivileged: true, ContainerHostNetwork: true,
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	if got, _ := m["container_id"].(string); got != id {
		t.Errorf("raw_data.container_id = %q", got)
	}
	if got, _ := m["privileged"].(bool); !got {
		t.Error("raw_data.privileged が立っていません。" +
			"特権コンテナ内のシェル起動検知はこのフラグだけで判定します")
	}
	if got, _ := m["host_network"].(bool); !got {
		t.Error("raw_data.host_network が立っていません")
	}
}

// A host process carries no containment keys at all — not privileged:false.
// "not privileged" and "not in a container" are different facts, and the
// detection filters on the flag being true.
func TestAHostProcessCarriesNoContainmentKeys(t *testing.T) {
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 100, ProcessName: "sshd",
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	for _, k := range []string{"container_id", "privileged", "host_network"} {
		if _, present := m[k]; present {
			t.Errorf("ホストのプロセスに %q キーが出ています (値: %v)。"+
				"「コンテナにいない」と「特権でない」は別の事実です", k, m[k])
		}
	}
}

// An ordinary container is reported as a container with the flags false, so
// container_id's presence is what says "contained" and the flags say only what
// kind. Without this the flags could be emitted only when true and a plain
// container would look like a host process.
func TestAnOrdinaryContainerIsStillReportedAsContained(t *testing.T) {
	const id = "aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990"
	evt := &v1.Event{
		Type: v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 100, ProcessName: "nginx", ContainerId: id,
		}},
	}

	var m map[string]interface{}
	if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
		t.Fatalf("normalizeEventData: %v", err)
	}
	if got, _ := m["container_id"].(string); got != id {
		t.Errorf("raw_data.container_id = %q", got)
	}
	for _, k := range []string{"privileged", "host_network"} {
		v, present := m[k]
		if !present {
			t.Errorf("通常のコンテナに %q キーがありません。"+
				"監視対象コンテナ数はこのキーの有無で数えます", k)
			continue
		}
		if b, _ := v.(bool); b {
			t.Errorf("通常のコンテナで %q が true になっています", k)
		}
	}
}
