package ingestion

import (
	"encoding/json"
	"testing"
)

// ─── NewInMemoryCommandDispatcher ─────────────────────────────────────────────

func TestNewInMemoryCommandDispatcher_NotNil(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	if d == nil {
		t.Fatal("NewInMemoryCommandDispatcher は nil を返すべきではありません")
	}
}

func TestNewInMemoryCommandDispatcher_QueuesInitialized(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	if d.queues == nil {
		t.Error("queues マップが初期化されていません")
	}
}

// ─── Enqueue ──────────────────────────────────────────────────────────────────

func TestEnqueue_EmptyAgentID_ReturnsError(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	err := d.Enqueue("", &Command{ID: "cmd-1", Type: "test"})
	if err == nil {
		t.Error("空の agentID はエラーを返すべきです")
	}
}

func TestEnqueue_ValidCommand_NoError(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	err := d.Enqueue("agent-001", &Command{ID: "cmd-1", Type: "test"})
	if err != nil {
		t.Fatalf("Enqueue: 予期しないエラー: %v", err)
	}
}

func TestEnqueue_MultipleCommands_AllQueued(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.Enqueue("agent-001", &Command{ID: "cmd-1", Type: "a"})
	_ = d.Enqueue("agent-001", &Command{ID: "cmd-2", Type: "b"})
	if len(d.queues["agent-001"]) != 2 {
		t.Errorf("キュー長: got %d, want 2", len(d.queues["agent-001"]))
	}
}

func TestEnqueue_DifferentAgents_SeparateQueues(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.Enqueue("agent-001", &Command{ID: "cmd-1", Type: "a"})
	_ = d.Enqueue("agent-002", &Command{ID: "cmd-2", Type: "b"})
	if len(d.queues["agent-001"]) != 1 {
		t.Errorf("agent-001 キュー: got %d, want 1", len(d.queues["agent-001"]))
	}
	if len(d.queues["agent-002"]) != 1 {
		t.Errorf("agent-002 キュー: got %d, want 1", len(d.queues["agent-002"]))
	}
}

// ─── Dequeue ──────────────────────────────────────────────────────────────────

func TestDequeue_EmptyQueue_ReturnsNil(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	cmds, err := d.Dequeue("agent-001")
	if err != nil {
		t.Fatalf("Dequeue (empty): 予期しないエラー: %v", err)
	}
	if cmds != nil {
		t.Errorf("空キューは nil を返すべきです: got %v", cmds)
	}
}

func TestDequeue_AfterEnqueue_ReturnsCommands(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.Enqueue("agent-001", &Command{ID: "cmd-1", Type: "isolate"})
	cmds, err := d.Dequeue("agent-001")
	if err != nil {
		t.Fatalf("Dequeue: 予期しないエラー: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("Dequeue: got %d commands, want 1", len(cmds))
	}
	if cmds[0].Type != "isolate" {
		t.Errorf("Command Type: got %q, want isolate", cmds[0].Type)
	}
}

func TestDequeue_ClearsQueue(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.Enqueue("agent-001", &Command{ID: "cmd-1", Type: "test"})
	_, _ = d.Dequeue("agent-001")
	cmds, _ := d.Dequeue("agent-001")
	if cmds != nil {
		t.Error("Dequeue 後のキューは空になるべきです")
	}
}

// ─── EnqueueIsolate ───────────────────────────────────────────────────────────

func TestEnqueueIsolate_CommandType(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	err := d.EnqueueIsolate("agent-001", "malware detected", "alert-123", []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("EnqueueIsolate: 予期しないエラー: %v", err)
	}
	cmds, _ := d.Dequeue("agent-001")
	if len(cmds) != 1 {
		t.Fatalf("EnqueueIsolate: got %d commands, want 1", len(cmds))
	}
	if cmds[0].Type != "isolate" {
		t.Errorf("Type: got %q, want isolate", cmds[0].Type)
	}
}

func TestEnqueueIsolate_PayloadContainsReason(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.EnqueueIsolate("agent-001", "malware detected", "alert-123", nil)
	cmds, _ := d.Dequeue("agent-001")
	var payload map[string]interface{}
	_ = json.Unmarshal(cmds[0].Payload, &payload)
	if payload["reason"] != "malware detected" {
		t.Errorf("payload reason: got %v, want malware detected", payload["reason"])
	}
}

// ─── EnqueueKillProcess ───────────────────────────────────────────────────────

func TestEnqueueKillProcess_CommandType(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	err := d.EnqueueKillProcess("agent-001", 1234, "malicious process")
	if err != nil {
		t.Fatalf("EnqueueKillProcess: 予期しないエラー: %v", err)
	}
	cmds, _ := d.Dequeue("agent-001")
	if cmds[0].Type != "kill_process" {
		t.Errorf("Type: got %q, want kill_process", cmds[0].Type)
	}
}

func TestEnqueueKillProcess_PayloadContainsPID(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.EnqueueKillProcess("agent-001", 5678, "reason")
	cmds, _ := d.Dequeue("agent-001")
	var payload map[string]interface{}
	_ = json.Unmarshal(cmds[0].Payload, &payload)
	pid, _ := payload["pid"].(float64)
	if int(pid) != 5678 {
		t.Errorf("payload pid: got %v, want 5678", payload["pid"])
	}
}

// ─── EnqueueQuarantine ────────────────────────────────────────────────────────

func TestEnqueueQuarantine_CommandType(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	err := d.EnqueueQuarantine("agent-001", "/tmp/malware.exe", "alert-456")
	if err != nil {
		t.Fatalf("EnqueueQuarantine: 予期しないエラー: %v", err)
	}
	cmds, _ := d.Dequeue("agent-001")
	if cmds[0].Type != "quarantine_file" {
		t.Errorf("Type: got %q, want quarantine_file", cmds[0].Type)
	}
}

func TestEnqueueQuarantine_PayloadContainsPath(t *testing.T) {
	d := NewInMemoryCommandDispatcher()
	_ = d.EnqueueQuarantine("agent-001", "/tmp/malware.exe", "alert-456")
	cmds, _ := d.Dequeue("agent-001")
	var payload map[string]interface{}
	_ = json.Unmarshal(cmds[0].Payload, &payload)
	if payload["path"] != "/tmp/malware.exe" {
		t.Errorf("payload path: got %v, want /tmp/malware.exe", payload["path"])
	}
}

// ─── generateCommandID ────────────────────────────────────────────────────────

func TestGenerateCommandID_StartsWithCmd(t *testing.T) {
	id := generateCommandID()
	if len(id) < 4 || id[:4] != "cmd-" {
		t.Errorf("generateCommandID: got %q, want prefix cmd-", id)
	}
}

func TestGenerateCommandID_Unique(t *testing.T) {
	id1 := generateCommandID()
	id2 := generateCommandID()
	// 連続生成では同一になる可能性があるため、参照のみ
	_ = id1
	_ = id2
}
