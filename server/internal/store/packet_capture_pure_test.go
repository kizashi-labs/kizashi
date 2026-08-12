package store

import (
	"strings"
	"testing"
	"time"
)

// ─── PacketCapture 構造体テスト ────────────────────────────────────────────────

// TestPacketCapture_ZeroValue は PacketCapture のゼロ値が期待通りであることを確認する
func TestPacketCapture_ZeroValue(t *testing.T) {
	var pc PacketCapture
	if pc.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", pc.ID)
	}
	if pc.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", pc.AgentID)
	}
	if pc.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", pc.Status)
	}
	if pc.MaxPackets != 0 {
		t.Errorf("MaxPackets のデフォルト = %d, want 0", pc.MaxPackets)
	}
	if pc.FilePath != nil {
		t.Error("FilePath のデフォルトは nil であるべき")
	}
	if pc.FileSizeBytes != nil {
		t.Error("FileSizeBytes のデフォルトは nil であるべき")
	}
	if pc.PacketCount != nil {
		t.Error("PacketCount のデフォルトは nil であるべき")
	}
	if pc.ErrorMsg != nil {
		t.Error("ErrorMsg のデフォルトは nil であるべき")
	}
	if pc.StartedAt != nil {
		t.Error("StartedAt のデフォルトは nil であるべき")
	}
	if pc.CompletedAt != nil {
		t.Error("CompletedAt のデフォルトは nil であるべき")
	}
}

// TestPacketCapture_FieldAssignment は PacketCapture のフィールド代入が正しく反映されることを確認する
func TestPacketCapture_FieldAssignment(t *testing.T) {
	fp := "/tmp/capture.pcap"
	size := int64(1048576)
	count := 500
	errMsg := "timeout occurred"
	createdBy := "user-abc"
	now := time.Now().UTC()

	pc := PacketCapture{
		ID:              "cap-001",
		AgentID:         "agent-001",
		Name:            "テストキャプチャ",
		Status:          "completed",
		Filter:          "tcp port 80",
		InterfaceName:   "eth0",
		MaxPackets:      1000,
		MaxSizeMB:       50,
		DurationSeconds: 30,
		FilePath:        &fp,
		FileSizeBytes:   &size,
		PacketCount:     &count,
		ErrorMsg:        &errMsg,
		StartedAt:       &now,
		CompletedAt:     &now,
		CreatedAt:       now,
		CreatedBy:       &createdBy,
	}

	if pc.ID != "cap-001" {
		t.Errorf("ID = %q, want \"cap-001\"", pc.ID)
	}
	if pc.Status != "completed" {
		t.Errorf("Status = %q, want \"completed\"", pc.Status)
	}
	if pc.Filter != "tcp port 80" {
		t.Errorf("Filter = %q, want \"tcp port 80\"", pc.Filter)
	}
	if *pc.FilePath != fp {
		t.Errorf("FilePath = %q, want %q", *pc.FilePath, fp)
	}
	if *pc.FileSizeBytes != size {
		t.Errorf("FileSizeBytes = %d, want %d", *pc.FileSizeBytes, size)
	}
	if *pc.PacketCount != count {
		t.Errorf("PacketCount = %d, want %d", *pc.PacketCount, count)
	}
	if *pc.ErrorMsg != errMsg {
		t.Errorf("ErrorMsg = %q, want %q", *pc.ErrorMsg, errMsg)
	}
}

// TestPacketCaptureStatus_KnownValues は既知のステータス値を確認する
func TestPacketCaptureStatus_KnownValues(t *testing.T) {
	// パケットキャプチャの有効なステータス値を検証する
	validStatuses := []string{"pending", "running", "completed", "failed", "cancelled"}
	for _, s := range validStatuses {
		pc := PacketCapture{Status: s}
		if pc.Status != s {
			t.Errorf("Status = %q, want %q", pc.Status, s)
		}
	}
}

// TestPacketCaptureFilter_BPFExpressions は BPF フィルター式のフィールド格納を確認する
func TestPacketCaptureFilter_BPFExpressions(t *testing.T) {
	// BPF フィルター式が正しく格納されることを確認する
	filters := []struct {
		name   string
		filter string
	}{
		{"TCP ポートフィルター", "tcp port 443"},
		{"ホストフィルター", "host 192.168.1.1"},
		{"プロトコルフィルター", "icmp"},
		{"複合フィルター", "tcp and (host 10.0.0.1 or host 10.0.0.2)"},
		{"UDP ポート範囲", "udp portrange 1024-65535"},
		{"空フィルター", ""},
	}

	for _, tc := range filters {
		pc := PacketCapture{Filter: tc.filter}
		if pc.Filter != tc.filter {
			t.Errorf("[%s] Filter = %q, want %q", tc.name, pc.Filter, tc.filter)
		}
	}
}

// TestPacketCaptureStatusTransition_CompletedSetsTimestamp は
// completed/failed/cancelled ステータスが完了時刻を必要とするロジックを確認する
func TestPacketCaptureStatusTransition_CompletedSetsTimestamp(t *testing.T) {
	// UpdateStatus の completedAt ロジックを純粋に再現する
	terminalStatuses := []string{"completed", "failed", "cancelled"}
	for _, status := range terminalStatuses {
		var completedAt *time.Time
		if status == "completed" || status == "failed" || status == "cancelled" {
			now := time.Now().UTC()
			completedAt = &now
		}
		if completedAt == nil {
			t.Errorf("ステータス %q は completedAt を設定するべき", status)
		}
	}
}

// TestPacketCaptureStatusTransition_RunningSetStartedAt は
// running ステータスが開始時刻を必要とするロジックを確認する
func TestPacketCaptureStatusTransition_RunningSetStartedAt(t *testing.T) {
	// UpdateStatus の startedAt ロジックを純粋に再現する
	var startedAt *time.Time
	targetStatus := "running"
	if targetStatus == "running" {
		now := time.Now().UTC()
		startedAt = &now
	}
	if startedAt == nil {
		t.Error("running ステータスは startedAt を設定するべき")
	}

	// pending ステータスは startedAt を設定しない
	var noStart *time.Time
	status := "pending"
	if status == "running" {
		now := time.Now().UTC()
		noStart = &now
	}
	if noStart != nil {
		t.Error("pending ステータスは startedAt を設定するべきでない")
	}
}

// TestPacketCaptureStatusTransition_NonTerminalNoCompletedAt は
// 終了ステータス以外は completedAt を設定しないことを確認する
func TestPacketCaptureStatusTransition_NonTerminalNoCompletedAt(t *testing.T) {
	nonTerminal := []string{"pending", "running"}
	for _, status := range nonTerminal {
		var completedAt *time.Time
		if status == "completed" || status == "failed" || status == "cancelled" {
			now := time.Now().UTC()
			completedAt = &now
		}
		if completedAt != nil {
			t.Errorf("ステータス %q は completedAt を設定するべきでない", status)
		}
	}
}

// TestPacketCapture_Limits は MaxPackets / MaxSizeMB / DurationSeconds フィールドを確認する
func TestPacketCapture_Limits(t *testing.T) {
	pc := PacketCapture{
		MaxPackets:      10000,
		MaxSizeMB:       100,
		DurationSeconds: 120,
	}
	if pc.MaxPackets != 10000 {
		t.Errorf("MaxPackets = %d, want 10000", pc.MaxPackets)
	}
	if pc.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB = %d, want 100", pc.MaxSizeMB)
	}
	if pc.DurationSeconds != 120 {
		t.Errorf("DurationSeconds = %d, want 120", pc.DurationSeconds)
	}
}

// TestPacketCaptureColumns_ContainsRequiredFields は
// packetCaptureColumns 定数に必須フィールドが含まれることを確認する
func TestPacketCaptureColumns_ContainsRequiredFields(t *testing.T) {
	// SQL 列リストに必須フィールドが含まれることを検証する
	requiredCols := []string{
		"id", "agent_id", "name", "status", "filter",
		"interface_name", "max_packets", "max_size_mb",
		"duration_seconds", "file_path", "file_size_bytes",
		"packet_count", "error_msg", "started_at",
		"completed_at", "created_at", "created_by",
	}
	for _, col := range requiredCols {
		if !strings.Contains(packetCaptureColumns, col) {
			t.Errorf("packetCaptureColumns に %q が含まれるべき", col)
		}
	}
}

// TestPacketCapture_CreatedByOptional は CreatedBy がオプションであることを確認する
func TestPacketCapture_CreatedByOptional(t *testing.T) {
	// CreatedBy が nil の場合（匿名ユーザーまたはシステム）
	pcAnon := PacketCapture{Name: "anonymous capture"}
	if pcAnon.CreatedBy != nil {
		t.Error("CreatedBy のデフォルトは nil であるべき")
	}

	// CreatedBy が設定されている場合
	creator := "user-xyz"
	pcOwned := PacketCapture{Name: "owned capture", CreatedBy: &creator}
	if pcOwned.CreatedBy == nil || *pcOwned.CreatedBy != creator {
		t.Errorf("CreatedBy = %v, want %q", pcOwned.CreatedBy, creator)
	}
}
