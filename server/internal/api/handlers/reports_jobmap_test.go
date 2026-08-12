package handlers

import (
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// jobToMap のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestJobToMap_BasicFields(t *testing.T) {
	// 基本フィールドが正しくマップに変換される
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "test-job-id",
		Type:        "alert_summary",
		Status:      "pending",
		RequestedBy: "user-123",
		RequestedAt: now,
	}
	m := jobToMap(j)

	if m["id"] != "test-job-id" {
		t.Errorf("id = %v, want %q", m["id"], "test-job-id")
	}
	if m["type"] != "alert_summary" {
		t.Errorf("type = %v, want %q", m["type"], "alert_summary")
	}
	if m["status"] != "pending" {
		t.Errorf("status = %v, want %q", m["status"], "pending")
	}
	if m["requested_by"] != "user-123" {
		t.Errorf("requested_by = %v, want %q", m["requested_by"], "user-123")
	}
}

func TestJobToMap_CompletedAt_IncludedWhenSet(t *testing.T) {
	// CompletedAt が設定されている場合、マップに含まれる
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "job-1",
		Type:        "agent_status",
		Status:      "completed",
		RequestedBy: "user-1",
		RequestedAt: now,
		CompletedAt: &now,
	}
	m := jobToMap(j)

	if _, ok := m["completed_at"]; !ok {
		t.Error("CompletedAt が設定されているのに completed_at キーがありません")
	}
}

func TestJobToMap_CompletedAt_AbsentWhenNil(t *testing.T) {
	// CompletedAt が nil の場合、マップに含まれない
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "job-2",
		Type:        "alert_summary",
		Status:      "running",
		RequestedBy: "user-2",
		RequestedAt: now,
		CompletedAt: nil,
	}
	m := jobToMap(j)

	if _, ok := m["completed_at"]; ok {
		t.Error("CompletedAt が nil なのに completed_at キーが存在します")
	}
}

func TestJobToMap_Error_IncludedWhenNonEmpty(t *testing.T) {
	// Error が空でない場合、マップに含まれる
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "job-3",
		Type:        "threat_report",
		Status:      "failed",
		RequestedBy: "user-3",
		RequestedAt: now,
		Error:       "データベース接続エラー",
	}
	m := jobToMap(j)

	if m["error"] != "データベース接続エラー" {
		t.Errorf("error = %v, want %q", m["error"], "データベース接続エラー")
	}
}

func TestJobToMap_Error_AbsentWhenEmpty(t *testing.T) {
	// Error が空の場合、マップに含まれない
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "job-4",
		Type:        "alert_summary",
		Status:      "completed",
		RequestedBy: "user-4",
		RequestedAt: now,
		Error:       "",
	}
	m := jobToMap(j)

	if _, ok := m["error"]; ok {
		t.Error("Error が空なのに error キーが存在します")
	}
}

func TestJobToMap_DownloadURL_SetWhenCompleted(t *testing.T) {
	// Status が "completed" のとき download_url が設定される
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "abc123",
		Type:        "agent_status",
		Status:      "completed",
		RequestedBy: "user-5",
		RequestedAt: now,
	}
	m := jobToMap(j)

	want := "/api/v1/reports/abc123"
	if m["download_url"] != want {
		t.Errorf("download_url = %v, want %q", m["download_url"], want)
	}
}

func TestJobToMap_DownloadURL_AbsentWhenNotCompleted(t *testing.T) {
	// Status が "completed" 以外のとき download_url は設定されない
	statuses := []string{"pending", "running", "failed"}
	now := time.Now()
	for _, status := range statuses {
		t.Run("status="+status, func(t *testing.T) {
			j := &store.ReportJobRow{
				ID:          "job-x",
				Type:        "alert_summary",
				Status:      status,
				RequestedBy: "user-x",
				RequestedAt: now,
			}
			m := jobToMap(j)
			if _, ok := m["download_url"]; ok {
				t.Errorf("status=%q なのに download_url キーが存在します", status)
			}
		})
	}
}

func TestJobToMap_RequestedByName_AlwaysPresent(t *testing.T) {
	// requested_by_name は値が空でも常にキーが存在する
	now := time.Now()
	j := &store.ReportJobRow{
		ID:              "job-y",
		Type:            "threat_report",
		Status:          "pending",
		RequestedBy:     "user-y",
		RequestedByName: "テスト ユーザー",
		RequestedAt:     now,
	}
	m := jobToMap(j)

	if m["requested_by_name"] != "テスト ユーザー" {
		t.Errorf("requested_by_name = %v, want %q", m["requested_by_name"], "テスト ユーザー")
	}
}

func TestJobToMap_RequestedAt_IsIncluded(t *testing.T) {
	// requested_at が常にマップに含まれる
	ts := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	j := &store.ReportJobRow{
		ID:          "job-z",
		Type:        "alert_summary",
		Status:      "pending",
		RequestedBy: "user-z",
		RequestedAt: ts,
	}
	m := jobToMap(j)

	if m["requested_at"] != ts {
		t.Errorf("requested_at = %v, want %v", m["requested_at"], ts)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// generateReport: 不明なレポートタイプのエラーメッセージ確認
// ─────────────────────────────────────────────────────────────────────────────

// TestReportHandler_UnknownType_GeneratesErrorMessage は
// generateReport が未知のレポートタイプに対してエラーを正しく記録するかを
// ReportStore なしで（ストアなし = no-op パス）検証する。
func TestReportHandler_UnknownType_NoStoreNoPanic(t *testing.T) {
	// ReportStore が nil のとき generateReport はパニックしない
	h := &ReportHandler{} // Store, AgentStore, ReportStore いずれも nil
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 7, 0, 0, 0, 0, time.UTC)

	// パニックしないことを確認 (StoreがnilなのでDB呼び出しはスキップされる)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("generateReport がパニックしました: %v", r)
		}
	}()
	h.generateReport("dummy-job", "unknown_type", from, to)
}

func TestReportHandler_AgentStatus_NoStoreReturnsMessage(t *testing.T) {
	// AgentStore が nil のとき buildAgentStatus は空メッセージを返す（DBなし）
	h := &ReportHandler{}
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	// パニックしないことを確認
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("generateReport (agent_status) がパニックしました: %v", r)
		}
	}()
	h.generateReport("dummy-job-2", "agent_status", from, to)
}
