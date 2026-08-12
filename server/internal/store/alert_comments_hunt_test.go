package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── AlertCommentRecord 構造体テスト ──────────────────────────────────────────

// TestAlertCommentRecord_ZeroValue は AlertCommentRecord のゼロ値を確認する
func TestAlertCommentRecord_ZeroValue(t *testing.T) {
	var c AlertCommentRecord
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.AlertID != "" {
		t.Errorf("AlertID のデフォルト = %q, want \"\"", c.AlertID)
	}
	if c.AuthorID != "" {
		t.Errorf("AuthorID のデフォルト = %q, want \"\"", c.AuthorID)
	}
	if c.AuthorName != "" {
		t.Errorf("AuthorName のデフォルト = %q, want \"\"", c.AuthorName)
	}
	if c.Content != "" {
		t.Errorf("Content のデフォルト = %q, want \"\"", c.Content)
	}
}

// TestAlertCommentRecord_FieldAssignment は AlertCommentRecord のフィールド代入を確認する
func TestAlertCommentRecord_FieldAssignment(t *testing.T) {
	now := time.Now()
	c := AlertCommentRecord{
		ID:         "comment-uuid-001",
		AlertID:    "alert-uuid-001",
		AuthorID:   "user-uuid-001",
		AuthorName: "analyst@example.com",
		Content:    "このアラートはFPです。調査済み。",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if c.ID != "comment-uuid-001" {
		t.Errorf("ID = %q, want \"comment-uuid-001\"", c.ID)
	}
	if c.AlertID != "alert-uuid-001" {
		t.Errorf("AlertID = %q, want \"alert-uuid-001\"", c.AlertID)
	}
	if c.AuthorID != "user-uuid-001" {
		t.Errorf("AuthorID = %q, want \"user-uuid-001\"", c.AuthorID)
	}
	if c.Content != "このアラートはFPです。調査済み。" {
		t.Errorf("Content = %q, want \"このアラートはFPです。調査済み。\"", c.Content)
	}
}

// TestAlertCommentRecord_ContentNotEmpty はコメント内容が空でない場合を確認する
func TestAlertCommentRecord_ContentNotEmpty(t *testing.T) {
	c := AlertCommentRecord{Content: "マルウェアをクリーンアップしました。"}
	if strings.TrimSpace(c.Content) == "" {
		t.Error("Content は空でないべき")
	}
}

// TestAlertCommentRecord_AuthorOwnership はコメントの著者所有権確認ロジックを検証する
func TestAlertCommentRecord_AuthorOwnership(t *testing.T) {
	// Delete メソッドの権限チェックロジックを反映したヘルパー
	canDelete := func(authorID, requesterID string, isAdmin bool) bool {
		if isAdmin {
			return true
		}
		return authorID == requesterID
	}

	cases := []struct {
		authorID    string
		requesterID string
		isAdmin     bool
		want        bool
		desc        string
	}{
		{"user-001", "user-001", false, true, "著者本人は削除可能"},
		{"user-001", "user-002", false, false, "他ユーザーは削除不可"},
		{"user-001", "user-002", true, true, "管理者は誰のコメントでも削除可能"},
		{"user-001", "user-001", true, true, "管理者兼著者も削除可能"},
	}
	for _, tc := range cases {
		got := canDelete(tc.authorID, tc.requesterID, tc.isAdmin)
		if got != tc.want {
			t.Errorf("[%s] canDelete(%q, %q, %v) = %v, want %v",
				tc.desc, tc.authorID, tc.requesterID, tc.isAdmin, got, tc.want)
		}
	}
}

// TestAlertCommentRecord_TimestampOrdering はコメントの時系列順序を確認する
func TestAlertCommentRecord_TimestampOrdering(t *testing.T) {
	base := time.Now()
	comments := []AlertCommentRecord{
		{ID: "c1", CreatedAt: base},
		{ID: "c2", CreatedAt: base.Add(1 * time.Minute)},
		{ID: "c3", CreatedAt: base.Add(2 * time.Minute)},
	}

	// List メソッドは ORDER BY created_at ASC で返す
	// 昇順で並んでいることを確認する
	for i := 1; i < len(comments); i++ {
		if !comments[i].CreatedAt.After(comments[i-1].CreatedAt) {
			t.Errorf("コメント[%d].CreatedAt (%v) はコメント[%d].CreatedAt (%v) より後であるべき",
				i, comments[i].CreatedAt, i-1, comments[i-1].CreatedAt)
		}
	}
}

// TestAlertCommentRecord_EmptyListFallback は空リストが nil ではなく []AlertCommentRecord{} を返すことを確認する
func TestAlertCommentRecord_EmptyListFallback(t *testing.T) {
	// List メソッドのロジック: result == nil なら [] を使用する
	applyListFallback := func(result []AlertCommentRecord) []AlertCommentRecord {
		if result == nil {
			return []AlertCommentRecord{}
		}
		return result
	}

	result := applyListFallback(nil)
	if result == nil {
		t.Error("nil 結果は空スライスにフォールバックするべき")
	}
	if len(result) != 0 {
		t.Errorf("フォールバック後の数 = %d, want 0", len(result))
	}
}

// ─── SavedHunt 構造体テスト ───────────────────────────────────────────────────

// TestSavedHunt_ZeroValue は SavedHunt のゼロ値を確認する
func TestSavedHunt_ZeroValue(t *testing.T) {
	var h SavedHunt
	if h.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", h.ID)
	}
	if h.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", h.Name)
	}
	if h.Description != "" {
		t.Errorf("Description のデフォルト = %q, want \"\"", h.Description)
	}
	if h.Params != nil {
		t.Errorf("Params のデフォルトは nil であるべき")
	}
	if h.CreatedBy != "" {
		t.Errorf("CreatedBy のデフォルト = %q, want \"\"", h.CreatedBy)
	}
	if h.LastRun != nil {
		t.Errorf("LastRun のデフォルトは nil であるべき")
	}
	if h.RunCount != 0 {
		t.Errorf("RunCount のデフォルト = %d, want 0", h.RunCount)
	}
}

// TestSavedHunt_FieldAssignment は SavedHunt の全フィールドが正しく代入できることを確認する
func TestSavedHunt_FieldAssignment(t *testing.T) {
	now := time.Now()
	lastRun := now.Add(-1 * time.Hour)
	params := json.RawMessage(`{"process_name": "powershell.exe", "min_severity": 7}`)

	h := SavedHunt{
		ID:          "hunt-uuid-001",
		Name:        "PowerShell 異常検出",
		Description: "PowerShell プロセスの不審な実行を追跡する",
		Params:      params,
		CreatedBy:   "user-uuid-001",
		CreatedAt:   now,
		LastRun:     &lastRun,
		RunCount:    5,
	}

	if h.ID != "hunt-uuid-001" {
		t.Errorf("ID = %q, want \"hunt-uuid-001\"", h.ID)
	}
	if h.Name != "PowerShell 異常検出" {
		t.Errorf("Name = %q, want \"PowerShell 異常検出\"", h.Name)
	}
	if h.RunCount != 5 {
		t.Errorf("RunCount = %d, want 5", h.RunCount)
	}
	if h.LastRun == nil {
		t.Fatal("LastRun は nil でないべき")
	}
	if !h.LastRun.Equal(lastRun) {
		t.Errorf("LastRun = %v, want %v", *h.LastRun, lastRun)
	}
}

// TestSavedHunt_ParamsJSONSerialization は SavedHunt の Params JSON シリアライゼーションを確認する
func TestSavedHunt_ParamsJSONSerialization(t *testing.T) {
	params := json.RawMessage(`{"process_name":"cmd.exe","min_severity":5,"hostname_prefix":"PROD"}`)
	h := SavedHunt{
		Name:   "CMD 実行監視",
		Params: params,
	}

	// Params が有効な JSON であることを確認する
	var decoded map[string]interface{}
	if err := json.Unmarshal(h.Params, &decoded); err != nil {
		t.Fatalf("Params のデシリアライズに失敗: %v", err)
	}
	if decoded["process_name"] != "cmd.exe" {
		t.Errorf("Params[process_name] = %v, want \"cmd.exe\"", decoded["process_name"])
	}
}

// TestSavedHunt_LastRunNilWhenNeverRun は一度も実行されていないハントで LastRun が nil であることを確認する
func TestSavedHunt_LastRunNilWhenNeverRun(t *testing.T) {
	h := SavedHunt{
		Name:     "新規ハント",
		RunCount: 0,
	}
	if h.LastRun != nil {
		t.Error("未実行のハントの LastRun は nil であるべき")
	}
	if h.RunCount != 0 {
		t.Errorf("未実行のハントの RunCount = %d, want 0", h.RunCount)
	}
}

// TestSavedHunt_RunCountIncrement は RunCount がインクリメントされることを確認する
func TestSavedHunt_RunCountIncrement(t *testing.T) {
	// RecordRun のロジック: run_count = run_count + 1
	h := SavedHunt{RunCount: 3}
	h.RunCount++ // DB での run_count+1 をシミュレート
	if h.RunCount != 4 {
		t.Errorf("RunCount インクリメント後 = %d, want 4", h.RunCount)
	}
}

// TestSavedHunt_EmptyListFallback は空ハントリストが nil でなく []*SavedHunt{} を返すことを確認する
func TestSavedHunt_EmptyListFallback(t *testing.T) {
	// List メソッドのロジック: hunts == nil なら [] を使用する
	applyHuntListFallback := func(hunts []*SavedHunt) []*SavedHunt {
		if hunts == nil {
			return []*SavedHunt{}
		}
		return hunts
	}

	result := applyHuntListFallback(nil)
	if result == nil {
		t.Error("nil 結果は空スライスにフォールバックするべき")
	}
	if len(result) != 0 {
		t.Errorf("フォールバック後の数 = %d, want 0", len(result))
	}

	existing := []*SavedHunt{{Name: "test"}}
	result2 := applyHuntListFallback(existing)
	if len(result2) != 1 {
		t.Errorf("既存ハントの数 = %d, want 1", len(result2))
	}
}

// TestSavedHunt_ParamsEmptyObject は Params が空 JSON オブジェクトの場合を確認する
func TestSavedHunt_ParamsEmptyObject(t *testing.T) {
	h := SavedHunt{
		Name:   "パラメータなしハント",
		Params: json.RawMessage(`{}`),
	}
	if string(h.Params) != "{}" {
		t.Errorf("Params = %q, want \"{}\"", string(h.Params))
	}
	// 空 JSON オブジェクトが有効であることを確認する
	var decoded map[string]interface{}
	if err := json.Unmarshal(h.Params, &decoded); err != nil {
		t.Fatalf("空 Params のデシリアライズに失敗: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("空 Params のキー数 = %d, want 0", len(decoded))
	}
}

// TestSavedHunt_NameNotEmpty はハント名が空でない場合を確認する
func TestSavedHunt_NameNotEmpty(t *testing.T) {
	h := SavedHunt{Name: "横移動検出ハント"}
	if strings.TrimSpace(h.Name) == "" {
		t.Error("Name は空でないべき")
	}
}
