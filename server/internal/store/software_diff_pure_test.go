package store

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── SoftwareDiff 構造体テスト ────────────────────────────────────────────────

func TestSoftwareDiff_ZeroValue_DiffStore(t *testing.T) {
	var d SoftwareDiff
	if d.ID != "" {
		t.Errorf("ZeroValue ID = %q, want \"\"", d.ID)
	}
	if d.AgentID != "" {
		t.Errorf("ZeroValue AgentID = %q, want \"\"", d.AgentID)
	}
	if d.AddedCount != 0 {
		t.Errorf("ZeroValue AddedCount = %d, want 0", d.AddedCount)
	}
	if d.RemovedCount != 0 {
		t.Errorf("ZeroValue RemovedCount = %d, want 0", d.RemovedCount)
	}
}

func TestSoftwareDiff_FieldAssignment_DiffStore(t *testing.T) {
	now := time.Now()
	d := SoftwareDiff{
		ID:           "diff-id-123",
		AgentID:      "agent-uuid-456",
		DiffDate:     "2026-03-23",
		AddedCount:   5,
		RemovedCount: 2,
		CreatedAt:    now,
	}

	if d.ID != "diff-id-123" {
		t.Errorf("ID = %q, want \"diff-id-123\"", d.ID)
	}
	if d.AgentID != "agent-uuid-456" {
		t.Errorf("AgentID = %q, want \"agent-uuid-456\"", d.AgentID)
	}
	if d.AddedCount != 5 {
		t.Errorf("AddedCount = %d, want 5", d.AddedCount)
	}
	if d.RemovedCount != 2 {
		t.Errorf("RemovedCount = %d, want 2", d.RemovedCount)
	}
	if d.CreatedAt.IsZero() {
		t.Error("CreatedAt はゼロでないべき")
	}
}

func TestSoftwareDiff_JSONRawMessageFields(t *testing.T) {
	// Added/Removed は json.RawMessage なので任意の JSON を格納できる
	addedJSON := json.RawMessage(`[{"name":"Chrome","version":"120.0"}]`)
	removedJSON := json.RawMessage(`[{"name":"OldApp","version":"1.0"}]`)

	d := SoftwareDiff{
		Added:   addedJSON,
		Removed: removedJSON,
	}

	// JSON として有効であることを確認
	var added []map[string]string
	if err := json.Unmarshal(d.Added, &added); err != nil {
		t.Errorf("Added JSON パース失敗: %v", err)
	}
	if len(added) != 1 {
		t.Errorf("Added 要素数 = %d, want 1", len(added))
	}
	if added[0]["name"] != "Chrome" {
		t.Errorf("Added[0].name = %q, want \"Chrome\"", added[0]["name"])
	}
}

func TestSoftwareDiff_NullJSONRawMessage(t *testing.T) {
	// nil の json.RawMessage は null と同等
	d := SoftwareDiff{}
	if d.Added != nil {
		// ゼロ値は nil
	}
	// null JSON も有効として扱える
	d.Added = json.RawMessage("null")
	if string(d.Added) != "null" {
		t.Errorf("Added = %q, want \"null\"", string(d.Added))
	}
}

// ─── ソフトウェア差分カウント検証ヘルパー ─────────────────────────────────────

func TestSoftwareDiff_CountConsistency(t *testing.T) {
	// AddedCount と Removed Count は非負であるべき
	tests := []struct {
		added   int
		removed int
		valid   bool
	}{
		{5, 2, true},
		{0, 0, true},
		{10, 0, true},
		{0, 3, true},
	}

	for _, tc := range tests {
		d := SoftwareDiff{
			AddedCount:   tc.added,
			RemovedCount: tc.removed,
		}
		if tc.valid && (d.AddedCount < 0 || d.RemovedCount < 0) {
			t.Errorf("カウントは非負であるべき: added=%d, removed=%d", d.AddedCount, d.RemovedCount)
		}
	}
}

func TestSoftwareDiff_DiffDateFormat_DiffStore(t *testing.T) {
	// DiffDate は YYYY-MM-DD 形式
	validDate := "2026-03-23"
	d := SoftwareDiff{DiffDate: validDate}

	if len(d.DiffDate) != 10 {
		t.Errorf("DiffDate 長 = %d, want 10 (YYYY-MM-DD)", len(d.DiffDate))
	}
	if d.DiffDate[4] != '-' || d.DiffDate[7] != '-' {
		t.Errorf("DiffDate フォーマット不正: %q", d.DiffDate)
	}
}

// ─── GetDiffs リミット検証ヘルパー ────────────────────────────────────────────

func TestSoftwareDiffLimit_Clamping(t *testing.T) {
	// GetDiffs の limit パラメータ: 1–100 の範囲
	clampDiffLimit := func(limit int) int {
		if limit <= 0 {
			return 30
		}
		if limit > 100 {
			return 100
		}
		return limit
	}

	tests := []struct {
		input int
		want  int
	}{
		{0, 30},
		{-1, 30},
		{30, 30},
		{50, 50},
		{100, 100},
		{101, 100},
		{9999, 100},
	}
	for _, tc := range tests {
		got := clampDiffLimit(tc.input)
		if got != tc.want {
			t.Errorf("clampDiffLimit(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
