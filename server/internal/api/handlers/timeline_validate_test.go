package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────
// timeline limit/offset クランプのテスト
// ─────────────────────────────────────────────

// clampTimelineLimit は timeline_handler.go の GetTimeline が行う
// limit の正規化ロジックを純粋関数として抽出したもの。
func clampTimelineLimit(raw int) int {
	if raw <= 0 || raw > 1000 {
		return 100
	}
	return raw
}

// clampTimelineOffset は timeline_handler.go の GetTimeline が行う
// offset の正規化ロジックを純粋関数として抽出したもの。
func clampTimelineOffset(raw int) int {
	if raw < 0 {
		return 0
	}
	return raw
}

func TestClampTimelineLimit_ValidValues(t *testing.T) {
	// 有効な範囲 (1〜1000) の limit はそのまま返されることを確認
	cases := []int{1, 50, 100, 500, 999, 1000}
	for _, v := range cases {
		t.Run(fmt.Sprintf("limit=%d", v), func(t *testing.T) {
			got := clampTimelineLimit(v)
			if got != v {
				t.Errorf("clampTimelineLimit(%d) = %d, want %d", v, got, v)
			}
		})
	}
}

func TestClampTimelineLimit_InvalidValues_DefaultToHundred(t *testing.T) {
	// 無効な limit 値 (0以下 または 1000超) はデフォルト値 100 に戻ることを確認
	cases := []int{0, -1, -100, 1001, 9999}
	for _, v := range cases {
		t.Run(fmt.Sprintf("limit=%d", v), func(t *testing.T) {
			got := clampTimelineLimit(v)
			if got != 100 {
				t.Errorf("clampTimelineLimit(%d) = %d, want 100 (デフォルト)", v, got)
			}
		})
	}
}

func TestClampTimelineOffset_NonNegativePreserved(t *testing.T) {
	// 0 以上の offset はそのまま返されることを確認
	cases := []int{0, 1, 50, 200, 10000}
	for _, v := range cases {
		t.Run(fmt.Sprintf("offset=%d", v), func(t *testing.T) {
			got := clampTimelineOffset(v)
			if got != v {
				t.Errorf("clampTimelineOffset(%d) = %d, want %d", v, got, v)
			}
		})
	}
}

func TestClampTimelineOffset_NegativeValues_DefaultToZero(t *testing.T) {
	// 負の offset はゼロにクランプされることを確認
	cases := []int{-1, -50, -1000}
	for _, v := range cases {
		t.Run(fmt.Sprintf("offset=%d", v), func(t *testing.T) {
			got := clampTimelineOffset(v)
			if got != 0 {
				t.Errorf("clampTimelineOffset(%d) = %d, want 0", v, got)
			}
		})
	}
}

// ─────────────────────────────────────────────
// TimelineEvent.Link 生成ロジックのテスト
// ─────────────────────────────────────────────

// buildTimelineLink は timeline_handler.go の GetTimeline 内で行う
// イベントタイプ別リンク生成ロジックを純粋関数として抽出したもの。
func buildTimelineLink(eventType, eventID string) string {
	switch eventType {
	case "alert":
		return fmt.Sprintf("/alerts/%s", eventID)
	case "audit":
		return fmt.Sprintf("/audit/%s", eventID)
	default:
		return ""
	}
}

func TestBuildTimelineLink_AlertType(t *testing.T) {
	// タイプが "alert" のイベントは /alerts/:id の形式でリンクが生成される
	id := "alert-uuid-123"
	got := buildTimelineLink("alert", id)
	want := "/alerts/alert-uuid-123"
	if got != want {
		t.Errorf("buildTimelineLink(\"alert\", %q) = %q, want %q", id, got, want)
	}
}

func TestBuildTimelineLink_AuditType(t *testing.T) {
	// タイプが "audit" のイベントは /audit/:id の形式でリンクが生成される
	id := "audit-uuid-456"
	got := buildTimelineLink("audit", id)
	want := "/audit/audit-uuid-456"
	if got != want {
		t.Errorf("buildTimelineLink(\"audit\", %q) = %q, want %q", id, got, want)
	}
}

func TestBuildTimelineLink_UnknownType_ReturnsEmpty(t *testing.T) {
	// 未知のタイプは空文字列を返すことを確認
	for _, eventType := range []string{"unknown", "log", "network", ""} {
		t.Run(eventType, func(t *testing.T) {
			got := buildTimelineLink(eventType, "some-id")
			if got != "" {
				t.Errorf("buildTimelineLink(%q, \"some-id\") = %q, want \"\"", eventType, got)
			}
		})
	}
}

func TestBuildTimelineLink_IDIncludedInPath(t *testing.T) {
	// 生成されたリンクにIDが含まれることを確認
	id := "specific-event-id"
	for _, eventType := range []string{"alert", "audit"} {
		got := buildTimelineLink(eventType, id)
		if !strings.Contains(got, id) {
			t.Errorf("buildTimelineLink(%q, %q): IDがリンクに含まれていません: %q", eventType, id, got)
		}
	}
}

// ─────────────────────────────────────────────
// タイムフィルタ文字列のパースバリデーションテスト
// ─────────────────────────────────────────────

// parseTimelineTimeFilter は RFC3339 形式の時刻文字列を解析して有効かどうかを返す。
// timeline_handler.go の GetTimeline 内のタイム解析ロジックを抽出。
func parseTimelineTimeFilter(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func TestParseTimelineTimeFilter_ValidRFC3339(t *testing.T) {
	// 有効なRFC3339形式の文字列は正常にパースされることを確認
	valid := []string{
		"2024-01-01T00:00:00Z",
		"2024-06-15T12:30:00+09:00",
		"2023-12-31T23:59:59Z",
	}
	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			_, ok := parseTimelineTimeFilter(s)
			if !ok {
				t.Errorf("parseTimelineTimeFilter(%q): 有効な形式なのに false が返りました", s)
			}
		})
	}
}

func TestParseTimelineTimeFilter_InvalidFormats_ReturnFalse(t *testing.T) {
	// 無効な形式の文字列は false を返すことを確認
	invalid := []string{
		"",
		"2024-01-01",           // 日付のみ（時刻なし）
		"2024/01/01T00:00:00Z", // スラッシュ区切り
		"not-a-date",
		"2024-13-01T00:00:00Z", // 不正な月
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, ok := parseTimelineTimeFilter(s)
			if ok {
				t.Errorf("parseTimelineTimeFilter(%q): 無効な形式なのに true が返りました", s)
			}
		})
	}
}

func TestParseTimelineTimeFilter_ReturnedTimeMatchesInput(t *testing.T) {
	// パースされた時刻が入力文字列と一致することを確認
	input := "2024-03-15T10:30:00Z"
	got, ok := parseTimelineTimeFilter(input)
	if !ok {
		t.Fatalf("parseTimelineTimeFilter(%q) = false, 有効な形式のはず", input)
	}
	want, _ := time.Parse(time.RFC3339, input)
	if !got.Equal(want) {
		t.Errorf("parseTimelineTimeFilter(%q) 時刻 = %v, want %v", input, got, want)
	}
}

// ─────────────────────────────────────────────
// TimelineEvent 構造体フィールドのテスト
// ─────────────────────────────────────────────

func TestTimelineEvent_ZeroValueDefaults(t *testing.T) {
	// TimelineEvent のゼロ値が予期通りであることを確認
	var ev TimelineEvent
	if ev.Severity != 0 {
		t.Errorf("Severity のゼロ値は 0 のはず, got %d", ev.Severity)
	}
	if !ev.Timestamp.IsZero() {
		t.Errorf("Timestamp のゼロ値は time.Zero のはず, got %v", ev.Timestamp)
	}
	if ev.ID != "" || ev.Type != "" || ev.Title != "" {
		t.Errorf("文字列フィールドのゼロ値は空文字列のはず")
	}
}

func TestTimelineEvent_FieldAssignment(t *testing.T) {
	// TimelineEvent のフィールドが正しく代入されることを確認
	now := time.Now()
	ev := TimelineEvent{
		ID:        "ev-001",
		Type:      "alert",
		Title:     "テストアラート",
		Detail:    "詳細情報",
		Severity:  3,
		AgentID:   "agent-001",
		Timestamp: now,
		Link:      "/alerts/ev-001",
	}
	if ev.ID != "ev-001" {
		t.Errorf("ID = %q, want \"ev-001\"", ev.ID)
	}
	if ev.Severity != 3 {
		t.Errorf("Severity = %d, want 3", ev.Severity)
	}
	if !ev.Timestamp.Equal(now) {
		t.Errorf("Timestamp が一致しません")
	}
}
