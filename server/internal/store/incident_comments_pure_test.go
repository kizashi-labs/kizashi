package store

import (
	"strings"
	"testing"
	"time"
)

// ─── コメント本文バリデーションヘルパー（テスト専用）─────────────────────────
// incident_comments.go はDB依存のみのため、
// コメント本文の制約ロジックをテスト内ヘルパーとして定義する。

// isValidCommentBody はコメント本文の基本的な妥当性を検証する
// ・空文字列は無効
// ・スペースのみは無効
// ・10,000 文字を超える場合は無効
func isValidCommentBody(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	if len(body) > 10_000 {
		return false
	}
	return true
}

// truncateCommentBody はコメント本文を指定した最大長で切り詰める
func truncateCommentBody(body string, maxLen int) string {
	runes := []rune(body)
	if len(runes) <= maxLen {
		return body
	}
	return string(runes[:maxLen])
}

// ─── IncidentComment 構造体テスト ────────────────────────────────────────────

// TestIncidentComment_ZeroValue は IncidentComment のゼロ値を確認する
func TestIncidentComment_ZeroValue(t *testing.T) {
	var c IncidentComment
	if c.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", c.ID)
	}
	if c.IncidentID != "" {
		t.Errorf("IncidentID のデフォルト = %q, want \"\"", c.IncidentID)
	}
	if c.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", c.UserID)
	}
	if c.UserName != "" {
		t.Errorf("UserName のデフォルト = %q, want \"\"", c.UserName)
	}
	if c.Body != "" {
		t.Errorf("Body のデフォルト = %q, want \"\"", c.Body)
	}
}

// TestIncidentComment_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestIncidentComment_FieldAssignment(t *testing.T) {
	now := time.Now()
	c := IncidentComment{
		ID:         "comment-001",
		IncidentID: "incident-abc",
		UserID:     "user-xyz",
		UserName:   "田中 太郎",
		Body:       "調査を開始しました。マルウェアの痕跡を確認中です。",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if c.ID != "comment-001" {
		t.Errorf("ID = %q, want \"comment-001\"", c.ID)
	}
	if c.IncidentID != "incident-abc" {
		t.Errorf("IncidentID = %q, want \"incident-abc\"", c.IncidentID)
	}
	if c.UserName != "田中 太郎" {
		t.Errorf("UserName = %q, want \"田中 太郎\"", c.UserName)
	}
	if c.Body == "" {
		t.Error("Body は空でないべき")
	}
	if !c.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", c.CreatedAt, now)
	}
}

// TestIncidentComment_CreatedAtUpdatedAtSameOnCreate は
// 新規作成時は CreatedAt と UpdatedAt が等しいことを確認する
func TestIncidentComment_CreatedAtUpdatedAtSameOnCreate(t *testing.T) {
	now := time.Now()
	c := IncidentComment{CreatedAt: now, UpdatedAt: now}
	if !c.CreatedAt.Equal(c.UpdatedAt) {
		t.Error("新規作成時は CreatedAt と UpdatedAt は等しいべき")
	}
}

// TestIncidentComment_UpdatedAtAfterEdit は
// 編集後は UpdatedAt が CreatedAt より後になることを確認する
func TestIncidentComment_UpdatedAtAfterEdit(t *testing.T) {
	created := time.Now().Add(-1 * time.Hour)
	updated := time.Now()
	c := IncidentComment{CreatedAt: created, UpdatedAt: updated}
	if !c.UpdatedAt.After(c.CreatedAt) {
		t.Error("編集後は UpdatedAt は CreatedAt より後であるべき")
	}
}

// ─── isValidCommentBody テスト ───────────────────────────────────────────────

// TestCommentBody_EmptyIsInvalid は空のコメント本文が無効であることを確認する
func TestCommentBody_EmptyIsInvalid(t *testing.T) {
	if isValidCommentBody("") {
		t.Error("空文字列は無効なコメント本文であるべき")
	}
}

// TestCommentBody_SpacesOnlyIsInvalid はスペースのみのコメントが無効であることを確認する
func TestCommentBody_SpacesOnlyIsInvalid(t *testing.T) {
	if isValidCommentBody("   ") {
		t.Error("スペースのみは無効なコメント本文であるべき")
	}
}

// TestCommentBody_NormalTextIsValid は通常のテキストが有効であることを確認する
func TestCommentBody_NormalTextIsValid(t *testing.T) {
	bodies := []string{
		"IOCを確認しました。",
		"This is a valid comment.",
		"マルウェア検体を隔離しました。詳細な分析が必要です。",
	}
	for _, body := range bodies {
		if !isValidCommentBody(body) {
			t.Errorf("isValidCommentBody(%q) = false, want true", body)
		}
	}
}

// TestCommentBody_TooLongIsInvalid は10,000文字を超えるコメントが無効であることを確認する
func TestCommentBody_TooLongIsInvalid(t *testing.T) {
	longBody := strings.Repeat("a", 10_001)
	if isValidCommentBody(longBody) {
		t.Error("10,001文字のコメントは無効であるべき")
	}
}

// TestCommentBody_ExactMaxLengthIsValid は10,000文字ちょうどが有効であることを確認する
func TestCommentBody_ExactMaxLengthIsValid(t *testing.T) {
	maxBody := strings.Repeat("b", 10_000)
	if !isValidCommentBody(maxBody) {
		t.Errorf("10,000文字のコメントは有効であるべき: len=%d", len(maxBody))
	}
}

// ─── truncateCommentBody テスト ───────────────────────────────────────────────

// TestTruncateCommentBody_ShortBodyUnchanged は短い本文が変更されないことを確認する
func TestTruncateCommentBody_ShortBodyUnchanged(t *testing.T) {
	body := "短いコメント"
	got := truncateCommentBody(body, 100)
	if got != body {
		t.Errorf("truncateCommentBody: got %q, want %q", got, body)
	}
}

// TestTruncateCommentBody_LongBodyTruncated は長い本文が切り詰められることを確認する
func TestTruncateCommentBody_LongBodyTruncated(t *testing.T) {
	body := strings.Repeat("x", 200)
	got := truncateCommentBody(body, 100)
	if len([]rune(got)) != 100 {
		t.Errorf("切り詰め後の長さ = %d, want 100", len([]rune(got)))
	}
}

// TestTruncateCommentBody_ExactLengthUnchanged は
// 本文の長さが制限と等しい場合に変更されないことを確認する
func TestTruncateCommentBody_ExactLengthUnchanged(t *testing.T) {
	body := strings.Repeat("y", 50)
	got := truncateCommentBody(body, 50)
	if got != body {
		t.Errorf("ちょうど最大長の本文は変更されないべき")
	}
}

// TestIncidentComment_BodyPreservesMultiline は
// 複数行のコメント本文が正しく保持されることを確認する
func TestIncidentComment_BodyPreservesMultiline(t *testing.T) {
	multiline := "1行目: 初期調査完了\n2行目: C2通信を特定\n3行目: エージェントを隔離"
	c := IncidentComment{Body: multiline}
	if c.Body != multiline {
		t.Errorf("Body が変更されている: got %q", c.Body)
	}
	lineCount := strings.Count(c.Body, "\n") + 1
	if lineCount != 3 {
		t.Errorf("Body の行数 = %d, want 3", lineCount)
	}
}

// TestIncidentComment_UserNameIsOptional は
// UserName が省略可能なフィールドであることを確認する（COALESCE由来）
func TestIncidentComment_UserNameIsOptional(t *testing.T) {
	// UserName は `json:"user_name,omitempty"` なので省略可能
	c := IncidentComment{
		ID:     "comment-002",
		UserID: "user-anon",
		Body:   "匿名ユーザーのコメント",
	}
	if c.UserName != "" {
		t.Errorf("UserName のデフォルト = %q, want \"\"", c.UserName)
	}
}
