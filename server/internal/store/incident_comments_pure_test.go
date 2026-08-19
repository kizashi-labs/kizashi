package store

import (
	"strings"
	"testing"
	"time"
)

// コメント本文の規則は **`internal/api/handlers` にあります**
// （`validateCommentBody`）。ここには写しが置いてありましたが、
// **製品にその規則が無い時期に書かれたもの**でした —— 規則の方を足して、
// `incident_comment_body_test.go` が試しています。
//
// 本文の切り詰め (`truncateCommentBody`) も製品にはありません。切り詰めが
// 要るなら製品側の話です。

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
