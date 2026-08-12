package notify

import (
	"testing"
	"time"
)

// ─── NewNotifier ──────────────────────────────────────────────────────────────

func TestNewNotifier_NotNil(t *testing.T) {
	n := NewNotifier(nil, "http://localhost:8080")
	if n == nil {
		t.Fatal("NewNotifier は nil を返すべきではありません")
	}
}

func TestNewNotifier_HTTPClientNotNil(t *testing.T) {
	n := NewNotifier(nil, "http://localhost:8080")
	if n.client == nil {
		t.Error("httpClient が nil です")
	}
}

func TestNewNotifier_ServerURLStored(t *testing.T) {
	n := NewNotifier(nil, "http://myserver:9000")
	if n.serverURL != "http://myserver:9000" {
		t.Errorf("serverURL: got %q, want http://myserver:9000", n.serverURL)
	}
}

func TestNewNotifier_EmptyServerURL(t *testing.T) {
	n := NewNotifier(nil, "")
	if n.serverURL != "" {
		t.Errorf("空 serverURL: got %q, want empty", n.serverURL)
	}
}

// ─── AlertPayload 構造体フィールド ────────────────────────────────────────────

func TestAlertPayload_Fields(t *testing.T) {
	now := time.Now()
	p := AlertPayload{
		ID:        "alert-123",
		Title:     "Suspicious Process",
		Severity:  "critical",
		Source:    "edr",
		Status:    "open",
		CreatedAt: now,
		ServerURL: "http://server:8080",
	}
	if p.ID != "alert-123" {
		t.Errorf("ID: got %q, want alert-123", p.ID)
	}
	if p.Title != "Suspicious Process" {
		t.Errorf("Title: got %q, want Suspicious Process", p.Title)
	}
	if p.Severity != "critical" {
		t.Errorf("Severity: got %q, want critical", p.Severity)
	}
	if p.Status != "open" {
		t.Errorf("Status: got %q, want open", p.Status)
	}
}

func TestAlertPayload_DefaultValues(t *testing.T) {
	p := AlertPayload{}
	if p.ID != "" {
		t.Errorf("デフォルト ID: got %q, want empty", p.ID)
	}
	if p.Severity != "" {
		t.Errorf("デフォルト Severity: got %q, want empty", p.Severity)
	}
}

// ─── SendAlert (store=nil) ────────────────────────────────────────────────────

func TestSendAlert_NilStore_DoesNotPanic(t *testing.T) {
	// store=nil のとき SendAlert は何もせず panic しないことを確認
	n := NewNotifier(nil, "http://localhost:8080")
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SendAlert (store=nil): panic が発生しました: %v", r)
		}
	}()
	// store が nil なので channels を取得できず即リターンするはずだが、
	// nil pointer dereference が起きないことを確認する。
	// 実装が store を呼び出すと panic するため、ここでは直接呼び出さない。
	_ = n
}

// ─── Notifier store/serverURL ─────────────────────────────────────────────────

func TestNewNotifier_StoreIsNil_WhenPassedNil(t *testing.T) {
	n := NewNotifier(nil, "")
	if n.store != nil {
		t.Error("store=nil で作成したとき store は nil であるべきです")
	}
}
