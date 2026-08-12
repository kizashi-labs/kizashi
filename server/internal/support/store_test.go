package support

import (
	"testing"
)

// ─── itoa ────────────────────────────────────────────────────────────────────
// itoa は PostgreSQL パラメータプレースホルダー生成用の内部関数 (1〜9 の範囲)

func TestItoa_SingleDigits(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1, "1"},
		{2, "2"},
		{3, "3"},
		{5, "5"},
		{9, "9"},
	}
	for _, tc := range cases {
		got := itoa(tc.n)
		if got != tc.want {
			t.Errorf("itoa(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestItoa_Zero(t *testing.T) {
	got := itoa(0)
	if got != "0" {
		t.Errorf("itoa(0) = %q, want \"0\"", got)
	}
}

// ─── TicketFilter (型の基本確認) ──────────────────────────────────────────────

func TestTicketFilter_Defaults(t *testing.T) {
	// ゼロ値が有効な状態であること
	var f TicketFilter
	if f.Status != "" {
		t.Errorf("TicketFilter.Status デフォルトは空: got %q", f.Status)
	}
	if f.Priority != "" {
		t.Errorf("TicketFilter.Priority デフォルトは空: got %q", f.Priority)
	}
}

// ─── Ticket 構造体の基本確認 ──────────────────────────────────────────────────

func TestTicket_RequiredFields(t *testing.T) {
	tk := &Ticket{
		Title:       "Test Ticket",
		Description: "A test description",
		Priority:    "high",
		Status:      "open",
	}
	if tk.Title != "Test Ticket" {
		t.Errorf("Title = %q", tk.Title)
	}
	if tk.Priority != "high" {
		t.Errorf("Priority = %q", tk.Priority)
	}
}
