package notification

// メール通知のうち、SMTP 接続を伴わない部分。
//
// 実送信 (sendEmail / sendMailSTARTTLS) は STARTTLS ハンドシェイクを行うため
// 偽サーバを立てるコストが高く、ここでは対象にしていない。
// 代わりに「誰に送るか」「何を送るか」を決める部分を固定する。

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── 送信対象の絞り込み ───────────────────────────────────────────

// TestIsCriticalOrHigh はメールを送る深刻度の線引き。
// ここが緩むと低優先度のアラートまでメール配信され、通知疲れを起こす。
func TestIsCriticalOrHigh(t *testing.T) {
	send := []string{"critical", "high"}
	skip := []string{"medium", "low", "info", "", "CRITICAL", "High", "unknown"}

	for _, s := range send {
		if !isCriticalOrHigh(s) {
			t.Errorf("isCriticalOrHigh(%q) = false, want true", s)
		}
	}
	for _, s := range skip {
		if isCriticalOrHigh(s) {
			t.Errorf("isCriticalOrHigh(%q) = true, want false", s)
		}
	}
}

// TestSeverityLabel は件名に出る表示名。未知の値は素通しする。
func TestSeverityLabel(t *testing.T) {
	cases := map[string]string{
		"critical": "緊急",
		"high":     "高",
		"medium":   "中",
		"low":      "低",
		"unknown":  "unknown",
		"":         "",
	}
	for in, want := range cases {
		if got := severityLabel(in); got != want {
			t.Errorf("severityLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── 本文の組み立て ───────────────────────────────────────────────

func TestBuildAlertEmailBody_IncludesAlertDetails(t *testing.T) {
	alert := AlertPayload{
		ID:            "alert-123",
		Title:         "Known IOC detected: 203.0.113.10",
		Severity:      "critical",
		AgentHostname: "web-01",
		RuleName:      "IOC Match: ip",
		CreatedAt:     time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC),
	}

	body := buildAlertEmailBody(alert)

	for _, want := range []string{alert.Title, alert.AgentHostname, alert.RuleName} {
		if !strings.Contains(body, want) {
			t.Errorf("本文に %q が含まれていない", want)
		}
	}
	if !strings.Contains(body, "2026-08-02 03:04:05") {
		t.Errorf("本文に発生時刻が含まれていない:\n%s", body)
	}
}

// TestBuildAlertEmailBody_FallsBackForMissingFields は欠けた項目の穴埋め。
// 生の空文字が本文に出ると、受信者は「情報が無い」のか「壊れている」のか
// 判断できない。
func TestBuildAlertEmailBody_FallsBackForMissingFields(t *testing.T) {
	// hostname も agent_id も無い。
	body := buildAlertEmailBody(AlertPayload{
		Title:    "no host",
		Severity: "high",
	})
	if !strings.Contains(body, "不明") {
		t.Errorf("ホスト名の穴埋め (不明) が出ていない:\n%s", body)
	}
	if !strings.Contains(body, "—") {
		t.Errorf("ルール名の穴埋め (—) が出ていない:\n%s", body)
	}

	// hostname が無いときは agent_id で代替する。
	body = buildAlertEmailBody(AlertPayload{
		Title:    "id only",
		Severity: "high",
		AgentID:  "agent-xyz",
	})
	if !strings.Contains(body, "agent-xyz") {
		t.Errorf("hostname 欠落時に agent_id で代替していない:\n%s", body)
	}
}

// TestBuildAlertEmailBody_SeverityColor は critical と high で色を変えること。
func TestBuildAlertEmailBody_SeverityColor(t *testing.T) {
	crit := buildAlertEmailBody(AlertPayload{Title: "x", Severity: "critical"})
	high := buildAlertEmailBody(AlertPayload{Title: "x", Severity: "high"})

	if !strings.Contains(crit, "#dc2626") {
		t.Error("critical で赤 (#dc2626) が使われていない")
	}
	if !strings.Contains(high, "#ea580c") {
		t.Error("high で橙 (#ea580c) が使われていない")
	}
}

// ── 起動時の縮退 ─────────────────────────────────────────────────

// TestEmailNotifier_StartWithoutSMTPHostReturns は SMTP 未設定時に
// 即座に戻ること。ここでブロックすると起動シーケンスが止まる。
func TestEmailNotifier_StartWithoutSMTPHost(t *testing.T) {
	n := NewEmailNotifier(nil, nil) // SMTP 環境変数なし想定

	done := make(chan struct{})
	go func() {
		n.Start(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP 未設定でも Start が戻らない")
	}
}
