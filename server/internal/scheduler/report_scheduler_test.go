package scheduler

import (
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// smtpFromEnv は環境変数から SMTP 設定を読む。ポートのデフォルト/上書き/不正値、
// および SMTP_FROM 未設定時に SMTP_USERNAME へフォールバックする挙動を検証する。

func TestSMTPFromEnv_Defaults(t *testing.T) {
	for _, k := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"} {
		t.Setenv(k, "")
	}
	cfg := smtpFromEnv()
	if cfg.port != 587 {
		t.Errorf("default port = %d, want 587", cfg.port)
	}
	if cfg.host != "" || cfg.from != "" {
		t.Errorf("空env時は host/from が空であるべき: %+v", cfg)
	}
}

func TestSMTPFromEnv_Overrides(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "25")
	t.Setenv("SMTP_USERNAME", "user@example.com")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM", "")
	cfg := smtpFromEnv()
	if cfg.host != "smtp.example.com" || cfg.port != 25 {
		t.Errorf("host/port が反映されていない: %+v", cfg)
	}
	// SMTP_FROM 未設定 → SMTP_USERNAME にフォールバック
	if cfg.from != "user@example.com" {
		t.Errorf("from = %q, want fallback to username", cfg.from)
	}
}

func TestSMTPFromEnv_InvalidPortFallsBack(t *testing.T) {
	t.Setenv("SMTP_PORT", "not-a-number")
	if cfg := smtpFromEnv(); cfg.port != 587 {
		t.Errorf("不正なポートはデフォルト587にフォールバックすべき, got %d", cfg.port)
	}
}

// buildReportEmail はスケジュール名とレポート種別を埋め込んだHTMLメールを生成する。
func TestBuildReportEmail(t *testing.T) {
	t.Setenv("EDR_BASE_URL", "")
	sched := &store.ReportSchedule{Name: "週次セキュリティレポート", ReportType: "security"}
	html := buildReportEmail(sched, "本文サンプル")

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTMLメールは DOCTYPE を含むべき")
	}
	if !strings.Contains(html, "週次セキュリティレポート") {
		t.Error("本文にスケジュール名が埋め込まれるべき")
	}
	if !strings.Contains(html, "本文サンプル") {
		t.Error("渡した textBody が本文に含まれるべき")
	}
}
