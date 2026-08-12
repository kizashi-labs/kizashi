package scheduler

import (
	"strings"
	"testing"
	"time"
)

// buildLicenseExpiryEmail は残日数に応じて緊急度 (期限切れ / 7日以内 / それ以外) を
// 切り替え、件名と本文を生成する。ユーザーに届く通知の正しさを担保するため、
// 各段階の分岐と必須情報の埋め込みを検証する。

func TestBuildLicenseExpiryEmail_Expired(t *testing.T) {
	exp := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for _, d := range []int{0, -1, -30} {
		subject, body := buildLicenseExpiryEmail("Acme Corp", "professional", exp, d)
		if !strings.Contains(subject, "期限切れ") {
			t.Errorf("daysLeft=%d: subject に「期限切れ」を含むべき: %q", d, subject)
		}
		if !strings.Contains(body, "Acme Corp") {
			t.Errorf("daysLeft=%d: body に組織名を含むべき", d)
		}
	}
}

func TestBuildLicenseExpiryEmail_UrgentWithinWeek(t *testing.T) {
	exp := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	for _, d := range []int{1, 3, 7} {
		subject, _ := buildLicenseExpiryEmail("Beta LLC", "starter", exp, d)
		if !strings.Contains(subject, "至急") {
			t.Errorf("daysLeft=%d: 7日以内は subject に「至急」を含むべき: %q", d, subject)
		}
		if !strings.Contains(subject, "残り") {
			t.Errorf("daysLeft=%d: subject に残日数を含むべき: %q", d, subject)
		}
	}
}

func TestBuildLicenseExpiryEmail_Informational(t *testing.T) {
	exp := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	subject, body := buildLicenseExpiryEmail("Gamma Inc", "enterprise", exp, 30)
	// 8日以上先は「至急」ではなく通常のお知らせトーン。
	if strings.Contains(subject, "至急") {
		t.Errorf("30日先で「至急」は不適切: %q", subject)
	}
	if !strings.Contains(subject, "残り 30 日") {
		t.Errorf("subject に残日数を含むべき: %q", subject)
	}
	// 本文には有効期限日 (フォーマット済み) とプランが埋め込まれる。
	if !strings.Contains(body, exp.Format("2006年01月02日")) {
		t.Errorf("body に有効期限日を含むべき")
	}
	if !strings.Contains(body, "enterprise") {
		t.Errorf("body にプラン名を含むべき")
	}
}

// 件名と本文は常に非空であること (どの分岐でも生成される) を確認する。
func TestBuildLicenseExpiryEmail_NeverEmpty(t *testing.T) {
	exp := time.Now()
	for _, d := range []int{-10, 0, 5, 100} {
		subject, body := buildLicenseExpiryEmail("Org", "starter", exp, d)
		if subject == "" || body == "" {
			t.Errorf("daysLeft=%d: subject/body は非空であるべき", d)
		}
	}
}
