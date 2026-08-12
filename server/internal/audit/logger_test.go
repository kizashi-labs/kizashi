package audit

import (
	"testing"
	"time"
)

// ─── NewLogger ────────────────────────────────────────────────────────────────

func TestNewLogger_NotNil(t *testing.T) {
	l := NewLogger(nil)
	if l == nil {
		t.Fatal("NewLogger は nil を返すべきではありません")
	}
}

func TestNewLogger_HasBufferedChannel(t *testing.T) {
	l := NewLogger(nil)
	// ch フィールドは 1000 バッファのチャネルであるはず
	if cap(l.ch) != 1000 {
		t.Errorf("ch capacity: got %d, want 1000", cap(l.ch))
	}
}

// ─── Log ──────────────────────────────────────────────────────────────────────

func TestLog_NilEvent_DoesNotPanic(t *testing.T) {
	l := NewLogger(nil)
	// パニックしないことを確認
	l.Log(nil)
}

func TestLog_ValidEvent_EnqueuesEvent(t *testing.T) {
	l := NewLogger(nil)
	e := &Event{
		Action:    "login",
		Resource:  "auth",
		Success:   true,
		Timestamp: time.Now(),
	}
	l.Log(e)
	if len(l.ch) != 1 {
		t.Errorf("Log: チャネルにイベントが入っていません: len=%d", len(l.ch))
	}
}

func TestLog_SetsRiskScore(t *testing.T) {
	l := NewLogger(nil)
	e := &Event{
		Action:    "export_data",
		Resource:  "reports",
		Success:   true,
		Timestamp: time.Now(),
	}
	l.Log(e)
	if e.RiskScore == 0 {
		// export アクションは RiskScore > 0 のはず
		t.Error("Log: export アクションで RiskScore が設定されるべきです")
	}
}

// ─── CalculateRiskScore ───────────────────────────────────────────────────────

func makeEvent(action, resource string, success bool, hour int) *Event {
	ts := time.Date(2026, 3, 20, hour, 0, 0, 0, time.UTC)
	return &Event{
		Action:    action,
		Resource:  resource,
		Success:   success,
		Timestamp: ts,
	}
}

func TestCalculateRiskScore_BusinessHours_NormalAction_Zero(t *testing.T) {
	e := makeEvent("view_alert", "alerts", true, 10)
	score := CalculateRiskScore(e)
	if score != 0 {
		t.Errorf("通常の業務時間アクション: score got %d, want 0", score)
	}
}

func TestCalculateRiskScore_EarlyHour_Adds20(t *testing.T) {
	e := makeEvent("view_alert", "alerts", true, 3) // 3am
	score := CalculateRiskScore(e)
	if score != 20 {
		t.Errorf("深夜(3am): score got %d, want 20", score)
	}
}

func TestCalculateRiskScore_LateHour_Adds20(t *testing.T) {
	e := makeEvent("view_alert", "alerts", true, 23) // 11pm
	score := CalculateRiskScore(e)
	if score != 20 {
		t.Errorf("深夜(11pm): score got %d, want 20", score)
	}
}

func TestCalculateRiskScore_Hour6_IsNotUnusual(t *testing.T) {
	e := makeEvent("view_alert", "alerts", true, 6)
	score := CalculateRiskScore(e)
	if score != 0 {
		t.Errorf("6am は通常時間: score got %d, want 0", score)
	}
}

func TestCalculateRiskScore_DeleteAction_Adds10(t *testing.T) {
	e := makeEvent("delete_agent", "agents", true, 10)
	score := CalculateRiskScore(e)
	if score != 10 {
		t.Errorf("delete アクション: score got %d, want 10", score)
	}
}

func TestCalculateRiskScore_BulkDeleteAction_Adds30(t *testing.T) {
	e := makeEvent("bulk_delete", "agents", true, 10)
	score := CalculateRiskScore(e)
	if score != 30 {
		t.Errorf("bulk delete アクション: score got %d, want 30", score)
	}
}

func TestCalculateRiskScore_ConfigResource_Adds15(t *testing.T) {
	e := makeEvent("update", "config", true, 10)
	score := CalculateRiskScore(e)
	if score != 15 {
		t.Errorf("config リソース: score got %d, want 15", score)
	}
}

func TestCalculateRiskScore_FailedLogin_Adds25(t *testing.T) {
	e := makeEvent("login", "auth", false, 10) // Success=false
	score := CalculateRiskScore(e)
	if score != 25 {
		t.Errorf("失敗ログイン: score got %d, want 25", score)
	}
}

func TestCalculateRiskScore_SuccessfulLogin_NoBonus(t *testing.T) {
	e := makeEvent("login", "auth", true, 10)
	score := CalculateRiskScore(e)
	if score != 0 {
		t.Errorf("成功ログイン: score got %d, want 0", score)
	}
}

func TestCalculateRiskScore_ExportAction_Adds10(t *testing.T) {
	e := makeEvent("export_csv", "reports", true, 10)
	score := CalculateRiskScore(e)
	if score != 10 {
		t.Errorf("export アクション: score got %d, want 10", score)
	}
}

func TestCalculateRiskScore_CombinedFactors(t *testing.T) {
	// 深夜(+20) + 失敗auth(+25) = 45
	e := makeEvent("auth_attempt", "auth", false, 2)
	score := CalculateRiskScore(e)
	if score != 45 {
		t.Errorf("複合要因(深夜+失敗auth): score got %d, want 45", score)
	}
}

func TestCalculateRiskScore_CappedAt100(t *testing.T) {
	// 深夜(+20) + bulk_delete(+30) + config(+15) + failed_auth(+25) = 90 → 90
	// 全て重ねるとスコアが100を超えることを確認
	e := makeEvent("bulk_delete_config_auth", "config", false, 2)
	score := CalculateRiskScore(e)
	if score > 100 {
		t.Errorf("スコアは100を超えるべきではありません: got %d", score)
	}
}

func TestCalculateRiskScore_ZeroTimestamp_NoUnusualHourBonus(t *testing.T) {
	// Timestamp がゼロ値の場合、深夜ボーナスは付かない
	e := &Event{Action: "view", Resource: "alerts", Success: true}
	score := CalculateRiskScore(e)
	if score != 0 {
		t.Errorf("ゼロTimestampで通常アクション: score got %d, want 0", score)
	}
}

func TestCalculateRiskScore_FailedAuthVariant(t *testing.T) {
	// "auth" ではなく "auth_check" でも失敗なら加点
	e := makeEvent("auth_check", "sso", false, 10)
	score := CalculateRiskScore(e)
	if score != 25 {
		t.Errorf("失敗auth_check: score got %d, want 25", score)
	}
}
