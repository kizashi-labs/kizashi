package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────
// validateCorrelationRuleRequest のテスト
// ─────────────────────────────────────────────

func strPtr(s string) *string { return &s }

func TestValidateCorrelationRuleRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     correlationRuleRequest
		wantMsg string
	}{
		{
			// 有効なリクエスト
			name: "有効なリクエスト",
			req: correlationRuleRequest{
				AgentID:        "agent-uuid-001",
				MITRETechnique: "T1059",
				AlertCount:     3,
			},
			wantMsg: "",
		},
		{
			// IncidentIDあり
			name: "IncidentIDありで有効",
			req: correlationRuleRequest{
				AgentID:        "agent-uuid-002",
				MITRETechnique: "T1078",
				AlertCount:     5,
				IncidentID:     strPtr("inc-uuid-123"),
			},
			wantMsg: "",
		},
		{
			// agent_id が空
			name: "agent_idが空",
			req: correlationRuleRequest{
				AgentID:        "",
				MITRETechnique: "T1059",
				AlertCount:     1,
			},
			wantMsg: "agent_id は必須です",
		},
		{
			// agent_id がスペースのみ
			name: "agent_idがスペースのみ",
			req: correlationRuleRequest{
				AgentID:        "   ",
				MITRETechnique: "T1059",
				AlertCount:     1,
			},
			wantMsg: "agent_id は必須です",
		},
		{
			// mitre_technique が空
			name: "mitre_techniqueが空",
			req: correlationRuleRequest{
				AgentID:        "agent-001",
				MITRETechnique: "",
				AlertCount:     2,
			},
			wantMsg: "mitre_technique は必須です",
		},
		{
			// mitre_technique がスペースのみ
			name: "mitre_techniqueがスペースのみ",
			req: correlationRuleRequest{
				AgentID:        "agent-001",
				MITRETechnique: "  ",
				AlertCount:     2,
			},
			wantMsg: "mitre_technique は必須です",
		},
		{
			// alert_count が 0
			name: "alert_countが0",
			req: correlationRuleRequest{
				AgentID:        "agent-001",
				MITRETechnique: "T1059",
				AlertCount:     0,
			},
			wantMsg: "alert_count は 1 以上を指定してください",
		},
		{
			// alert_count が負数
			name: "alert_countが負数",
			req: correlationRuleRequest{
				AgentID:        "agent-001",
				MITRETechnique: "T1059",
				AlertCount:     -5,
			},
			wantMsg: "alert_count は 1 以上を指定してください",
		},
		{
			// alert_count がちょうど 1 (境界値)
			name: "alert_count=1（境界値）",
			req: correlationRuleRequest{
				AgentID:        "agent-001",
				MITRETechnique: "T1059",
				AlertCount:     1,
			},
			wantMsg: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateCorrelationRuleRequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateCorrelationRuleRequest() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

// ─────────────────────────────────────────────
// validateCERequest のテスト
// ─────────────────────────────────────────────

func TestValidateCERequest(t *testing.T) {
	tests := []struct {
		name              string
		req               correlationEngineRuleRequest
		wantMsg           string
		wantTimeWindow    int // デフォルト補完後の値
		wantAlertSeverity int
	}{
		{
			// 有効なリクエスト（明示的な値あり）
			name: "有効なリクエスト",
			req: correlationEngineRuleRequest{
				Name:              "BruteForce",
				TriggerEventType:  "auth_failure",
				FollowEventType:   "auth_success",
				AlertTitle:        "Brute Force Detected",
				TimeWindowSeconds: 60,
				AlertSeverity:     8,
			},
			wantMsg:           "",
			wantTimeWindow:    60,
			wantAlertSeverity: 8,
		},
		{
			// TimeWindowSeconds が 0 → デフォルト 300 に補完
			name: "TimeWindowSeconds=0でデフォルト300",
			req: correlationEngineRuleRequest{
				Name:              "TestRule",
				TriggerEventType:  "login",
				FollowEventType:   "exec",
				AlertTitle:        "Test Alert",
				TimeWindowSeconds: 0,
				AlertSeverity:     5,
			},
			wantMsg:           "",
			wantTimeWindow:    300,
			wantAlertSeverity: 5,
		},
		{
			// AlertSeverity が 0 → デフォルト 7 に補完
			name: "AlertSeverity=0でデフォルト7",
			req: correlationEngineRuleRequest{
				Name:              "TestRule2",
				TriggerEventType:  "net_conn",
				FollowEventType:   "dns_query",
				AlertTitle:        "Network Alert",
				TimeWindowSeconds: 120,
				AlertSeverity:     0,
			},
			wantMsg:           "",
			wantTimeWindow:    120,
			wantAlertSeverity: 7,
		},
		{
			// name が空
			name: "nameが空",
			req: correlationEngineRuleRequest{
				Name:             "",
				TriggerEventType: "event_a",
				FollowEventType:  "event_b",
				AlertTitle:       "Alert",
			},
			wantMsg: "name is required",
		},
		{
			// name がスペースのみ
			name: "nameがスペースのみ",
			req: correlationEngineRuleRequest{
				Name:             "  ",
				TriggerEventType: "event_a",
				FollowEventType:  "event_b",
				AlertTitle:       "Alert",
			},
			wantMsg: "name is required",
		},
		{
			// trigger_event_type が空
			name: "trigger_event_typeが空",
			req: correlationEngineRuleRequest{
				Name:             "Rule",
				TriggerEventType: "",
				FollowEventType:  "event_b",
				AlertTitle:       "Alert",
			},
			wantMsg: "trigger_event_type is required",
		},
		{
			// follow_event_type が空
			name: "follow_event_typeが空",
			req: correlationEngineRuleRequest{
				Name:             "Rule",
				TriggerEventType: "event_a",
				FollowEventType:  "",
				AlertTitle:       "Alert",
			},
			wantMsg: "follow_event_type is required",
		},
		{
			// alert_title が空
			name: "alert_titleが空",
			req: correlationEngineRuleRequest{
				Name:             "Rule",
				TriggerEventType: "event_a",
				FollowEventType:  "event_b",
				AlertTitle:       "",
			},
			wantMsg: "alert_title is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateCERequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateCERequest() = %q, want %q", got, tc.wantMsg)
			}
			// デフォルト補完の検証 (エラーなしの場合のみ)
			if tc.wantMsg == "" {
				if req.TimeWindowSeconds != tc.wantTimeWindow {
					t.Errorf("TimeWindowSeconds = %d, want %d", req.TimeWindowSeconds, tc.wantTimeWindow)
				}
				if req.AlertSeverity != tc.wantAlertSeverity {
					t.Errorf("AlertSeverity = %d, want %d", req.AlertSeverity, tc.wantAlertSeverity)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────
// validateEscalationRuleRequest のテスト
// ─────────────────────────────────────────────

func TestValidateEscalationRuleRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     escalationRuleRequest
		wantMsg string
	}{
		{
			// 有効なリクエスト
			name: "有効なリクエスト",
			req: escalationRuleRequest{
				Name:           "HighSeverityEscalation",
				SeverityMin:    7,
				UnresolvedMins: 30,
				EscalateTo:     "oncall-team",
			},
			wantMsg: "",
		},
		{
			// name が空
			name: "nameが空",
			req: escalationRuleRequest{
				Name:           "",
				SeverityMin:    5,
				UnresolvedMins: 60,
				EscalateTo:     "team",
			},
			wantMsg: "name は必須です",
		},
		{
			// name がスペースのみ
			name: "nameがスペースのみ",
			req: escalationRuleRequest{
				Name:           "  ",
				SeverityMin:    5,
				UnresolvedMins: 60,
				EscalateTo:     "team",
			},
			wantMsg: "name は必須です",
		},
		{
			// escalate_to が空
			name: "escalate_toが空",
			req: escalationRuleRequest{
				Name:           "TestRule",
				SeverityMin:    5,
				UnresolvedMins: 60,
				EscalateTo:     "",
			},
			wantMsg: "escalate_to は必須です",
		},
		{
			// severity_min が 0 (範囲外)
			name: "severity_min=0（範囲外）",
			req: escalationRuleRequest{
				Name:           "TestRule",
				SeverityMin:    0,
				UnresolvedMins: 60,
				EscalateTo:     "team",
			},
			wantMsg: "severity_min は 1〜10 の範囲で指定してください",
		},
		{
			// severity_min が 11 (範囲外)
			name: "severity_min=11（範囲外）",
			req: escalationRuleRequest{
				Name:           "TestRule",
				SeverityMin:    11,
				UnresolvedMins: 60,
				EscalateTo:     "team",
			},
			wantMsg: "severity_min は 1〜10 の範囲で指定してください",
		},
		{
			// severity_min=1 (境界値・有効)
			name: "severity_min=1（境界値・有効）",
			req: escalationRuleRequest{
				Name:           "LowSeverityEsc",
				SeverityMin:    1,
				UnresolvedMins: 5,
				EscalateTo:     "team",
			},
			wantMsg: "",
		},
		{
			// severity_min=10 (境界値・有効)
			name: "severity_min=10（境界値・有効）",
			req: escalationRuleRequest{
				Name:           "CriticalEsc",
				SeverityMin:    10,
				UnresolvedMins: 5,
				EscalateTo:     "sec-team",
			},
			wantMsg: "",
		},
		{
			// unresolved_mins が 0
			name: "unresolved_mins=0",
			req: escalationRuleRequest{
				Name:           "TestRule",
				SeverityMin:    5,
				UnresolvedMins: 0,
				EscalateTo:     "team",
			},
			wantMsg: "unresolved_mins は 1 以上を指定してください",
		},
		{
			// unresolved_mins が負数
			name: "unresolved_minsが負数",
			req: escalationRuleRequest{
				Name:           "TestRule",
				SeverityMin:    5,
				UnresolvedMins: -10,
				EscalateTo:     "team",
			},
			wantMsg: "unresolved_mins は 1 以上を指定してください",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateEscalationRuleRequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateEscalationRuleRequest() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}
