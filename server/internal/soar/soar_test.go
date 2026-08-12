package soar

import (
	"testing"
)

// ─── NewClient ────────────────────────────────────────────────────────────────

func TestNewClient_Jira_AllFields_ReturnsClient(t *testing.T) {
	cfg := map[string]interface{}{
		"url":       "https://myorg.atlassian.net",
		"email":     "user@example.com",
		"api_token": "token-abc",
		"project":   "EDR",
	}
	client, err := NewClient("jira", cfg)
	if err != nil {
		t.Fatalf("NewClient jira: 予期しないエラー: %v", err)
	}
	if client == nil {
		t.Fatal("NewClient jira: nil が返されました")
	}
}

func TestNewClient_Jira_MissingURL_ReturnsError(t *testing.T) {
	cfg := map[string]interface{}{
		"email":     "user@example.com",
		"api_token": "token-abc",
		"project":   "EDR",
	}
	_, err := NewClient("jira", cfg)
	if err == nil {
		t.Error("url なしの jira 設定はエラーを返すべきです")
	}
}

func TestNewClient_Jira_MissingEmail_ReturnsError(t *testing.T) {
	cfg := map[string]interface{}{
		"url":       "https://myorg.atlassian.net",
		"api_token": "token-abc",
		"project":   "EDR",
	}
	_, err := NewClient("jira", cfg)
	if err == nil {
		t.Error("email なしの jira 設定はエラーを返すべきです")
	}
}

func TestNewClient_Jira_MissingProject_ReturnsError(t *testing.T) {
	cfg := map[string]interface{}{
		"url":       "https://myorg.atlassian.net",
		"email":     "user@example.com",
		"api_token": "token-abc",
	}
	_, err := NewClient("jira", cfg)
	if err == nil {
		t.Error("project なしの jira 設定はエラーを返すべきです")
	}
}

func TestNewClient_ServiceNow_AllFields_ReturnsClient(t *testing.T) {
	cfg := map[string]interface{}{
		"url":      "https://instance.service-now.com",
		"username": "admin",
		"password": "pass123",
	}
	client, err := NewClient("servicenow", cfg)
	if err != nil {
		t.Fatalf("NewClient servicenow: 予期しないエラー: %v", err)
	}
	if client == nil {
		t.Fatal("NewClient servicenow: nil が返されました")
	}
}

func TestNewClient_ServiceNow_MissingURL_ReturnsError(t *testing.T) {
	cfg := map[string]interface{}{
		"username": "admin",
		"password": "pass123",
	}
	_, err := NewClient("servicenow", cfg)
	if err == nil {
		t.Error("url なしの servicenow 設定はエラーを返すべきです")
	}
}

func TestNewClient_ServiceNow_MissingUsername_ReturnsError(t *testing.T) {
	cfg := map[string]interface{}{
		"url":      "https://instance.service-now.com",
		"password": "pass123",
	}
	_, err := NewClient("servicenow", cfg)
	if err == nil {
		t.Error("username なしの servicenow 設定はエラーを返すべきです")
	}
}

func TestNewClient_ServiceNow_DefaultTable_IsIncident(t *testing.T) {
	cfg := map[string]interface{}{
		"url":      "https://instance.service-now.com",
		"username": "admin",
		"password": "pass123",
		// table を指定しない
	}
	client, err := NewClient("servicenow", cfg)
	if err != nil {
		t.Fatalf("NewClient servicenow (デフォルトtable): %v", err)
	}
	sn, ok := client.(*ServiceNowClient)
	if !ok {
		t.Fatal("ServiceNowClient への型アサーションに失敗しました")
	}
	if sn.table != "incident" {
		t.Errorf("デフォルト table: got %q, want incident", sn.table)
	}
}

func TestNewClient_ServiceNow_ExplicitTable_Preserved(t *testing.T) {
	cfg := map[string]interface{}{
		"url":      "https://instance.service-now.com",
		"username": "admin",
		"password": "pass123",
		"table":    "problem",
	}
	client, err := NewClient("servicenow", cfg)
	if err != nil {
		t.Fatalf("NewClient servicenow (table 指定): %v", err)
	}
	sn := client.(*ServiceNowClient)
	if sn.table != "problem" {
		t.Errorf("table: got %q, want problem", sn.table)
	}
}

func TestNewClient_Unknown_ReturnsError(t *testing.T) {
	_, err := NewClient("unknown_soar", map[string]interface{}{})
	if err == nil {
		t.Error("未対応のSOARタイプはエラーを返すべきです")
	}
}

// ─── jiraIssuePriority ────────────────────────────────────────────────────────

func TestJiraIssuePriority_Critical_ReturnsHighest(t *testing.T) {
	if got := jiraIssuePriority("critical"); got != "Highest" {
		t.Errorf("critical: got %q, want Highest", got)
	}
}

func TestJiraIssuePriority_High_ReturnsHigh(t *testing.T) {
	if got := jiraIssuePriority("high"); got != "High" {
		t.Errorf("high: got %q, want High", got)
	}
}

func TestJiraIssuePriority_Medium_ReturnsMedium(t *testing.T) {
	if got := jiraIssuePriority("medium"); got != "Medium" {
		t.Errorf("medium: got %q, want Medium", got)
	}
}

func TestJiraIssuePriority_Low_ReturnsLow(t *testing.T) {
	if got := jiraIssuePriority("low"); got != "Low" {
		t.Errorf("low: got %q, want Low", got)
	}
}

func TestJiraIssuePriority_Unknown_ReturnsLow(t *testing.T) {
	if got := jiraIssuePriority("unknown_prio"); got != "Low" {
		t.Errorf("unknown: got %q, want Low", got)
	}
}

// ─── snUrgency ────────────────────────────────────────────────────────────────

func TestSnUrgency_Critical_Returns1(t *testing.T) {
	if got := snUrgency("critical"); got != "1" {
		t.Errorf("critical: got %q, want 1", got)
	}
}

func TestSnUrgency_High_Returns2(t *testing.T) {
	if got := snUrgency("high"); got != "2" {
		t.Errorf("high: got %q, want 2", got)
	}
}

func TestSnUrgency_Medium_Returns3(t *testing.T) {
	if got := snUrgency("medium"); got != "3" {
		t.Errorf("medium: got %q, want 3", got)
	}
}

func TestSnUrgency_Low_Returns3(t *testing.T) {
	if got := snUrgency("low"); got != "3" {
		t.Errorf("low: got %q, want 3", got)
	}
}

func TestSnUrgency_Unknown_Returns3(t *testing.T) {
	if got := snUrgency("unknown"); got != "3" {
		t.Errorf("unknown: got %q, want 3", got)
	}
}

// ─── basicAuth (JiraClient) ───────────────────────────────────────────────────

func TestJiraBasicAuth_StartsWithBasic(t *testing.T) {
	j := &JiraClient{email: "user@example.com", apiToken: "token123"}
	auth := j.basicAuth()
	if len(auth) < 6 || auth[:6] != "Basic " {
		t.Errorf("basicAuth: got %q, want 'Basic ...'", auth)
	}
}

func TestJiraBasicAuth_Deterministic(t *testing.T) {
	j := &JiraClient{email: "user@example.com", apiToken: "token123"}
	a, b := j.basicAuth(), j.basicAuth()
	if a != b {
		t.Error("basicAuth は冪等であるべきです")
	}
}

// ─── basicAuth (ServiceNowClient) ────────────────────────────────────────────

func TestSnBasicAuth_StartsWithBasic(t *testing.T) {
	s := &ServiceNowClient{username: "admin", password: "pass"}
	auth := s.basicAuth()
	if len(auth) < 6 || auth[:6] != "Basic " {
		t.Errorf("basicAuth: got %q, want 'Basic ...'", auth)
	}
}

func TestSnBasicAuth_DifferentCredsProduceDifferentAuth(t *testing.T) {
	s1 := &ServiceNowClient{username: "admin", password: "pass1"}
	s2 := &ServiceNowClient{username: "admin", password: "pass2"}
	if s1.basicAuth() == s2.basicAuth() {
		t.Error("異なる認証情報は異なる basicAuth を生成すべきです")
	}
}
