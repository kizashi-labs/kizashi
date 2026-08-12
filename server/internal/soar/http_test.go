package soar

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// これらのテストは httptest.Server を使って JiraClient / ServiceNowClient の
// HTTP 経路（doRequest / CreateTicket / TestConnection）を実ネットワークなしで検証する。
// 従来カバーされていなかった成功・エラー・不正レスポンスの各分岐を網羅する。

// ─── Jira: CreateTicket ────────────────────────────────────────────────────────

func TestJira_CreateTicket_Success(t *testing.T) {
	var gotAuth, gotContentType, gotPath, gotMethod string
	var payload map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10001","key":"EDR-42","self":"https://x/rest/api/3/issue/10001"}`))
	}))
	defer srv.Close()

	j := &JiraClient{
		baseURL:  srv.URL,
		email:    "user@example.com",
		apiToken: "token-abc",
		project:  "EDR",
		client:   srv.Client(),
	}

	resp, err := j.CreateTicket(context.Background(), TicketRequest{
		Title:       "不審なプロセス実行",
		Description: "T1059 が発火",
		Priority:    "critical",
	})
	if err != nil {
		t.Fatalf("CreateTicket: 予期しないエラー: %v", err)
	}
	if resp.TicketID != "EDR-42" {
		t.Errorf("TicketID: got %q, want EDR-42", resp.TicketID)
	}
	if resp.System != "jira" {
		t.Errorf("System: got %q, want jira", resp.System)
	}
	if want := srv.URL + "/browse/EDR-42"; resp.TicketURL != want {
		t.Errorf("TicketURL: got %q, want %q", resp.TicketURL, want)
	}
	// リクエストの中身を検証
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/rest/api/3/issue" {
		t.Errorf("path: got %q, want /rest/api/3/issue", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("Authorization: got %q, want Basic ...", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", gotContentType)
	}
	// priority=critical → "Highest"
	fields, _ := payload["fields"].(map[string]interface{})
	prio, _ := fields["priority"].(map[string]interface{})
	if prio["name"] != "Highest" {
		t.Errorf("priority name: got %v, want Highest", prio["name"])
	}
}

func TestJira_CreateTicket_DefaultLabels(t *testing.T) {
	var payload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"EDR-1"}`))
	}))
	defer srv.Close()

	j := &JiraClient{baseURL: srv.URL, project: "EDR", client: srv.Client()}
	if _, err := j.CreateTicket(context.Background(), TicketRequest{Title: "t"}); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	fields := payload["fields"].(map[string]interface{})
	labels, _ := fields["labels"].([]interface{})
	if len(labels) != 2 || labels[0] != "edr" || labels[1] != "security" {
		t.Errorf("Labels なし時のデフォルトは [edr security] であるべき: got %v", labels)
	}
}

func TestJira_CreateTicket_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorMessages":["bad project"]}`))
	}))
	defer srv.Close()

	j := &JiraClient{baseURL: srv.URL, project: "EDR", client: srv.Client()}
	_, err := j.CreateTicket(context.Background(), TicketRequest{Title: "t"})
	if err == nil {
		t.Fatal("非201ステータスはエラーを返すべき")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("エラーにステータスコードが含まれるべき: %v", err)
	}
}

func TestJira_CreateTicket_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	j := &JiraClient{baseURL: srv.URL, project: "EDR", client: srv.Client()}
	_, err := j.CreateTicket(context.Background(), TicketRequest{Title: "t"})
	if err == nil {
		t.Fatal("不正なJSONレスポンスはパースエラーを返すべき")
	}
}

// ─── Jira: TestConnection ──────────────────────────────────────────────────────

func TestJira_TestConnection_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/myself" {
			t.Errorf("path: got %q, want /rest/api/3/myself", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accountId":"abc"}`))
	}))
	defer srv.Close()

	j := &JiraClient{baseURL: srv.URL, client: srv.Client()}
	if err := j.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: 予期しないエラー: %v", err)
	}
}

func TestJira_TestConnection_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	j := &JiraClient{baseURL: srv.URL, client: srv.Client()}
	if err := j.TestConnection(context.Background()); err == nil {
		t.Error("401 は接続テストエラーを返すべき")
	}
}

// ─── Jira: doRequest 低レベル ───────────────────────────────────────────────────

func TestJira_DoRequest_TrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// baseURL に末尾スラッシュがあっても二重にならないこと
	j := &JiraClient{baseURL: srv.URL + "/", client: srv.Client()}
	_, status, err := j.doRequest(context.Background(), http.MethodGet, "/rest/api/3/myself", nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status: got %d, want 200", status)
	}
	if gotPath != "/rest/api/3/myself" {
		t.Errorf("path: got %q（末尾スラッシュの二重化）", gotPath)
	}
}

func TestJira_DoRequest_NetworkError(t *testing.T) {
	// 即座に閉じたサーバに接続 → ネットワークエラー
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	j := &JiraClient{baseURL: url, client: &http.Client{}}
	_, _, err := j.doRequest(context.Background(), http.MethodGet, "/x", nil)
	if err == nil {
		t.Error("到達不能なサーバはエラーを返すべき")
	}
}

// ─── ServiceNow: CreateTicket ──────────────────────────────────────────────────

func TestServiceNow_CreateTicket_Success(t *testing.T) {
	var gotPath string
	var payload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"sys_id":"sid-9","number":"INC0012345"}}`))
	}))
	defer srv.Close()

	s := &ServiceNowClient{instanceURL: srv.URL, username: "admin", password: "p", table: "incident", client: srv.Client()}
	resp, err := s.CreateTicket(context.Background(), TicketRequest{Title: "t", Priority: "high", IncidentID: "INC-1"})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if resp.TicketID != "INC0012345" {
		t.Errorf("TicketID: got %q, want INC0012345", resp.TicketID)
	}
	if resp.System != "servicenow" {
		t.Errorf("System: got %q, want servicenow", resp.System)
	}
	if gotPath != "/api/now/table/incident" {
		t.Errorf("path: got %q", gotPath)
	}
	if payload["urgency"] != "2" { // high → 2
		t.Errorf("urgency: got %v, want 2", payload["urgency"])
	}
	if payload["u_edr_incident_id"] != "INC-1" {
		t.Errorf("u_edr_incident_id: got %v", payload["u_edr_incident_id"])
	}
}

func TestServiceNow_CreateTicket_NumberFallsBackToSysID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 も許容される
		_, _ = w.Write([]byte(`{"result":{"sys_id":"sid-only"}}`))
	}))
	defer srv.Close()

	s := &ServiceNowClient{instanceURL: srv.URL, table: "incident", client: srv.Client()}
	resp, err := s.CreateTicket(context.Background(), TicketRequest{Title: "t"})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if resp.TicketID != "sid-only" {
		t.Errorf("number 欠落時は sys_id にフォールバックすべき: got %q", resp.TicketID)
	}
}

func TestServiceNow_CreateTicket_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
	}))
	defer srv.Close()

	s := &ServiceNowClient{instanceURL: srv.URL, table: "incident", client: srv.Client()}
	_, err := s.CreateTicket(context.Background(), TicketRequest{Title: "t"})
	if err == nil {
		t.Fatal("500 はエラーを返すべき")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("エラーにステータスが含まれるべき: %v", err)
	}
}

func TestServiceNow_CreateTicket_EmptyTableDefaultsToIncident(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"number":"INC1"}}`))
	}))
	defer srv.Close()

	// table を空にしても incident にフォールバックする
	s := &ServiceNowClient{instanceURL: srv.URL, client: srv.Client()}
	if _, err := s.CreateTicket(context.Background(), TicketRequest{Title: "t"}); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if gotPath != "/api/now/table/incident" {
		t.Errorf("空 table は incident にフォールバックすべき: got %q", gotPath)
	}
}

// ─── ServiceNow: TestConnection ────────────────────────────────────────────────

func TestServiceNow_TestConnection_OK(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	s := &ServiceNowClient{instanceURL: srv.URL, table: "incident", client: srv.Client()}
	if err := s.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: 予期しないエラー: %v", err)
	}
	if !strings.Contains(gotQuery, "sysparm_limit=1") {
		t.Errorf("疎通確認は sysparm_limit=1 を付与すべき: got %q", gotQuery)
	}
}

func TestServiceNow_TestConnection_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := &ServiceNowClient{instanceURL: srv.URL, table: "incident", client: srv.Client()}
	if err := s.TestConnection(context.Background()); err == nil {
		t.Error("403 は接続テストエラーを返すべき")
	}
}
