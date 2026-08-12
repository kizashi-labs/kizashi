package soar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClients_HTTP points the Jira and ServiceNow clients at a local httptest
// server so their request-building + response-parsing paths (CreateTicket,
// TestConnection) run without any external network.
func TestClients_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "1", "key": "COV-1", "self": "x",
				"result": map[string]any{"sys_id": "abc", "number": "INC001", "short_description": "cov"},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{}})
	}))
	defer srv.Close()
	ctx := context.Background()
	req := TicketRequest{Title: "cov", Description: "d", Priority: "high", Labels: []string{"cov"}, IncidentID: "inc-1"}

	jira, err := NewClient("jira", map[string]interface{}{
		"url": srv.URL, "email": "cov@example.com", "api_token": "tok", "project": "COV",
	})
	if err != nil {
		t.Fatalf("NewClient jira: %v", err)
	}
	if _, err := jira.CreateTicket(ctx, req); err != nil {
		t.Fatalf("jira CreateTicket: %v", err)
	}
	_ = jira.TestConnection(ctx)

	sn, err := NewClient("servicenow", map[string]interface{}{
		"url": srv.URL, "username": "cov", "password": "pw", "table": "incident",
	})
	if err != nil {
		t.Fatalf("NewClient servicenow: %v", err)
	}
	if _, err := sn.CreateTicket(ctx, req); err != nil {
		t.Fatalf("servicenow CreateTicket: %v", err)
	}
	_ = sn.TestConnection(ctx)
}
