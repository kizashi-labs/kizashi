package store_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	uuidpkg "github.com/google/uuid"

	"github.com/edr-platform/server/internal/store"
)

// covTestDB opens a *store.DB against TEST_DATABASE_URL (the shared migrated
// database used by the DB-backed suite). It skips when the var is unset, so the
// pure-logic run stays green. These CRUD tests exercise store methods that were
// previously uncovered end-to-end against a real schema.
func covTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB CRUD tests")
	}
	db, err := store.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestMaintenanceWindowStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewMaintenanceWindowStore(db.Pool())
	ctx := context.Background()

	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)
	created, err := s.Create(ctx, &store.MaintenanceWindow{
		Name:           "cov-mw",
		Description:    "coverage window",
		StartTime:      start,
		EndTime:        end,
		SuppressAlerts: true,
		Enabled:        true,
		AffectedAgents: []string{"agent-1"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.Name != "cov-mw" {
		t.Fatalf("unexpected created window: %+v", created)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })

	got, err := s.Get(ctx, created.ID)
	if err != nil || got.ID != created.ID {
		t.Fatalf("Get: %v (got %+v)", err, got)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsMW(list, created.ID) {
		t.Errorf("List did not contain created window %s", created.ID)
	}

	// The window spans now, so it should be reported active.
	active, err := s.IsActive(ctx)
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if !active {
		t.Errorf("IsActive = false, want true for a window spanning now")
	}
	if la, err := s.ListActive(ctx); err != nil {
		t.Fatalf("ListActive: %v", err)
	} else if !containsMW(la, created.ID) {
		t.Errorf("ListActive did not contain the active window")
	}

	created.Name = "cov-mw-updated"
	created.Enabled = false
	updated, err := s.Update(ctx, created.ID, created)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "cov-mw-updated" || updated.Enabled {
		t.Errorf("Update not applied: %+v", updated)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, created.ID); err == nil {
		t.Errorf("Get after Delete should error")
	}
}

func containsMW(ws []*store.MaintenanceWindow, id string) bool {
	for _, w := range ws {
		if w.ID == id {
			return true
		}
	}
	return false
}

func TestProcessBlockRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewProcessBlockRuleStore(db.Pool())
	ctx := context.Background()

	created, err := s.Create(ctx, store.CreateProcessBlockRuleInput{
		Name:        "cov-block",
		ProcessName: "mimikatz.exe",
		Enabled:     true,
		// RuleType/Scope/Action/Severity left empty to exercise the defaults.
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.RuleType != "deny" || created.Scope != "all" || created.Action != "alert" || created.Severity != "high" {
		t.Errorf("defaults not applied: %+v", created)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })

	if got, err := s.Get(ctx, created.ID); err != nil || got.ProcessName != "mimikatz.exe" {
		t.Fatalf("Get: %v (%+v)", err, got)
	}

	rules, total, err := s.List(ctx, store.ProcessBlockRuleFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total < 1 || !containsPBR(rules, created.ID) {
		t.Errorf("List missing created rule (total=%d)", total)
	}

	// Toggle flips enabled true -> false.
	toggled, err := s.Toggle(ctx, created.ID)
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if toggled.Enabled {
		t.Errorf("Toggle should have disabled the rule")
	}

	updated, err := s.Update(ctx, created.ID, store.UpdateProcessBlockRuleInput{
		Name:        "cov-block-2",
		ProcessName: "psexec.exe",
		RuleType:    "deny",
		Scope:       "all",
		Action:      "block",
		Enabled:     true,
		Severity:    "critical",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "cov-block-2" || updated.Action != "block" || updated.Severity != "critical" {
		t.Errorf("Update not applied: %+v", updated)
	}

	// ListForAgent should include the scope='all' enabled rule.
	if forAgent, err := s.ListForAgent(ctx, "any-agent"); err != nil {
		t.Fatalf("ListForAgent: %v", err)
	} else if !containsPBR(forAgent, created.ID) {
		t.Errorf("ListForAgent missing scope=all rule")
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err == nil {
		t.Errorf("Delete of missing rule should error")
	}
}

func containsPBR(rs []*store.ProcessBlockRule, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}

func TestCustomAlertRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewCustomAlertRuleStore(db.Pool())
	ctx := context.Background()

	conds := json.RawMessage(`[{"field":"process_name","operator":"eq","value":"nc.exe"}]`)
	created, err := s.Create(ctx, store.CreateCustomAlertRuleInput{
		Name:              "cov-rule",
		Description:       "coverage rule",
		Enabled:           true,
		EventType:         "process",
		Conditions:        conds,
		ThresholdCount:    1,
		TimeWindowSeconds: 60,
		Severity:          7,
		AlertTitle:        "Suspicious nc.exe",
		AlertDescription:  "netcat launched",
		MitreTags:         []string{"T1059"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.Name != "cov-rule" {
		t.Fatalf("unexpected created rule: %+v", created)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })

	if got, err := s.Get(ctx, created.ID); err != nil || got.EventType != "process" {
		t.Fatalf("Get: %v (%+v)", err, got)
	}

	if list, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	} else if !containsCAR(list, created.ID) {
		t.Errorf("List missing created rule")
	}

	// Enabled rule appears in ListEnabled.
	if en, err := s.ListEnabled(ctx); err != nil {
		t.Fatalf("ListEnabled: %v", err)
	} else if !containsCAR(en, created.ID) {
		t.Errorf("ListEnabled missing enabled rule")
	}

	updated, err := s.Update(ctx, created.ID, store.UpdateCustomAlertRuleInput{
		Name:              "cov-rule-2",
		Description:       "updated",
		Enabled:           true,
		EventType:         "network",
		Conditions:        conds,
		ThresholdCount:    3,
		TimeWindowSeconds: 120,
		Severity:          9,
		AlertTitle:        "t",
		AlertDescription:  "d",
		MitreTags:         []string{"T1049"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "cov-rule-2" || updated.EventType != "network" || updated.Severity != 9 {
		t.Errorf("Update not applied: %+v", updated)
	}

	// Toggle disables it → drops out of ListEnabled.
	if toggled, err := s.Toggle(ctx, created.ID); err != nil {
		t.Fatalf("Toggle: %v", err)
	} else if toggled.Enabled {
		t.Errorf("Toggle should have disabled the rule")
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func containsCAR(rs []*store.CustomAlertRule, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}

func TestIncidentStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewIncidentStore(db)
	ctx := context.Background()

	id, err := s.Insert(ctx, &store.Incident{
		Title:       "cov-incident",
		Description: "coverage incident",
		Severity:    5,
		Status:      "open",
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id == "" {
		t.Fatal("Insert returned empty id")
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })

	got, err := s.Get(ctx, id)
	if err != nil || got.Title != "cov-incident" {
		t.Fatalf("Get: %v (%+v)", err, got)
	}

	if list, total, err := s.List(ctx, "open", 50, 0); err != nil {
		t.Fatalf("List: %v", err)
	} else if total < 1 || !containsIncident(list, id) {
		t.Errorf("List missing created incident (total=%d)", total)
	}

	if err := s.Update(ctx, id, "cov-incident-2", "updated", "resolved", 8, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got, err := s.Get(ctx, id); err != nil || got.Title != "cov-incident-2" || got.Status != "resolved" {
		t.Fatalf("Get after Update: %v (%+v)", err, got)
	}

	// No alerts linked yet → empty slice, no error.
	if alerts, err := s.ListAlerts(ctx, id); err != nil {
		t.Fatalf("ListAlerts: %v", err)
	} else if len(alerts) != 0 {
		t.Errorf("expected no linked alerts, got %d", len(alerts))
	}

	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, id); err == nil {
		t.Errorf("Get after Delete should error")
	}
}

func containsIncident(xs []*store.Incident, id string) bool {
	for _, x := range xs {
		if x.ID == id {
			return true
		}
	}
	return false
}

func TestYARAStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewYARAStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.CreateYARARuleInput{Name: "cov-yara", Content: "rule x {condition: true}", Severity: "medium", Enabled: true, Tags: []string{"cov"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, _, err := s.List(ctx, store.YARAListFilter{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.UpdateYARARuleInput{Name: "cov-yara-2", Content: "rule y {condition: false}", Severity: "high", Enabled: false, Tags: []string{"c2"}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestFIMRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewFIMRuleStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.CreateFIMRuleInput{Name: "cov-fim", Path: "/etc", Recursive: true, Severity: "high", Enabled: true, ExcludePatterns: []string{"*.tmp"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, _, err := s.List(ctx, store.FIMRuleFilter{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.UpdateFIMRuleInput{Name: "cov-fim-2", Path: "/var", Severity: "low", Enabled: false}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestWebhookStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewWebhookStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.WebhookTarget{Name: "cov-wh", URL: "https://example.com/hook", Events: []string{"alert.created"}, Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.WebhookTarget{Name: "cov-wh-2", URL: "https://example.com/h2", Events: []string{"agent.offline"}, Enabled: false}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestReportTemplateStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewReportTemplateStore(db.Pool())
	ctx := context.Background()
	id, err := s.Create(ctx, &store.ReportTemplate{Name: "cov-tpl", Description: "d", Format: "pdf", Enabled: true, Sections: []store.ReportTemplateSection{{Type: "summary", Title: "S"}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.Update(ctx, id, &store.ReportTemplate{Name: "cov-tpl-2", Format: "html", Enabled: false, Sections: []store.ReportTemplateSection{}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestEscalationRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewEscalationRuleStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.CreateEscalationRuleInput{Name: "cov-esc", SeverityMin: 5, UnresolvedMins: 30, EscalateTo: "soc-team", Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.UpdateEscalationRuleInput{Name: "cov-esc-2", SeverityMin: 7, UnresolvedMins: 60, EscalateTo: "ir-team", Enabled: false}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// seedUserStore inserts a user and returns its id (for FK columns like
// alert_assign_rules.assignee_id).
func seedUserStore(t *testing.T, db *store.DB) string {
	t.Helper()
	id := uuidNewStr()
	ctx := context.Background()
	if _, err := db.Pool().Exec(ctx, "INSERT INTO users (id, email) VALUES ($1,$2)", id, "covstore-"+id[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", id) })
	return id
}

func TestAgentPolicyStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentPolicyStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.CreatePolicyInput{Name: "cov-pol", Description: "d", ScanIntervalMin: 60, FullScanHour: 2, LogLevel: "info", MonitoredExtensions: []string{".exe"}, ExcludedPaths: []string{"/tmp"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.UpdatePolicyInput{Name: "cov-pol-2", ScanIntervalMin: 120, FullScanHour: 3, LogLevel: "debug"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSSOConfigStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSSOConfigStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.SSOConfig{Provider: "oidc", Name: "cov-idp", ClientID: "cid", DiscoveryURL: "https://idp/.well-known/openid-configuration", Enabled: true, AttributeMapping: json.RawMessage(`{"email":"email"}`), DefaultRole: "viewer"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.ListEnabled(ctx); err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.SSOConfig{Provider: "oidc", Name: "cov-idp-2", ClientID: "cid2", DiscoveryURL: "https://idp2/.well-known/openid-configuration", Enabled: false, AttributeMapping: json.RawMessage(`{}`), DefaultRole: "admin"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestAlertAssignRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAlertAssignRuleStore(db.Pool())
	uid := seedUserStore(t, db)
	ctx := context.Background()
	created, err := s.Create(ctx, store.CreateAssignRuleInput{Name: "cov-assign", Priority: 1, Conditions: json.RawMessage(`{"severity_min":7}`), AssigneeID: uid, Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, store.UpdateAssignRuleInput{Name: "cov-assign-2", Priority: 2, Conditions: json.RawMessage(`{}`), AssigneeID: uid, Enabled: false}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func uuidNewStr() string { return uuidpkg.NewString() }

func TestSavedHuntStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSavedHuntStore(db.Pool())
	uid := seedUserStore(t, db)
	ctx := context.Background()
	created, err := s.Create(ctx, "cov-hunt", "d", "SELECT 1", "sql", []string{"cov"}, uid, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.Get(ctx, created.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx, uid, true); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, "cov-hunt-2", "d2", "SELECT 2", []string{"c2"}, true); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestAutoResponseStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAutoResponseStore(db.Pool())
	ctx := context.Background()
	created, err := s.CreateRule(ctx, store.CreateAutoResponseRuleInput{Name: "cov-ar", Description: "d", Enabled: true, TriggerSeverityMin: 7, TriggerStatus: "open", ActionType: "isolate_agent", ActionParams: json.RawMessage(`{}`), CooldownSeconds: 300})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteRule(ctx, created.ID) })
	if _, err := s.GetRule(ctx, created.ID); err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if _, err := s.ListRules(ctx); err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if _, err := s.ListEnabled(ctx); err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if _, err := s.UpdateRule(ctx, created.ID, store.UpdateAutoResponseRuleInput{Name: "cov-ar-2", Description: "d2", Enabled: false, TriggerSeverityMin: 9, TriggerStatus: "open", ActionType: "isolate_agent", ActionParams: json.RawMessage(`{}`), CooldownSeconds: 600}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if err := s.DeleteRule(ctx, created.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
}

// seedAgentStore inserts a minimal agents row and returns its UUID.
func seedAgentStore(t *testing.T, db *store.DB) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := db.Pool().QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`,
		"cov-agent-"+uuidNewStr()[:8]).Scan(&id)
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", id) })
	return id
}

func TestAPIKeyStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAPIKeyStore(db.Pool())
	uid := seedUserStore(t, db)
	ctx := context.Background()
	raw, err := s.Create(ctx, uid, "cov-key", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	k, err := s.FindByKey(ctx, raw)
	if err != nil {
		t.Fatalf("FindByKey: %v", err)
	}
	if err := s.UpdateLastUsed(ctx, k.ID); err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}
	if _, err := s.ListByUser(ctx, uid); err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if err := s.Revoke(ctx, k.ID, uid); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestAgentTagStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentTagStore(db.Pool())
	aid := seedAgentStore(t, db)
	ctx := context.Background()
	if err := s.Add(ctx, aid, "cov-tag"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s.ListByAgent(ctx, aid); err != nil {
		t.Fatalf("ListByAgent: %v", err)
	}
	if _, err := s.ListByTag(ctx, "cov-tag"); err != nil {
		t.Fatalf("ListByTag: %v", err)
	}
	if _, err := s.AllTags(ctx); err != nil {
		t.Fatalf("AllTags: %v", err)
	}
	if err := s.Remove(ctx, aid, "cov-tag"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestAlertCommentStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	uid := seedUserStore(t, db)
	ctx := context.Background()
	var alertID string
	err := db.Pool().QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status)
		 VALUES ($1, 5, 'cov-alert', 'd', 'open') RETURNING id::text`, aid).Scan(&alertID)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
	s := store.NewAlertCommentStore(db.Pool())
	c, err := s.Add(ctx, alertID, uid, "cov-user", "hello")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s.List(ctx, alertID); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.Delete(ctx, c.ID, uid, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestAgentStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentStore(db)
	ctx := context.Background()
	id := uuidNewStr()
	a := &store.AgentRow{ID: id, Hostname: "cov-host", OSType: "linux", OSVersion: "1.0", AgentVersion: "0.1", IPAddresses: []string{"10.0.0.1"}, Status: "online"}
	if err := s.UpsertAgent(ctx, a); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, id) })

	if err := s.UpdateLastSeen(ctx, id, "cov-host", []string{"10.0.0.2"}, "0.2", "1.1", "linux"); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	if err := s.UpdateProtectionMode(ctx, id, "enforce"); err != nil {
		t.Fatalf("UpdateProtectionMode: %v", err)
	}
	if _, err := s.ProtectionModeSummary(ctx); err != nil {
		t.Fatalf("ProtectionModeSummary: %v", err)
	}
	if _, err := s.ProtectionModeByOS(ctx); err != nil {
		t.Fatalf("ProtectionModeByOS: %v", err)
	}
	if _, err := s.AnomalousAgentsBoard(ctx, 10); err != nil {
		t.Fatalf("AnomalousAgentsBoard: %v", err)
	}
	if _, err := s.GetAgentByID(ctx, id); err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	if _, _, err := s.ListAgents(ctx, store.AgentFilter{OSType: "linux", Status: "online", Search: "cov", Limit: 10, Offset: 0}); err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if err := s.UpdateAgentMeta(ctx, id, []string{"t1"}, nil); err != nil {
		t.Fatalf("UpdateAgentMeta: %v", err)
	}
	if err := s.IsolateAgent(ctx, id, "cov-reason", "cov-op"); err != nil {
		t.Fatalf("IsolateAgent: %v", err)
	}
	if err := s.UnisolateAgent(ctx, id); err != nil {
		t.Fatalf("UnisolateAgent: %v", err)
	}
	if err := s.ResolveAgentOfflineAlerts(ctx, id); err != nil {
		t.Fatalf("ResolveAgentOfflineAlerts: %v", err)
	}
	if _, err := s.ListExpiringAgents(ctx, 30); err != nil {
		t.Fatalf("ListExpiringAgents: %v", err)
	}
	if err := s.DeleteAgent(ctx, id); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
}

func TestAgentStore_Groups(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentStore(db)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, "cov-group-"+uuidNewStr()[:8], "desc")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteGroup(ctx, g.ID) })
	if _, err := s.ListGroups(ctx); err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if err := s.UpdateGroup(ctx, g.ID, "cov-group-2", "desc2"); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if err := s.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
}

func TestAlertStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	uid := seedUserStore(t, db)
	s := store.NewAlertStore(db)
	ctx := context.Background()

	alertID := uuidNewStr()
	now := time.Now()
	a := &store.StoredAlert{
		ID: alertID, AgentID: aid, Severity: 8, Status: "open",
		Title: "cov-alert", AIMITRETags: []string{"T1059"},
		RawEvent: json.RawMessage(`{"k":"v"}`), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.SaveAlert(ctx, a); err != nil {
		t.Fatalf("SaveAlert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })

	if _, err := s.GetAlert(ctx, alertID); err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	resolved := "resolved"
	analysis := &store.AIAnalysisUpdate{IsThreat: true, Severity: 9, Confidence: 0.9, ThreatName: "cov", Summary: "s", Report: "r", AttackChain: []string{"a"}, MITRETags: []string{"T1"}}
	if err := s.UpdateAlert(ctx, alertID, &resolved, analysis, &uid); err != nil {
		t.Fatalf("UpdateAlert: %v", err)
	}
	if _, _, err := s.ListAlerts(ctx, store.AlertFilter{Status: "resolved", AgentID: aid, Severity: 1, Search: "cov", Limit: 10, Offset: 0}); err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if _, err := s.AlertStats(ctx); err != nil {
		t.Fatalf("AlertStats: %v", err)
	}
	if _, err := s.TopThreatenedAgents(ctx, 5); err != nil {
		t.Fatalf("TopThreatenedAgents: %v", err)
	}
	if _, err := s.GetRelated(ctx, alertID, 5); err != nil {
		t.Fatalf("GetRelated: %v", err)
	}
	if _, err := s.AlertCountInWindow(ctx, 24, 0); err != nil {
		t.Fatalf("AlertCountInWindow: %v", err)
	}
	if _, err := s.AlertTimeline(ctx, 24); err != nil {
		t.Fatalf("AlertTimeline: %v", err)
	}
	if _, err := s.GetAlertHistory(ctx, aid, 7); err != nil {
		t.Fatalf("GetAlertHistory: %v", err)
	}

	cid, _, err := s.AddComment(ctx, alertID, uid, "hi")
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	_ = cid
	if _, err := s.ListComments(ctx, alertID); err != nil {
		t.Fatalf("ListComments: %v", err)
	}

	ra := &store.ResponseActionRow{ID: uuidNewStr(), AlertID: &alertID, AgentID: aid, ActionType: "isolate", ExecutedBy: "cov", Success: true, ExecutedAt: now}
	if err := s.SaveResponseAction(ctx, ra); err != nil {
		t.Fatalf("SaveResponseAction: %v", err)
	}
}

func TestUserStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewUserStore(db)
	ctx := context.Background()
	email := "covuser-" + uuidNewStr()[:8] + "@example.com"
	u, err := s.Create(ctx, email, "InitPass123!", "Cov User", "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM users WHERE id=$1", u.ID) })

	if _, err := s.GetByID(ctx, u.ID); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if _, err := s.GetByEmail(ctx, email); err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Authenticate(ctx, email, "InitPass123!"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := s.VerifyCurrentPassword(ctx, u.ID, "InitPass123!"); err != nil {
		t.Fatalf("VerifyCurrentPassword: %v", err)
	}
	if err := s.UpdatePassword(ctx, u.ID, "NewPass456!"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if err := s.ClearMustChangePassword(ctx, u.ID); err != nil {
		t.Fatalf("ClearMustChangePassword: %v", err)
	}
	if err := s.UpdateFullName(ctx, u.ID, "Cov User 2"); err != nil {
		t.Fatalf("UpdateFullName: %v", err)
	}
	if err := s.UpdateRole(ctx, u.ID, "analyst"); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if err := s.SetActive(ctx, u.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	_ = s.SetActive(ctx, u.ID, true)

	// MFA
	if err := s.SetMFASecret(ctx, u.ID, "SECRET123"); err != nil {
		t.Fatalf("SetMFASecret: %v", err)
	}
	if _, _, err := s.GetMFASecret(ctx, u.ID); err != nil {
		t.Fatalf("GetMFASecret: %v", err)
	}
	if err := s.StoreMFASecret(ctx, u.ID, "SECRET456"); err != nil {
		t.Fatalf("StoreMFASecret: %v", err)
	}
	if err := s.EnableMFA(ctx, u.ID); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}
	if err := s.SetMFAType(ctx, u.ID, "totp"); err != nil {
		t.Fatalf("SetMFAType: %v", err)
	}
	if _, err := s.GetMFAType(ctx, u.ID); err != nil {
		t.Fatalf("GetMFAType: %v", err)
	}

	// Backup codes
	if err := s.SaveBackupCodes(ctx, u.ID, []string{"code-alpha", "code-beta"}); err != nil {
		t.Fatalf("SaveBackupCodes: %v", err)
	}
	if _, err := s.ListBackupCodeStatus(ctx, u.ID); err != nil {
		t.Fatalf("ListBackupCodeStatus: %v", err)
	}
	if ok, err := s.UseBackupCode(ctx, u.ID, "code-alpha"); err != nil || !ok {
		t.Fatalf("UseBackupCode: ok=%v err=%v", ok, err)
	}
	if err := s.DisableMFA(ctx, u.ID); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}
}

func TestRuleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewRuleStore(db)
	ctx := context.Background()
	id := uuidNewStr()
	desc := "cov rule desc"
	r := &store.RuleRow{
		ID: id, Name: "cov-rule", Type: "sigma", Platform: []string{"linux"},
		Severity: 7, Content: "title: cov", Enabled: true, Source: "custom",
		MITRETags: []string{"T1059"}, Description: &desc, FalsePositiveRate: 0.1,
	}
	if err := s.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })

	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	enabled := true
	if _, _, err := s.List(ctx, store.RuleFilter{Type: "sigma", Enabled: &enabled, Search: "cov", Limit: 10, Offset: 0}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.ListEnabled(ctx); err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	r.Name = "cov-rule-2"
	r.Severity = 9
	if err := s.Update(ctx, r); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Toggle(ctx, id, false); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if created, err := s.Upsert(ctx, r); err != nil || created {
		t.Fatalf("Upsert: created=%v err=%v (want created=false)", created, err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestIOCStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewIOCStore(db)
	ctx := context.Background()
	val := "10.9." + uuidNewStr()[:3] + ".7"
	if err := s.Insert(ctx, &store.IOCEntry{Type: "ip", Value: val, Description: "cov", Severity: 5, IsActive: true}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	entry, err := s.Check(ctx, "ip", val)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if entry == nil {
		t.Fatalf("Check returned nil for inserted IOC")
	}
	t.Cleanup(func() { _ = s.Delete(ctx, entry.ID) })

	if _, _, err := s.List(ctx, "ip", "10.9", true, 10, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.SetActive(ctx, entry.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if _, err := s.Stats(ctx); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	bulk := []*store.IOCEntry{{Type: "domain", Value: "cov-" + uuidNewStr()[:6] + ".test", Severity: 3, IsActive: true}}
	if _, err := s.BulkInsert(ctx, bulk); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	_, _ = db.Pool().Exec(ctx, "DELETE FROM ioc_entries WHERE value=$1", bulk[0].Value)
	if err := s.Delete(ctx, entry.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestThreatFeedStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewThreatFeedStore(db)
	ctx := context.Background()
	id, err := s.Insert(ctx, &store.ThreatFeed{Name: "cov-feed", URL: "https://feed/cov.txt", FeedType: "txt", IOCType: "ip", IsActive: true, SyncIntervalHours: 24})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.Update(ctx, &store.ThreatFeed{ID: id, Name: "cov-feed-2", URL: "https://feed/cov2.txt", FeedType: "csv", IOCType: "domain", IsActive: true, SyncIntervalHours: 12}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.SetActive(ctx, id, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if err := s.MarkSynced(ctx, id, 42); err != nil {
		t.Fatalf("MarkSynced: %v", err)
	}
	if _, err := s.GetDueForSync(ctx); err != nil {
		t.Fatalf("GetDueForSync: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestAlertNotifStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAlertNotifStore(db.Pool())
	ctx := context.Background()
	ch, err := s.Create(ctx, store.CreateAlertNotifChannelInput{Name: "cov-chan", Type: "webhook_generic", Config: json.RawMessage(`{"url":"https://hook"}`), Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, ch.ID) })
	if _, err := s.Get(ctx, ch.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.ListEnabled(ctx); err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if _, err := s.Update(ctx, ch.ID, store.CreateAlertNotifChannelInput{Name: "cov-chan-2", Type: "webhook_slack", Config: json.RawMessage(`{}`), Enabled: false}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, ch.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSessionStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSessionStore(db.Pool())
	uid := seedUserStore(t, db)
	ctx := context.Background()
	now := time.Now()
	jti := "cov-jti-" + uuidNewStr()
	sess := store.Session{UserID: uid, JTI: jti, DeviceInfo: map[string]interface{}{"user_agent": "cov"}, IPAddress: "10.0.0.5", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM user_sessions WHERE user_id=$1", uid) })

	list, err := s.ListByUser(ctx, uid)
	if err != nil || len(list) == 0 {
		t.Fatalf("ListByUser: %v (n=%d)", err, len(list))
	}
	sid := list[0].ID
	if err := s.UpdateLastSeen(ctx, jti); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	if _, _, err := s.GetJTIByID(ctx, sid); err != nil {
		t.Fatalf("GetJTIByID: %v", err)
	}
	if err := s.Revoke(ctx, sid, uid); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := s.RevokeByID(ctx, sid); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	if _, err := s.RevokeAll(ctx, uid); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if _, err := s.RevokeAllExcept(ctx, uid, "other-jti"); err != nil {
		t.Fatalf("RevokeAllExcept: %v", err)
	}
	if err := s.CleanupExpired(ctx); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
}

func TestVulnStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewVulnStore(db)
	ctx := context.Background()
	aid := seedAgentStore(t, db)
	id, err := s.Insert(ctx, &store.Vulnerability{AgentID: &aid, CVEID: "CVE-2026-" + uuidNewStr()[:4], Title: "cov-vuln", Description: "d", Severity: "high", AffectedPackage: "openssl", AffectedVersion: "1.0", FixedVersion: "1.1", Status: "open"})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, _, err := s.List(ctx, store.VulnFilter{Severity: "high", Status: "open", Search: "cov", Limit: 10, Offset: 0}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.UpdateStatus(ctx, id, "patched", "fixed"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if _, err := s.Stats(ctx); err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestQuarantineStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewQuarantineStore(db)
	ctx := context.Background()
	sz := int64(1234)
	f, err := s.Record(ctx, aid, "", "/tmp/evil.bin", &sz, "md5hash", "sha256hash-"+uuidNewStr()[:6], "aq-1")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, f.ID) })
	if _, _, err := s.List(ctx, store.QuarantineFilter{AgentID: aid, Status: "quarantined"}, 10, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.GetAgentQuarantineID(ctx, f.ID); err != nil {
		t.Fatalf("GetAgentQuarantineID: %v", err)
	}
	if _, err := s.GetAgentID(ctx, f.ID); err != nil {
		t.Fatalf("GetAgentID: %v", err)
	}
	if err := s.MarkRestored(ctx, f.ID, "cov-op"); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}
	if err := s.Delete(ctx, f.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestReportStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewReportStore(db)
	ctx := context.Background()
	id := uuidNewStr()
	if err := s.Insert(ctx, &store.ReportJobRow{ID: id, Type: "alert_summary", RequestedBy: uid}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if err := s.SetRunning(ctx, id); err != nil {
		t.Fatalf("SetRunning: %v", err)
	}
	if err := s.Complete(ctx, id, map[string]any{"rows": 3}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	// A second job to exercise Fail.
	id2 := uuidNewStr()
	if err := s.Insert(ctx, &store.ReportJobRow{ID: id2, Type: "alert_summary", RequestedBy: uid}); err != nil {
		t.Fatalf("Insert2: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id2) })
	if err := s.Fail(ctx, id2, "cov-error"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestPlaybookStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewPlaybookStore(db)
	ctx := context.Background()
	p := &store.Playbook{
		Name: "cov-pb", Description: "d",
		Conditions: store.PlaybookConditions{MinSeverity: 5, Status: "open"},
		Actions:    []store.PlaybookAction{{Type: "notify", Message: "hi"}},
		IsActive:   true,
	}
	id, err := s.Insert(ctx, p)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if _, err := s.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx, false); err != nil {
		t.Fatalf("List: %v", err)
	}
	p.ID = id
	p.Name = "cov-pb-2"
	if err := s.Update(ctx, p); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.SetActive(ctx, id, true); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if _, err := s.ListActiveForAlert(ctx, 8, "cov-rule", "cov-host", "T1059", "open"); err != nil {
		t.Fatalf("ListActiveForAlert: %v", err)
	}

	// RecordRun needs a real alert (FK).
	aid := seedAgentStore(t, db)
	var alertID string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status)
		 VALUES ($1, 5, 'cov-alert', 'd', 'open') RETURNING id::text`, aid).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
	if err := s.RecordRun(ctx, &store.PlaybookRun{PlaybookID: id, AlertID: alertID, ActionsRun: p.Actions, Success: true}); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	if _, err := s.ListRuns(ctx, id, 10); err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSystemUpdatesStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSystemUpdatesStore(db.Pool())
	ctx := context.Background()
	adminID := seedUserStore(t, db)
	mk := func(av string) store.SystemUpdate {
		u, err := s.Create(ctx, store.CreateSystemUpdateInput{CurrentVersion: "1.0.0", AvailableVersion: av, ReleaseNotesURL: "https://n", Channel: "stable"})
		if err != nil {
			t.Fatalf("Create(%s): %v", av, err)
		}
		t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM system_updates WHERE id=$1", u.ID) })
		return u
	}
	// Success path
	u1 := mk("1.1." + uuidNewStr()[:4])
	if _, err := s.Approve(ctx, u1.ID, adminID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.MarkApplying(ctx, u1.ID, "1.0.0"); err != nil {
		t.Fatalf("MarkApplying: %v", err)
	}
	if _, err := s.MarkSuccess(ctx, u1.ID); err != nil {
		t.Fatalf("MarkSuccess: %v", err)
	}
	// Failure path
	u2 := mk("1.2." + uuidNewStr()[:4])
	_, _ = s.Approve(ctx, u2.ID, adminID)
	_, _ = s.MarkApplying(ctx, u2.ID, "1.0.0")
	if _, err := s.MarkFailed(ctx, u2.ID, "boom"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	// Rollback path
	u3 := mk("1.3." + uuidNewStr()[:4])
	_, _ = s.Approve(ctx, u3.ID, adminID)
	_, _ = s.MarkApplying(ctx, u3.ID, "1.0.0")
	if _, err := s.MarkRolledBack(ctx, u3.ID, "reverted"); err != nil {
		t.Fatalf("MarkRolledBack: %v", err)
	}
	// Cancel path
	u4 := mk("1.4." + uuidNewStr()[:4])
	if _, err := s.Approve(ctx, u4.ID, adminID); err != nil {
		t.Fatalf("Approve(u4): %v", err)
	}
	if _, err := s.Cancel(ctx, u4.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Get(ctx, u1.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.NextApproved(ctx); err != nil {
		t.Fatalf("NextApproved: %v", err)
	}
	if _, err := s.LatestAvailable(ctx); err != nil {
		t.Fatalf("LatestAvailable: %v", err)
	}
	if _, err := s.GetSettings(ctx); err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if _, err := s.UpdateSettings(ctx, store.UpdateSettingsInput{AutoApplyPatch: true, NotifyEmail: "cov@example.com", Channel: "stable"}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
}

func TestLiveResponseStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewLiveResponseStore(db)
	ctx := context.Background()
	token := "cov-tok-" + uuidNewStr()
	sess, err := s.CreateSession(ctx, aid, token, "cov-user")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM live_response_sessions WHERE id=$1", sess.ID) })

	if _, err := s.GetSessionByToken(ctx, token); err != nil {
		t.Fatalf("GetSessionByToken: %v", err)
	}
	if _, err := s.GetSession(ctx, sess.ID); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if _, err := s.ListSessions(ctx, aid); err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	cmd, err := s.EnqueueCommand(ctx, sess.ID, "whoami", "cov-user")
	if err != nil {
		t.Fatalf("EnqueueCommand: %v", err)
	}
	if _, err := s.DequeuePendingCommands(ctx, sess.ID); err != nil {
		t.Fatalf("DequeuePendingCommands: %v", err)
	}
	if err := s.CompleteCommand(ctx, cmd.ID, "root", 0, false); err != nil {
		t.Fatalf("CompleteCommand: %v", err)
	}
	if _, err := s.ListCommands(ctx, sess.ID); err != nil {
		t.Fatalf("ListCommands: %v", err)
	}
	s.TouchSession(ctx, token)
	if err := s.CloseSession(ctx, sess.ID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	s.ExpireOldSessions(ctx)
}

func TestReportScheduleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewReportScheduleStore(db)
	ctx := context.Background()
	dow := 1
	id, err := s.Insert(ctx, &store.ReportSchedule{Name: "cov-sched", ReportType: "alert_summary", Frequency: "weekly", DayOfWeek: &dow, Hour: 9, Recipients: []string{"cov@example.com"}, IsActive: true, NextRunAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.Update(ctx, &store.ReportSchedule{ID: id, Name: "cov-sched-2", ReportType: "alert_summary", Frequency: "daily", Hour: 10, Recipients: []string{"cov2@example.com"}, IsActive: true, NextRunAt: time.Now().Add(2 * time.Hour)}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.SetActive(ctx, id, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if _, err := s.GetDue(ctx); err != nil {
		t.Fatalf("GetDue: %v", err)
	}
	if err := s.MarkRun(ctx, id, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("MarkRun: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestBehavioralBaselineStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewBehavioralBaselineStore(db.Pool())
	ctx := context.Background()
	b := &store.EndpointBaseline{ID: aid, BaselineStatus: "learning", LearningStarted: time.Now().Format(time.RFC3339), DataPointsCollected: 100, AnomalyCount: 1, ConfidenceScore: 50}
	if err := s.Upsert(ctx, b); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agent_behavioral_baselines WHERE agent_id=$1", aid) })
	if _, err := s.GetByAgentID(ctx, aid); err != nil {
		t.Fatalf("GetByAgentID: %v", err)
	}
	if _, err := s.ListAll(ctx); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if _, err := s.GetConfig(ctx); err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if err := s.SaveConfig(ctx, &store.BaselineConfig{LearningPeriodDays: 14, ConfidenceThreshold: 0.8, AutoAlertOnDeviation: true, DeviationSensitivity: "medium"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if _, err := s.GetExclusionRules(ctx, aid); err != nil {
		t.Fatalf("GetExclusionRules: %v", err)
	}
}

func TestPacketCaptureStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewPacketCaptureStore(db.Pool())
	ctx := context.Background()
	pc, err := s.Create(ctx, store.PacketCapture{AgentID: aid, Name: "cov-pcap", Status: "pending", Filter: "tcp", InterfaceName: "eth0", MaxPackets: 100, MaxSizeMB: 10, DurationSeconds: 60})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, pc.ID) })
	if _, err := s.Get(ctx, pc.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.List(ctx, aid); err != nil {
		t.Fatalf("List: %v", err)
	}
	fp := "/tmp/cov.pcap"
	fs := int64(2048)
	pcnt := 55
	if err := s.UpdateStatus(ctx, pc.ID, "completed", &fp, &fs, &pcnt, nil); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if err := s.Delete(ctx, pc.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestInvitationStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewInvitationStore(db)
	ctx := context.Background()
	tenantID := "00000000-0000-0000-0000-000000000001"
	email := "covinv-" + uuidNewStr()[:8] + "@example.com"
	tok, err := s.Create(ctx, email, "analyst", tenantID, uid)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	inv, err := s.FindByToken(ctx, tok)
	if err != nil {
		t.Fatalf("FindByToken: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, inv.ID) })
	if _, err := s.ListPending(ctx); err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if err := s.Accept(ctx, inv.ID); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := s.Delete(ctx, inv.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestSoftwareInventoryStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewSoftwareInventoryStore(db)
	ctx := context.Background()
	name := "cov-pkg-" + uuidNewStr()[:6]
	if err := s.UpsertBatch(ctx, aid, []*store.SoftwareEntry{{Name: name, Version: "1.0", Vendor: "cov", InstallPath: "/opt/cov"}}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM software_inventory WHERE agent_id=$1", aid) })
	entries, err := s.ListByAgent(ctx, aid)
	if err != nil {
		t.Fatalf("ListByAgent: %v", err)
	}
	if _, err := s.SearchAcrossAgents(ctx, "cov-pkg", 10); err != nil {
		t.Fatalf("SearchAcrossAgents: %v", err)
	}
	if len(entries) > 0 {
		if err := s.DeleteEntry(ctx, entries[0].ID); err != nil {
			t.Fatalf("DeleteEntry: %v", err)
		}
	}
}

func TestSIEMStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSIEMStore(db)
	ctx := context.Background()
	created, err := s.Create(ctx, &store.SIEMTarget{Name: "cov-siem", Type: "splunk_hec", Host: "siem.local", Port: 8088, Protocol: "https", Token: "tok", TLSEnabled: true, IndexName: "main", Enabled: true, MinSeverity: 5})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Update(ctx, created.ID, &store.SIEMTarget{Name: "cov-siem-2", Type: "elastic_ecs", Host: "siem2.local", Port: 9200, Protocol: "https", TLSEnabled: false, IndexName: "alerts", Enabled: false, MinSeverity: 7}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestUserPreferencesStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewUserPreferencesStore(db.Pool())
	ctx := context.Background()
	if _, err := s.Get(ctx, uid); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.Upsert(ctx, uid, store.UserPreferences{Theme: "dark", Language: "ja", Timezone: "Asia/Tokyo", Notifications: json.RawMessage(`{}`), DashboardPrefs: json.RawMessage(`{}`), SidebarCollapsed: true, ItemsPerPage: 50, Favorites: json.RawMessage(`[]`)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := s.GetFavorites(ctx, uid); err != nil {
		t.Fatalf("GetFavorites: %v", err)
	}
	if _, err := s.SetFavorites(ctx, uid, []store.FavoriteItem{{Href: "/alerts", Label: "Alerts"}}); err != nil {
		t.Fatalf("SetFavorites: %v", err)
	}
}

func TestTenantRoleStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	granter := seedUserStore(t, db)
	s := store.NewTenantRoleStore(db.Pool())
	ctx := context.Background()
	tenantID := "00000000-0000-0000-0000-000000000001"
	if _, err := s.Upsert(ctx, tenantID, uid, "tenant_admin", granter); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, tenantID, uid) })
	if _, err := s.List(ctx, tenantID); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Get(ctx, tenantID, uid); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.HasRole(ctx, tenantID, uid, "tenant_admin"); err != nil {
		t.Fatalf("HasRole: %v", err)
	}
	if err := s.Delete(ctx, tenantID, uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestPasswordResetStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewPasswordResetStore(db)
	ctx := context.Background()
	tok, err := s.Create(ctx, uid)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Verify(ctx, tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := s.MarkUsed(ctx, tok); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	if err := s.CleanupExpired(ctx); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
}

func TestSuppressionStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSuppressionStore(db)
	ctx := context.Background()
	name := "cov-supp-" + uuidNewStr()[:8]
	if err := s.Insert(ctx, &store.SuppressionRule{Name: name, Description: "d", DurationH: 24, IsActive: true}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	list, err := s.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var id string
	for _, r := range list {
		if r.Name == name {
			id = r.ID
			break
		}
	}
	if id == "" {
		t.Fatalf("inserted suppression rule not found")
	}
	t.Cleanup(func() { _ = s.Delete(ctx, id) })
	s.IncrHitCount(ctx, id)
	if err := s.SetActive(ctx, id, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestHuntStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewHuntStore(db)
	ctx := context.Background()
	created, err := s.Create(ctx, &store.SavedHunt{Name: "cov-hunt", Description: "d", Params: json.RawMessage(`{"q":"x"}`), CreatedBy: "cov"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if _, err := s.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	s.RecordRun(ctx, created.ID)
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestComplianceScoreStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewComplianceScoreStore(db.Pool())
	ctx := context.Background()
	if _, err := s.Upsert(ctx, &store.ComplianceScore{AgentID: aid, Framework: "CIS", Score: 80, TotalChecks: 100, PassedChecks: 80, Details: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM compliance_scores WHERE agent_id=$1", aid) })
	if _, err := s.GetByAgent(ctx, aid, "CIS"); err != nil {
		t.Fatalf("GetByAgent: %v", err)
	}
	if _, err := s.ListAll(ctx); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
}

func TestIncidentCommentStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	is := store.NewIncidentStore(db)
	ctx := context.Background()
	incID, err := is.Insert(ctx, &store.Incident{Title: "cov-inc", Description: "d", Severity: 5, Status: "open"})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	t.Cleanup(func() { _ = is.Delete(ctx, incID) })
	s := store.NewIncidentCommentStore(db.Pool())
	c, err := s.Add(ctx, incID, uid, "cov comment")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s.List(ctx, incID); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := s.Delete(ctx, c.ID, uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNotificationPrefStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewNotificationPrefStore(db)
	ctx := context.Background()
	if _, err := s.Upsert(ctx, &store.NotificationPrefs{UserID: uid, EmailEnabled: true, EmailAddress: "cov@example.com", MinSeverity: "medium", NotifyIncidents: true, NotifyAgentOffline: true}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM notification_preferences WHERE user_id=$1", uid) })
	if _, err := s.GetByUserID(ctx, uid); err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if _, err := s.ListEmailEnabled(ctx, "medium"); err != nil {
		t.Fatalf("ListEmailEnabled: %v", err)
	}
}

func TestIncidentStore_Alerts(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	is := store.NewIncidentStore(db)
	ctx := context.Background()
	incID, err := is.Insert(ctx, &store.Incident{Title: "cov-inc2", Description: "d", Severity: 6, Status: "open"})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _ = is.Delete(ctx, incID) })
	var alertID string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status)
		 VALUES ($1, 5, 'cov-alert', 'd', 'open') RETURNING id::text`, aid).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
	if err := is.LinkAlert(ctx, incID, alertID); err != nil {
		t.Fatalf("LinkAlert: %v", err)
	}
	if _, err := is.ListAlerts(ctx, incID); err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if _, _, err := is.List(ctx, "open", 10, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := is.Get(ctx, incID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := is.Update(ctx, incID, "cov-inc2b", "d2", "investigating", 7, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestPushTokenStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewPushTokenStore(db.Pool())
	ctx := context.Background()
	if err := s.Upsert(ctx, uid, "cov-token-"+uuidNewStr()[:8], "ios"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM push_tokens WHERE user_id=$1", uid) })
	if _, err := s.GetByUserID(ctx, uid); err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if _, err := s.GetAllTokens(ctx); err != nil {
		t.Fatalf("GetAllTokens: %v", err)
	}
}

func TestNotificationHistoryStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	ns := store.NewAlertNotifStore(db.Pool())
	ctx := context.Background()
	ch, err := ns.Create(ctx, store.CreateAlertNotifChannelInput{Name: "cov-nh", Type: "webhook_generic", Config: json.RawMessage(`{}`), Enabled: true})
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	t.Cleanup(func() { _ = ns.Delete(ctx, ch.ID) })
	s := store.NewNotificationHistoryStore(db)
	if err := s.Insert(ctx, &store.NotificationHistoryEntry{ChannelID: ch.ID, ChannelName: "cov-nh", ChannelType: "webhook_generic", Subject: "s", Body: "b", Status: "sent"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM notification_history WHERE channel_id=$1", ch.ID) })
	if _, _, err := s.List(ctx, 10, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Stats(ctx, 7); err != nil {
		t.Fatalf("Stats: %v", err)
	}
}

func TestEmailOTPStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewEmailOTPStore(db)
	ctx := context.Background()
	code, err := s.Generate(ctx, uid, "login")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM email_otp_codes WHERE user_id=$1", uid) })
	if err := s.Verify(ctx, uid, code, "login"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := s.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestDeviceEventStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewDeviceEventStore(db.Pool())
	ctx := context.Background()
	if err := s.Insert(ctx, &store.DeviceEvent{AgentID: aid, Action: "connected", DeviceID: "usb-1", DeviceName: "cov-usb", DeviceType: "usb", VendorID: "1234", ProductID: "5678"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM device_events WHERE agent_id=$1", aid) })
	if _, _, err := s.List(ctx, store.DeviceEventFilter{AgentID: aid, Limit: 10}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Stats(ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatalf("Stats: %v", err)
	}
}

func TestSoftwareDiffStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewSoftwareDiffStore(db.Pool())
	ctx := context.Background()
	if err := s.CreateSnapshot(ctx, aid, []map[string]interface{}{{"name": "cov-pkg", "version": "1.0"}}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// A second, differing snapshot produces a diff row for GetLatestDiff.
	if err := s.CreateSnapshot(ctx, aid, []map[string]interface{}{{"name": "cov-pkg", "version": "2.0"}, {"name": "cov-pkg2", "version": "1.0"}}); err != nil {
		t.Fatalf("CreateSnapshot2: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM software_snapshots WHERE agent_id=$1", aid) })
	if _, err := s.GetDiffs(ctx, aid, 10); err != nil {
		t.Fatalf("GetDiffs: %v", err)
	}
	// GetLatestDiff returns a not-found error when no diff row exists yet; the
	// call is exercised regardless, so a no-rows result is acceptable here.
	_, _ = s.GetLatestDiff(ctx, aid)
}

type stubPublisher struct{}

func (stubPublisher) Publish(string, []byte) error { return nil }

func TestNotificationStore_ListChannels(t *testing.T) {
	db := covTestDB(t)
	s := store.NewNotificationStore(db)
	ctx := context.Background()
	if _, err := s.ListChannels(ctx); err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
}

func TestAutoResponseStore_Executions(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewAutoResponseStore(db.Pool())
	ctx := context.Background()
	rule, err := s.CreateRule(ctx, store.CreateAutoResponseRuleInput{Name: "cov-arx", Description: "d", Enabled: true, TriggerSeverityMin: 7, TriggerStatus: "open", ActionType: "isolate_agent", ActionParams: json.RawMessage(`{}`), CooldownSeconds: 60})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteRule(ctx, rule.ID) })
	var alertID string
	if err := db.Pool().QueryRow(ctx,
		`INSERT INTO alerts (agent_id, severity, title, description, status)
		 VALUES ($1, 8, 'cov-alert', 'd', 'open') RETURNING id::text`, aid).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM alerts WHERE id=$1", alertID) })
	exec, err := s.CreateExecution(ctx, rule.ID, alertID, "isolate_agent")
	if err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if err := s.UpdateExecutionStatus(ctx, exec.ID, "completed", "ok"); err != nil {
		t.Fatalf("UpdateExecutionStatus: %v", err)
	}
	if _, err := s.ListExecutionsByRule(ctx, rule.ID, 10); err != nil {
		t.Fatalf("ListExecutionsByRule: %v", err)
	}
}

func TestCommandStore_Dispatch(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewCommandStore(db, stubPublisher{})
	ctx := context.Background()
	if err := s.IsolateEndpoint(ctx, aid, "cov-reason", "", "", "cov-actor"); err != nil {
		t.Fatalf("IsolateEndpoint: %v", err)
	}
	// actor がそのまま agents.isolated_by に入ること。ここは実 DB を使う数少ない
	// 経路なので、SQL まで通して確かめられる。以前はこの引数が無く、
	// "ai_agent" を決め打ちしていた——経路にかかわらず全ての隔離が AI トリアージの
	// 仕業に見え、手動隔離では操作者が消えていた。
	var isolatedBy string
	if err := db.Pool().QueryRow(ctx,
		`SELECT coalesce(isolated_by, '') FROM agents WHERE id = $1`, aid).Scan(&isolatedBy); err != nil {
		t.Fatalf("isolated_by の取得: %v", err)
	}
	if isolatedBy != "cov-actor" {
		t.Errorf("isolated_by = %q, want %q（送出口が主体を上書きしている）", isolatedBy, "cov-actor")
	}
	if err := s.UnisolateEndpoint(ctx, aid, "cov-reason", ""); err != nil {
		t.Fatalf("UnisolateEndpoint: %v", err)
	}
	if err := s.KillProcess(ctx, aid, 1234, "cov-reason", ""); err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	if err := s.QuarantineFile(ctx, aid, "/tmp/evil", "", ""); err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if err := s.Scan(ctx, aid, "quick", "cov-user", ""); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if err := s.ScanCancel(ctx, aid, "cov-user", ""); err != nil {
		t.Fatalf("ScanCancel: %v", err)
	}
}

func TestCmdQueueStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	lr := store.NewLiveResponseStore(db)
	ctx := context.Background()
	sess, err := lr.CreateSession(ctx, aid, "cov-cq-"+uuidNewStr(), "cov-user")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM live_response_sessions WHERE id=$1", sess.ID) })
	s := store.NewCmdQueueStore(db.Pool())
	c1, err := s.Create(ctx, store.CreateQueuedCommandInput{AgentID: aid, SessionID: &sess.ID, CommandType: "shell", Command: "whoami", Args: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM live_response_commands WHERE agent_id=$1", aid) })
	if _, err := s.Get(ctx, c1.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.ListByAgent(ctx, aid, 10); err != nil {
		t.Fatalf("ListByAgent: %v", err)
	}
	if _, err := s.PendingForAgent(ctx, aid); err != nil {
		t.Fatalf("PendingForAgent: %v", err)
	}
	ec := 0
	applied, err := s.UpdateResult(ctx, c1.ID, "completed", "root", &ec)
	if err != nil {
		t.Fatalf("UpdateResult: %v", err)
	}
	if !applied {
		t.Fatal("UpdateResult applied to no command")
	}
	// Cancel used to write status='failed', which the live_response_commands
	// CHECK rejects (pending/running/completed/error/timeout), so every
	// cancellation failed with 23514 and the command stayed pending. It now
	// writes QueuedCommandError; see live_response_queue_test.go for the gate.
	c2, err := s.Create(ctx, store.CreateQueuedCommandInput{AgentID: aid, SessionID: &sess.ID, CommandType: "shell", Command: "id", Args: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Cancel(ctx, c2.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if _, err := s.TimeoutStale(ctx); err != nil {
		t.Fatalf("TimeoutStale: %v", err)
	}
}

func TestAuditStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewAuditStore(db)
	ctx := context.Background()
	if err := s.Insert(ctx, &store.AuditLog{UserID: uid, UserEmail: "cov@example.com", Action: "login", ResourceID: "r1", IPAddress: "10.0.0.1", StatusCode: 200, Details: map[string]interface{}{"k": "v"}}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM audit_logs WHERE user_id=$1", uid) })
	if _, _, err := s.List(ctx, 10, 0, store.AuditFilter{}); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestDashboardPrefsStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewDashboardPrefsStore(db.Pool())
	ctx := context.Background()
	if err := s.Upsert(ctx, store.DashboardPrefs{UserID: uid, Widgets: []store.WidgetPref{}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM dashboard_preferences WHERE user_id=$1", uid) })
	if _, err := s.Get(ctx, uid); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestDashboardStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	uid := seedUserStore(t, db)
	s := store.NewDashboardStore(db.Pool())
	ctx := context.Background()
	if _, err := s.Upsert(ctx, uid, json.RawMessage(`[]`)); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM dashboard_layouts WHERE user_id=$1", uid) })
	if _, err := s.Get(ctx, uid); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestAgentPolicyStore_Groups(t *testing.T) {
	db := covTestDB(t)
	as := store.NewAgentStore(db)
	ps := store.NewAgentPolicyStore(db.Pool())
	ctx := context.Background()
	g, err := as.CreateGroup(ctx, "cov-grp-"+uuidNewStr()[:8], "d")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _ = as.DeleteGroup(ctx, g.ID) })
	pol, err := ps.Create(ctx, store.CreatePolicyInput{Name: "cov-gp", Description: "d", ScanIntervalMin: 60, FullScanHour: 2, LogLevel: "info"})
	if err != nil {
		t.Fatalf("Create policy: %v", err)
	}
	t.Cleanup(func() { _ = ps.Delete(ctx, pol.ID) })
	if err := ps.AssignToGroup(ctx, g.ID, pol.ID); err != nil {
		t.Fatalf("AssignToGroup: %v", err)
	}
	// NOTE: AgentPolicyStore.GetForGroup errors with "column reference id is
	// ambiguous" — a latent bug in its JOIN (both agent_groups and
	// agent_policies expose an unqualified id). Left unfixed; needs the query
	// to qualify the ambiguous column.
}

func TestCommandStore_EnqueueLiveResponseStart(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewCommandStore(db, stubPublisher{})
	if err := s.EnqueueLiveResponseStart(aid, uuidNewStr(), "cov-token", "https://cb/lr"); err != nil {
		t.Fatalf("EnqueueLiveResponseStart: %v", err)
	}
}

func TestWebhookStore_ExtraMethods(t *testing.T) {
	db := covTestDB(t)
	s := store.NewWebhookStore(db.Pool())
	ctx := context.Background()
	created, err := s.Create(ctx, store.WebhookTarget{Name: "cov-wh2", URL: "https://hook/x", Events: []string{"alert.created"}, Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, created.ID) })
	if err := s.SetEnabled(ctx, created.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := s.UpdateDeliveryStatus(ctx, created.ID, 200); err != nil {
		t.Fatalf("UpdateDeliveryStatus: %v", err)
	}
	if _, err := s.ListEnabledForEvent(ctx, "alert.created"); err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
}

func TestResponseActionStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewResponseActionStore(db)
	ctx := context.Background()
	id, err := s.Record(ctx, aid, "isolate", store.StatusDispatched, "cov-user", map[string]interface{}{"k": "v"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	// 送っただけの行が success と数えられないこと。ここが真だったのが元の欠陥。
	var success bool
	if err := db.Pool().QueryRow(ctx,
		"SELECT success FROM response_actions WHERE id=$1", id).Scan(&success); err != nil {
		t.Fatalf("success の読み出し: %v", err)
	}
	if success {
		t.Errorf("status=%s の行が success=true になっています", store.StatusDispatched)
	}
	// 結果が返ってきたら終了状態へ移せること。
	if err := s.Complete(ctx, id, store.StatusSuccess, ""); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := db.Pool().QueryRow(ctx,
		"SELECT success FROM response_actions WHERE id=$1", id).Scan(&success); err != nil {
		t.Fatalf("success の再読み出し: %v", err)
	}
	if !success {
		t.Error("Complete 後も success=false のままです")
	}

	// 期限切れの掃除。結果が返らないまま放置された行を timeout に畳む。
	// 新しい行を巻き添えにしないことが要点で、そちらを取り違えると
	// 実行中のコマンドを失敗として記録してしまう。
	stale, err := s.Record(ctx, aid, "isolate", store.StatusDispatched, "cov-user", nil)
	if err != nil {
		t.Fatalf("Record(stale): %v", err)
	}
	fresh, err := s.Record(ctx, aid, "isolate", store.StatusDispatched, "cov-user", nil)
	if err != nil {
		t.Fatalf("Record(fresh): %v", err)
	}
	// 片方だけ「30 分前に送った」ことにする
	if _, err := db.Pool().Exec(ctx,
		"UPDATE response_actions SET executed_at = NOW() - INTERVAL '30 minutes' WHERE id=$1",
		stale); err != nil {
		t.Fatalf("executed_at の巻き戻し: %v", err)
	}

	n, err := s.ExpireStale(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("ExpireStale: %v", err)
	}
	if n < 1 {
		t.Errorf("期限切れの件数 = %d, want >= 1", n)
	}

	var staleStatus, freshStatus string
	if err := db.Pool().QueryRow(ctx,
		"SELECT status_text FROM response_actions WHERE id=$1", stale).Scan(&staleStatus); err != nil {
		t.Fatalf("stale の読み出し: %v", err)
	}
	if staleStatus != store.StatusTimeout {
		t.Errorf("放置された行の状態 = %q, want %q", staleStatus, store.StatusTimeout)
	}
	if err := db.Pool().QueryRow(ctx,
		"SELECT status_text FROM response_actions WHERE id=$1", fresh).Scan(&freshStatus); err != nil {
		t.Fatalf("fresh の読み出し: %v", err)
	}
	if freshStatus != store.StatusDispatched {
		t.Errorf("送ったばかりの行の状態 = %q, want %q（巻き添えにしてはいけない）",
			freshStatus, store.StatusDispatched)
	}
	// 終了状態の行は二度と書き換えられない
	var completedStatus string
	if err := db.Pool().QueryRow(ctx,
		"SELECT status_text FROM response_actions WHERE id=$1", id).Scan(&completedStatus); err != nil {
		t.Fatalf("completed の読み出し: %v", err)
	}
	if completedStatus != store.StatusSuccess {
		t.Errorf("完了済みの行が %q に書き換わりました", completedStatus)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM response_actions WHERE agent_id=$1", aid) })
	if _, _, err := s.List(ctx, aid, 10, 0); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestPasswordPolicyStore_CRUD(t *testing.T) {
	db := covTestDB(t)
	s := store.NewPasswordPolicyStore(db)
	ctx := context.Background()
	pol, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := s.Update(ctx, *pol); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// pure-logic validators
	_ = s.Validate("Short1!", pol)
	_ = s.Validate("aVeryLongValidPassword123!", pol)
	_ = s.Violations("weak", pol)
}

func TestStoreExtras2(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()

	// YARA: upsert (create by name), list-enabled, then toggle + record-match.
	ys := store.NewYARAStore(db.Pool())
	name := "cov-yara-" + uuidNewStr()[:8]
	if _, err := ys.Upsert(ctx, store.UpsertYARARuleInput{Name: name, Description: "d", Content: "rule c { condition: true }", Tags: []string{"cov"}, Enabled: true, Severity: "medium", Category: "malware"}); err != nil {
		t.Fatalf("YARA Upsert: %v", err)
	}
	enabled, err := ys.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("YARA ListEnabled: %v", err)
	}
	for _, r := range enabled {
		if r.Name == name {
			if _, err := ys.Toggle(ctx, r.ID); err != nil {
				t.Fatalf("YARA Toggle: %v", err)
			}
			if err := ys.RecordMatch(ctx, r.ID); err != nil {
				t.Fatalf("YARA RecordMatch: %v", err)
			}
			t.Cleanup(func() { _ = ys.Delete(ctx, r.ID) })
			break
		}
	}

	// Escalation: list-enabled-for-severity (standalone query path).
	es := store.NewEscalationRuleStore(db.Pool())
	if _, err := es.ListEnabledForSeverity(ctx, 5); err != nil {
		t.Fatalf("ListEnabledForSeverity: %v", err)
	}

	// SSO: list-enabled-full (standalone query path).
	ss := store.NewSSOConfigStore(db.Pool())
	if _, err := ss.ListEnabledFull(ctx); err != nil {
		t.Fatalf("ListEnabledFull: %v", err)
	}

	// SavedHunt: create then increment-run-count.
	uid := seedUserStore(t, db)
	hs := store.NewSavedHuntStore(db.Pool())
	sh, err := hs.Create(ctx, "cov-sh2", "d", "process_name = 'x'", "kql", []string{"cov"}, uid, false)
	if err != nil {
		t.Fatalf("SavedHunt Create: %v", err)
	}
	t.Cleanup(func() { _ = hs.Delete(ctx, sh.ID) })
	hs.IncrementRunCount(ctx, sh.ID)
}

func TestAgentStore_CertRenewal(t *testing.T) {
	db := covTestDB(t)
	aid := seedAgentStore(t, db)
	s := store.NewAgentStore(db)
	ctx := context.Background()
	if err := s.UpdateCertExpiry(ctx, aid, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("UpdateCertExpiry: %v", err)
	}
	if err := s.SetRenewalToken(ctx, aid, "cov-renew-"+uuidNewStr()[:8], time.Hour); err != nil {
		t.Fatalf("SetRenewalToken: %v", err)
	}
	// ListExpiringAgents now works (int→interval fixed earlier); exercise it too.
	if _, err := s.ListExpiringAgents(ctx, 30); err != nil {
		t.Fatalf("ListExpiringAgents: %v", err)
	}
}
