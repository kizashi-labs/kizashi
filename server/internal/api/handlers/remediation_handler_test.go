package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/remediation"
)

// newRemediationRouter は DB・NATS なしのエンジンでテスト用 gin.Engine を構築する。
func newRemediationRouter(t *testing.T) (*gin.Engine, *handlers.RemediationHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := remediation.NewEngine(nil, nil)
	h := handlers.NewRemediationHandler(engine)
	r := gin.New()
	r.GET("/remediation/rules", h.ListRules)
	r.POST("/remediation/rules", h.CreateRule)
	r.PUT("/remediation/rules/:id/enable", h.EnableRule)
	r.GET("/remediation/logs", h.GetLogs)
	r.POST("/remediation/test", h.TestRule)
	r.GET("/remediation/exclusions", h.ListExclusions)
	r.POST("/remediation/exclusions", h.CreateExclusion)
	r.DELETE("/remediation/exclusions/:id", h.DeleteExclusion)
	r.GET("/remediation/pending-rollbacks", h.ListPendingRollbacks)
	r.POST("/remediation/executions/:id/approve", h.ApproveExecution)
	return r, h
}

func jsonBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonBody: %v", err)
	}
	return bytes.NewReader(b)
}

// ─── ListRules ────────────────────────────────────────────────────────────────

func TestRemediationHandler_ListRules_Empty(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/remediation/rules", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListRules: got %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("total: got %v, want 0", total)
	}
}

// ─── CreateRule ───────────────────────────────────────────────────────────────

func TestRemediationHandler_CreateRule_MissingName(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/remediation/rules",
		jsonBody(t, map[string]interface{}{"enabled": true}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("name 未指定: got %d, want 400", w.Code)
	}
}

func TestRemediationHandler_CreateRule_Valid(t *testing.T) {
	r, _ := newRemediationRouter(t)
	body := map[string]interface{}{
		"name":                     "Test Rule",
		"cooldown_seconds":         30,
		"rollback_timeout_seconds": 120,
		"trigger": map[string]interface{}{
			"event_type":   "alert",
			"min_severity": 7,
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/remediation/rules", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateRule: got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint:errcheck
	if resp["id"] == "" {
		t.Error("CreateRule: レスポンスに id が含まれるべきです")
	}
}

func TestRemediationHandler_CreateRule_AppearsInListRules(t *testing.T) {
	r, _ := newRemediationRouter(t)

	// ルールを作成
	body := map[string]interface{}{"name": "Visible Rule"}
	req := httptest.NewRequest(http.MethodPost, "/remediation/rules", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	// ListRules で確認
	req2 := httptest.NewRequest(http.MethodGet, "/remediation/rules", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	var resp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &resp) //nolint:errcheck
	if total, _ := resp["total"].(float64); total != 1 {
		t.Errorf("total: got %v, want 1", total)
	}
}

func TestRemediationHandler_CreateRule_RollbackTimeoutInResponse(t *testing.T) {
	r, _ := newRemediationRouter(t)
	body := map[string]interface{}{
		"name":                     "Rollback Rule",
		"rollback_timeout_seconds": 300,
	}
	req := httptest.NewRequest(http.MethodPost, "/remediation/rules", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	// ListRules でロールバックタイムアウトが含まれるか確認
	req2 := httptest.NewRequest(http.MethodGet, "/remediation/rules", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	var resp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &resp) //nolint:errcheck
	rules, _ := resp["rules"].([]interface{})
	if len(rules) == 0 {
		t.Fatal("rules が空です")
	}
	rule := rules[0].(map[string]interface{})
	if rule["rollback_timeout"] == "" || rule["rollback_timeout"] == nil {
		t.Error("rollback_timeout がレスポンスに含まれるべきです")
	}
}

// ─── EnableRule ───────────────────────────────────────────────────────────────

func TestRemediationHandler_EnableRule_NotFound(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodPut, "/remediation/rules/nonexistent/enable",
		jsonBody(t, map[string]interface{}{"enabled": false}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("存在しない ID: got %d, want 404", w.Code)
	}
}

func TestRemediationHandler_EnableRule_TogglesEnabled(t *testing.T) {
	r, _ := newRemediationRouter(t)

	// ルール作成
	createReq := httptest.NewRequest(http.MethodPost, "/remediation/rules",
		jsonBody(t, map[string]interface{}{"name": "Toggle Me"}))
	createReq.Header.Set("Content-Type", "application/json")
	cw := httptest.NewRecorder()
	r.ServeHTTP(cw, createReq)

	var createResp map[string]interface{}
	json.Unmarshal(cw.Body.Bytes(), &createResp) //nolint:errcheck
	id, _ := createResp["id"].(string)

	// enabled=false に変更
	req := httptest.NewRequest(http.MethodPut, "/remediation/rules/"+id+"/enable",
		jsonBody(t, map[string]interface{}{"enabled": false}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("EnableRule: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ─── GetLogs ──────────────────────────────────────────────────────────────────

func TestRemediationHandler_GetLogs_Empty(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/remediation/logs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetLogs: got %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("total: got %v, want 0", total)
	}
}

func TestRemediationHandler_GetLogs_InvalidLimit_UsesDefault(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/remediation/logs?limit=-5", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetLogs limit=-5: got %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	// limit は 20 (デフォルト) になるはず
	if lim, _ := body["limit"].(float64); lim != 20 {
		t.Errorf("limit: got %v, want 20", lim)
	}
}

// ─── TestRule (dry-run) ───────────────────────────────────────────────────────

func TestRemediationHandler_TestRule_NoMatch(t *testing.T) {
	r, _ := newRemediationRouter(t)
	body := map[string]interface{}{
		"event_type": "alert",
		"severity":   5,
		"tags":       []string{},
	}
	req := httptest.NewRequest(http.MethodPost, "/remediation/test", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("TestRule: got %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint:errcheck
	if dryRun, _ := resp["dry_run"].(bool); !dryRun {
		t.Error("dry_run フィールドは true のはずです")
	}
	if cnt, _ := resp["match_count"].(float64); cnt != 0 {
		t.Errorf("match_count: got %v, want 0", cnt)
	}
}

func TestRemediationHandler_TestRule_DefaultEventType(t *testing.T) {
	r, _ := newRemediationRouter(t)
	// event_type を省略 → "alert" がデフォルトになるはず
	req := httptest.NewRequest(http.MethodPost, "/remediation/test",
		jsonBody(t, map[string]interface{}{}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("TestRule (no event_type): got %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint:errcheck
	if et, _ := resp["event_type"].(string); et != "alert" {
		t.Errorf("event_type: got %q, want \"alert\"", et)
	}
}

// ─── ListExclusions ───────────────────────────────────────────────────────────

func TestRemediationHandler_ListExclusions_Empty(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/remediation/exclusions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListExclusions: got %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("total: got %v, want 0", total)
	}
}

// ─── CreateExclusion ──────────────────────────────────────────────────────────

func TestRemediationHandler_CreateExclusion_MissingPattern(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/remediation/exclusions",
		jsonBody(t, map[string]interface{}{"reason": "test"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("pattern 未指定: got %d, want 400", w.Code)
	}
}

func TestRemediationHandler_CreateExclusion_InvalidGlob(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/remediation/exclusions",
		jsonBody(t, map[string]interface{}{"hostname_pattern": "[invalid"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("不正 glob: got %d, want 400", w.Code)
	}
}

func TestRemediationHandler_CreateExclusion_Valid(t *testing.T) {
	r, _ := newRemediationRouter(t)
	body := map[string]interface{}{
		"hostname_pattern": "dc-*",
		"reason":           "ドメインコントローラー",
	}
	req := httptest.NewRequest(http.MethodPost, "/remediation/exclusions", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateExclusion: got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint:errcheck
	if resp["id"] == "" || resp["id"] == nil {
		t.Error("id がレスポンスに含まれるべきです")
	}
}

func TestRemediationHandler_CreateExclusion_AppearsInList(t *testing.T) {
	r, _ := newRemediationRouter(t)

	// 追加
	req := httptest.NewRequest(http.MethodPost, "/remediation/exclusions",
		jsonBody(t, map[string]interface{}{"hostname_pattern": "prod-db-*"}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	// 一覧確認
	req2 := httptest.NewRequest(http.MethodGet, "/remediation/exclusions", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	var resp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &resp) //nolint:errcheck
	if total, _ := resp["total"].(float64); total != 1 {
		t.Errorf("total: got %v, want 1", total)
	}
}

// ─── DeleteExclusion ──────────────────────────────────────────────────────────

func TestRemediationHandler_DeleteExclusion_NotFound(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodDelete, "/remediation/exclusions/nonexistent-id", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("存在しない ID: got %d, want 404", w.Code)
	}
}

func TestRemediationHandler_DeleteExclusion_Valid(t *testing.T) {
	r, _ := newRemediationRouter(t)

	// 追加
	cReq := httptest.NewRequest(http.MethodPost, "/remediation/exclusions",
		jsonBody(t, map[string]interface{}{"hostname_pattern": "srv-*"}))
	cReq.Header.Set("Content-Type", "application/json")
	cw := httptest.NewRecorder()
	r.ServeHTTP(cw, cReq)

	var cResp map[string]interface{}
	json.Unmarshal(cw.Body.Bytes(), &cResp) //nolint:errcheck
	id, _ := cResp["id"].(string)

	// 削除
	dReq := httptest.NewRequest(http.MethodDelete, "/remediation/exclusions/"+id, nil)
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, dReq)

	if dw.Code != http.StatusOK {
		t.Errorf("DeleteExclusion: got %d, want 200; body: %s", dw.Code, dw.Body.String())
	}

	// 削除後は空
	lReq := httptest.NewRequest(http.MethodGet, "/remediation/exclusions", nil)
	lw := httptest.NewRecorder()
	r.ServeHTTP(lw, lReq)

	var lResp map[string]interface{}
	json.Unmarshal(lw.Body.Bytes(), &lResp) //nolint:errcheck
	if total, _ := lResp["total"].(float64); total != 0 {
		t.Errorf("削除後 total: got %v, want 0", total)
	}
}

// ─── ListPendingRollbacks ─────────────────────────────────────────────────────

func TestRemediationHandler_ListPendingRollbacks_Empty(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/remediation/pending-rollbacks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListPendingRollbacks: got %d, want 200", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("total: got %v, want 0", total)
	}
}

// ─── ApproveExecution ─────────────────────────────────────────────────────────

func TestRemediationHandler_ApproveExecution_NotFound(t *testing.T) {
	r, _ := newRemediationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/remediation/executions/nonexistent/approve", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("存在しない execution ID: got %d, want 404", w.Code)
	}
}
