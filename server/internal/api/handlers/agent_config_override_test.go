package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Per-agent configuration could not be saved, and its absence was not reported.
//
// Measured against the migrated schema before this change:
//
//	agents.settings exists=false
//
//	PUT /api/v1/agents/<id>/config-override
//	  -> 500 {"error":"failed to update agent settings"}
//	GET /api/v1/agents/<id>/effective-config
//	  -> 200 {"config":{...policy defaults only...}}
//
// Both halves of the feature were written against a column no migration
// creates. The write failed with 42703 on every call — loudly, at least. The
// read asked for the same column, discarded the error, and skipped its override
// branch, so the endpoint that answers "what configuration is this agent
// actually running?" answered without the agent-level layer and looked correct
// doing it. Nothing else stores per-agent overrides: agent_policies covers the
// policy layer, and the layer above it had nowhere to live.
//
// Migration 377 adds the column. These gates pin that an override survives a
// round trip, reaches the effective config, and is checked against the schema
// this handler publishes — which nothing consulted before, and which would
// otherwise have started accepting values it declares invalid the moment the
// write began working.

func configPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// configFixture seeds one agent and returns a handler plus its id.
func configFixture(t *testing.T) (*AgentConfigHandler, *pgxpool.Pool, string) {
	t.Helper()
	pool := configPool(t)

	var agentID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('agent-config-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	return &AgentConfigHandler{pool: pool}, pool, agentID
}

// putOverride invokes the write endpoint with a raw JSON body.
func putOverride(t *testing.T, h *AgentConfigHandler, agentID, body string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut,
		"/api/v1/agents/"+agentID+"/config-override", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: agentID}}
	h.UpdateOverride(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	}
	return w.Code, decoded
}

// effectiveConfig reads the merged config the agent would receive.
func effectiveConfig(t *testing.T, h *AgentConfigHandler, agentID string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet,
		"/api/v1/agents/"+agentID+"/effective-config", nil)
	c.Params = gin.Params{{Key: "id", Value: agentID}}
	h.GetEffective(c)

	var decoded map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	cfg, _ := decoded["config"].(map[string]interface{})
	return w.Code, cfg
}

// An override must be stored. This is the 500 that used to happen every time.
func TestAnOverrideIsStored(t *testing.T) {
	h, pool, agentID := configFixture(t)

	code, body := putOverride(t, h, agentID, `{"log_level":"debug"}`)
	if code != http.StatusOK {
		t.Fatalf("設定の保存が %d を返しました (期待: 200): %v", code, body)
	}

	// Read it back from the database rather than trusting the response, which
	// is what made the retry-policy endpoint look like it was saving.
	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT settings FROM agents WHERE id=$1::uuid`, agentID).Scan(&raw); err != nil {
		t.Fatalf("read back: %v", err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("stored settings are not JSON: %v", err)
	}
	if stored["log_level"] != "debug" {
		t.Errorf("保存された設定が %v です", stored)
	}
}

// The stored override must reach the effective config, which is the answer to
// "what is this agent actually running?".
func TestAnOverrideReachesTheEffectiveConfig(t *testing.T) {
	h, _, agentID := configFixture(t)

	// The schema default is info.
	if _, cfg := effectiveConfig(t, h, agentID); cfg["log_level"] != "info" {
		t.Fatalf("初期の log_level が %v、期待は info", cfg["log_level"])
	}

	if code, body := putOverride(t, h, agentID, `{"log_level":"debug","file_monitoring":true}`); code != http.StatusOK {
		t.Fatalf("保存が %d: %v", code, body)
	}

	code, cfg := effectiveConfig(t, h, agentID)
	if code != http.StatusOK {
		t.Fatalf("実効設定が %d を返しました", code)
	}
	if cfg["log_level"] != "debug" {
		t.Errorf("log_level が %v、期待は debug — 個別設定が反映されていません", cfg["log_level"])
	}
	if cfg["file_monitoring"] != true {
		t.Errorf("file_monitoring が %v、期待は true", cfg["file_monitoring"])
	}
	// Untouched keys keep their defaults.
	if cfg["process_monitoring"] != true {
		t.Errorf("未指定の項目が既定値を失いました: %v", cfg["process_monitoring"])
	}
}

// A second write must merge, not replace: overriding one key must not silently
// discard the others already set.
func TestOverridesMergeRatherThanReplace(t *testing.T) {
	h, _, agentID := configFixture(t)

	if code, _ := putOverride(t, h, agentID, `{"log_level":"debug"}`); code != http.StatusOK {
		t.Fatal("first write failed")
	}
	if code, _ := putOverride(t, h, agentID, `{"file_monitoring":true}`); code != http.StatusOK {
		t.Fatal("second write failed")
	}

	_, cfg := effectiveConfig(t, h, agentID)
	if cfg["log_level"] != "debug" {
		t.Errorf("先に設定した log_level が失われました: %v", cfg["log_level"])
	}
	if cfg["file_monitoring"] != true {
		t.Errorf("後から設定した file_monitoring が反映されていません: %v", cfg["file_monitoring"])
	}
}

// Values the published schema calls invalid must be refused, not stored. The
// schema is served at /api/v1/agent-config/schema and nothing consulted it.
func TestValuesTheSchemaRejectsAreRefused(t *testing.T) {
	// `reason` is the fragment the rejection must give. Asserting only the 400
	// would let a value be refused for the wrong reason — a wrong-typed
	// log_level rejected as "not in the enum" rather than "not a string" means
	// the type check is doing nothing, which matters for the next string field
	// added without an enum.
	cases := []struct{ name, body, reason string }{
		{"unknown key", `{"turbo_mode":true}`, "設定項目ではありません"},
		{"log_level outside the enum", `{"log_level":"verbose"}`, "のいずれかである必要があります"},
		{"log_level of the wrong type", `{"log_level":123}`, "文字列である必要があります"},
		{"boolean given a string", `{"file_monitoring":"yes"}`, "真偽値である必要があります"},
		{"interval below the minimum", `{"collection_interval_seconds":1}`, "以上である必要があります"},
		{"interval above the maximum", `{"collection_interval_seconds":99999}`, "以下である必要があります"},
		{"interval that is not whole", `{"send_interval_seconds":10.5}`, "整数である必要があります"},
		{"integer given a string", `{"send_interval_seconds":"30"}`, "整数である必要があります"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, pool, agentID := configFixture(t)

			code, body := putOverride(t, h, agentID, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("%s が %d を返しました (期待: 400): %v", tc.body, code, body)
			}
			details, _ := body["details"].([]interface{})
			joined := ""
			for _, d := range details {
				joined += d.(string)
			}
			if !strings.Contains(joined, tc.reason) {
				t.Errorf("%s の拒否理由が %q を含みません: %v", tc.body, tc.reason, details)
			}

			// And nothing was written.
			var raw []byte
			if err := pool.QueryRow(context.Background(),
				`SELECT settings FROM agents WHERE id=$1::uuid`, agentID).Scan(&raw); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if s := string(raw); s != "{}" {
				t.Errorf("拒否されたはずの値が保存されました: %s", s)
			}
		})
	}
}

// A rejection must say which keys were wrong; one message per offending key so
// a caller is not made to discover them one at a time.
func TestARejectionNamesEveryOffendingKey(t *testing.T) {
	h, _, agentID := configFixture(t)

	code, body := putOverride(t, h, agentID,
		`{"log_level":"verbose","collection_interval_seconds":1,"turbo_mode":true}`)
	if code != http.StatusBadRequest {
		t.Fatalf("不正な値が %d を返しました (期待: 400)", code)
	}
	details, _ := body["details"].([]interface{})
	if len(details) != 3 {
		t.Fatalf("指摘が %d 件、期待は 3 件: %v", len(details), details)
	}
	joined := ""
	for _, d := range details {
		joined += d.(string)
	}
	for _, key := range []string{"log_level", "collection_interval_seconds", "turbo_mode"} {
		if !strings.Contains(joined, key) {
			t.Errorf("指摘に %q が含まれていません: %v", key, details)
		}
	}
}

// Every boundary the schema declares must be accepted at its edge — a bound
// that is one out would refuse a legal configuration.
func TestTheSchemaBoundsAreInclusive(t *testing.T) {
	for _, body := range []string{
		`{"collection_interval_seconds":10}`,   // min
		`{"collection_interval_seconds":3600}`, // max
		`{"send_interval_seconds":5}`,          // min
		`{"send_interval_seconds":300}`,        // max
		`{"log_level":"debug"}`,
		`{"log_level":"error"}`,
	} {
		t.Run(body, func(t *testing.T) {
			h, _, agentID := configFixture(t)
			if code, resp := putOverride(t, h, agentID, body); code != http.StatusOK {
				t.Errorf("境界値 %s が %d で拒否されました: %v", body, code, resp)
			}
		})
	}
}

// An unknown agent must be reported as missing rather than silently answered
// with defaults, on both endpoints.
func TestAnUnknownAgentIsReportedOnBothEndpoints(t *testing.T) {
	pool := configPool(t)
	h := &AgentConfigHandler{pool: pool}
	const missing = "00000000-0000-0000-0000-000000000000"

	if code, _ := putOverride(t, h, missing, `{"log_level":"debug"}`); code != http.StatusNotFound {
		t.Errorf("存在しないエージェントへの保存が %d を返しました (期待: 404)", code)
	}
	if code, _ := effectiveConfig(t, h, missing); code != http.StatusNotFound {
		t.Errorf("存在しないエージェントの実効設定が %d を返しました (期待: 404)", code)
	}
}

// validateOverrides is the gate the write path leans on; pin it directly so a
// change to it is visible even if the handler stops calling it.
func TestValidateOverridesAcceptsTheSchemaDefaults(t *testing.T) {
	if problems := validateOverrides(defaultConfigValues()); len(problems) != 0 {
		t.Errorf("スキーマの既定値が検証に失敗しました: %v", problems)
	}
}
