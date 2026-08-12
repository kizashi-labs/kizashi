package handlers_test

// Wazuh 取り込みが常に 500 を返していた件の再発防止。
//
// INSERT が alerts に無い 5 つの列 (agent_hostname / agent_os /
// rule_name / mitre_tactic / raw_data) に書こうとしていたため、
// POST /api/v1/ingest/wazuh は毎回
//
//	column "agent_hostname" of relation "alerts" does not exist
//
// で落ちていた。Wazuh 側から見ると「連携したのにアラートが 1 件も
// 上がってこない」状態になる。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

func TestWazuhIngest_CreatesAlert(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	const hostname = "wazuh-ingest-host"
	cleanup := func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM alerts WHERE agent_id IN (SELECT id FROM agents WHERE hostname = $1)`, hostname)
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE hostname = $1`, hostname)
	}
	cleanup()
	t.Cleanup(cleanup)

	body := map[string]any{
		"timestamp": "2026-08-03T00:00:00Z",
		"rule": map[string]any{
			"level":       12,
			"description": "Multiple authentication failures",
			"id":          "5716",
			"groups":      []string{"authentication_failed", "syslog", "sshd"},
			"mitre": map[string]any{
				"tactic":    []string{"Credential Access"},
				"technique": []string{"T1110"},
			},
		},
		"agent":    map[string]any{"id": "003", "name": hostname, "ip": "198.51.100.9"},
		"id":       "1754179200.12345",
		"full_log": "Failed password for invalid user admin from 198.51.100.9",
		"location": "/var/log/auth.log",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	h := handlers.NewIngestHandler(pool, "") // トークン未設定 = 認証スキップ
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/ingest/wazuh", h.WazuhAlert)

	w := jsonReq(r, http.MethodPost, "/api/v1/ingest/wazuh", json.RawMessage(raw))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AlertID  string `json:"alert_id"`
		Severity int    `json:"severity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response: %v (body: %s)", err, w.Body.String())
	}
	if resp.AlertID == "" {
		t.Fatalf("alert_id が空: %s", w.Body.String())
	}

	// 保存された行が、落とした列の情報をどこかに保っていることを確認する。
	var title, description, technique, source, rawEvent string
	var agentIDMatches bool
	if err := pool.QueryRow(ctx, `
		SELECT al.title, COALESCE(al.description,''), COALESCE(al.mitre_technique,''),
		       COALESCE(al.source,''), COALESCE(al.raw_event,''),
		       (ag.hostname = $2) AS host_ok
		FROM alerts al
		JOIN agents ag ON ag.id = al.agent_id
		WHERE al.id = $1`, resp.AlertID, hostname).
		Scan(&title, &description, &technique, &source, &rawEvent, &agentIDMatches); err != nil {
		t.Fatalf("保存されたアラートを読めない: %v", err)
	}

	if title != "Multiple authentication failures" {
		t.Errorf("title = %q", title)
	}
	// ホスト名/OS は alerts ではなく agents 側が持つ。
	if !agentIDMatches {
		t.Errorf("alerts.agent_id が %q のエージェントを指していない", hostname)
	}
	// rule_name 相当は description に残す (捨てるとどのルールか追えない)。
	if !strings.Contains(description, "5716") {
		t.Errorf("description に Wazuh ルール ID が残っていない: %q", description)
	}
	// mitre_tactic 列は無いが、タクティクも description に残す。
	if !strings.Contains(description, "Credential Access") {
		t.Errorf("description に MITRE タクティクが残っていない: %q", description)
	}
	if technique != "T1110" {
		t.Errorf("mitre_technique = %q, want T1110", technique)
	}
	if source != "wazuh" {
		t.Errorf("source = %q, want wazuh", source)
	}
	// raw_data 列は無い。ペイロード全体は raw_event (text) に入る。
	if !strings.Contains(rawEvent, "198.51.100.9") {
		t.Errorf("raw_event に元ペイロードが入っていない: %q", rawEvent)
	}

	// 統計エンドポイントも agents.source を読む。列が無いと
	// wazuh_agents が 0 のままになる。
	code, status := doJSON(t, http.MethodGet, "/api/v1/ingest/wazuh/status", nil, h.WazuhStatus)
	if code != http.StatusOK {
		t.Fatalf("status endpoint = %d, want 200 (body: %v)", code, status)
	}
	if got := numField(t, status, "wazuh_agents"); got < 1 {
		t.Errorf("wazuh_agents = %v, want >= 1", got)
	}
	if got := numField(t, status, "total_alerts"); got < 1 {
		t.Errorf("total_alerts = %v, want >= 1", got)
	}
}
