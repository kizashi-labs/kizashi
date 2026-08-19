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
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/store"
)

// The alert investigation graph marks each surrounding event as suspicious or
// not, and that flag is what the console highlights. All four event types read
// it from raw_data->>'is_suspicious', which only DNS events carry — so the
// process, network and file nodes were unhighlightable, and an analyst scanning
// the graph for the interesting nodes found exactly one: the alert itself.
//
// The three repairs are not the same, and that is the point:
//
//	network  threat_intel_matched  — the agent matched the peer against intel
//	file     yara_matched          — the agent's YARA scan hit
//	process  (none)                — no verdict of any kind is collected
//
// The process read is gone rather than repointed. Nothing on a process event
// expresses suspicion, and picking something adjacent — a high integrity level,
// say — would mean highlighting every elevated process in the graph as though
// the detector had judged it.

// The headline: a flagged connection and a YARA hit are highlighted.
func TestTheInvestigationGraphHighlightsTheAgentsVerdicts(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()

	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.5"})
	var alertID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id,severity,status,title,description)
		 VALUES ($1::uuid,9,'open','graph fixture','') RETURNING id::text`,
		agentID).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id=$1::uuid`, alertID)
	})

	flaggedIP := "203.0." + uuid.NewString()[:1] + "13.44"
	seedEvent(t, pool, agentID, "network", map[string]any{
		"dst_ip": flaggedIP, "dst_port": "443", "protocol": "tcp",
		"process_name": "beacon.exe", "threat_intel_matched": true,
	})
	cleanIP := "198.51.100.7"
	seedEvent(t, pool, agentID, "network", map[string]any{
		"dst_ip": cleanIP, "dst_port": "443", "protocol": "tcp",
		"process_name": "browser.exe",
	})

	hitPath := "/tmp/graph-fixture-" + uuid.NewString()[:8] + "-hit"
	seedEvent(t, pool, agentID, "file", map[string]any{
		"path": hitPath, "operation": "FILE_ACTION_MODIFY", "yara_matched": true,
	})
	cleanPath := "/tmp/graph-fixture-" + uuid.NewString()[:8] + "-clean"
	seedEvent(t, pool, agentID, "file", map[string]any{
		"path": cleanPath, "operation": "FILE_ACTION_MODIFY",
	})

	db, err := store.Connect(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	gin.SetMode(gin.TestMode)
	h := &AlertHandler{Store: store.NewAlertStore(db), Pool: pool}
	r := gin.New()
	r.GET("/alerts/:id/graph", h.Graph)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/alerts/"+alertID+"/graph", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Nodes []struct {
			Type       string            `json:"type"`
			Detail     map[string]string `json:"detail"`
			Suspicious bool              `json:"suspicious"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Labels are shortened for display (host:port, path basename), so key off
	// the detail map, which carries the value verbatim.
	suspicious := map[string]bool{}
	seen := map[string]bool{}
	for _, n := range body.Nodes {
		for _, key := range []string{"dst_ip", "path"} {
			if v := n.Detail[key]; v != "" {
				suspicious[v] = n.Suspicious
				seen[v] = true
			}
		}
	}

	for _, tc := range []struct {
		label string
		want  bool
		why   string
	}{
		{flaggedIP, true, "ネットワークイベントの「疑わしい」は threat_intel_matched です " +
			"(is_suspicious は dns イベント専用)"},
		{cleanIP, false, "何も一致していない通信が強調されています"},
		{hitPath, true, "ファイルイベントの「疑わしい」は yara_matched です"},
		{cleanPath, false, "YARA が一致していないファイルが強調されています"},
	} {
		if !seen[tc.label] {
			t.Errorf("%q のノードがグラフにありません: %s", tc.label, w.Body.String())
			continue
		}
		if suspicious[tc.label] != tc.want {
			t.Errorf("%q の suspicious = %v, want %v。%s",
				tc.label, suspicious[tc.label], tc.want, tc.why)
		}
	}
}

// And the process nodes must not read a verdict that does not exist. This is a
// source check because "always false" is what the defect looked like too: the
// graph rendered identically either way, and the difference is whether the code
// is asking a question it cannot answer.
//
// It is not "is_suspicious must not appear" — the DNS branch reads it and is
// right to. Every statement that reads it must be the one selecting DNS events.
func TestOnlyTheDNSQueryAsksForTheSuspicionVerdict(t *testing.T) {
	b, err := os.ReadFile("alerts_handler.go")
	if err != nil {
		t.Fatalf("read alerts_handler.go: %v", err)
	}
	src := stripSQLComments(stripGoComments(string(b)))

	checked := 0
	for _, lit := range backtickLiterals(src) {
		if !strings.Contains(lit, "is_suspicious") {
			continue
		}
		checked++
		if !strings.Contains(lit, "event_type = 'dns'") {
			t.Errorf("dns 以外のイベントを選ぶ文が is_suspicious を読んでいます:\n%s\n"+
				"このキーは DnsEvent の DGA/homograph 判定で、"+
				"process / network / file では常に NULL です", lit)
		}
	}
	if checked == 0 {
		t.Error("is_suspicious を読む文が1つも見つかりません。" +
			"dns の判定まで消えた可能性があります — " +
			"この抽出が壊れていても同じ結果になるので、どちらかを確認してください")
	}
}

// backtickLiterals returns every raw-string literal in src.
func backtickLiterals(src string) []string {
	var out []string
	parts := strings.Split(src, "`")
	for i := 1; i < len(parts); i += 2 {
		out = append(out, parts[i])
	}
	return out
}
