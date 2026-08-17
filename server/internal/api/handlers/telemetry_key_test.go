package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Four screens read raw_data keys the ingestion layer never writes. A missing
// jsonb key is NULL, not an error, so every one of them rendered a column of
// blanks or a flag that was permanently off — indistinguishable from an
// endpoint that simply had nothing to report.
//
//	agents_handler       hashes       -> sha256 / sha1 / md5 (separate keys)
//	fim_page_handler     change_type  -> operation (FileEvent.Action enum name)
//	alerts_handler       is_suspicious on network -> threat_intel_matched
//	                     is_suspicious on file    -> yara_matched
//	                     is_suspicious on process -> no such verdict exists
//	dns_security_handler src_ip       -> agents.ip_addresses
//
// The FIM one is the instructive case: the missing key fell through to
// COALESCE's default of 'modified', so the screen did not look broken — it
// reported every file change as a modification, and "System file deleted" could
// never be raised.

// seedEvent inserts one event of the given type with the given raw_data.
func seedEvent(t *testing.T, pool *pgxpool.Pool, agentID, evType string, raw map[string]any) {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		VALUES (NOW(), $1::uuid, $2, $3::jsonb)`, agentID, evType, string(b)); err != nil {
		t.Fatalf("seed %s event: %v", evType, err)
	}
}

// seedTelemetryAgent inserts an agent with the given IP addresses and arranges
// for its events to be removed afterwards.
func seedTelemetryAgent(t *testing.T, pool *pgxpool.Pool, ips []string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO agents (id,hostname,os_type,status,last_seen,ip_addresses)
		VALUES ($1::uuid,$2,'windows','online',NOW(),$3)`,
		id, "telemetry-fixture-"+id[:8], ips); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, id)
	})
	return id
}

// The headline: the process list shows a hash.
func TestTheProcessListShowsTheExecutableHash(t *testing.T) {
	pool := renamePool(t)
	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.1"})

	const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	seedEvent(t, pool, agentID, "process", map[string]any{
		"process_name": "fixture.exe", "pid": "1234", "sha256": sha, "md5": "d41d8cd9",
	})
	// And one with only a weaker hash, to show the fallback order.
	seedEvent(t, pool, agentID, "process", map[string]any{
		"process_name": "weak.exe", "pid": "1235", "md5": "0123456789abcdef",
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/agents/:id/processes", (&AgentHandler{Pool: pool}).GetProcesses)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/agents/"+agentID+"/processes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data []struct {
			Image  string `json:"image"`
			Hashes string `json:"hashes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	got := map[string]string{}
	for _, p := range body.Data {
		got[p.Image] = p.Hashes
	}
	if got["fixture.exe"] != sha {
		t.Errorf("ハッシュ = %q, want %q。ハッシュは sha256 / sha1 / md5 の"+
			"個別キーで入ります — hashes というキーは存在せず、"+
			"この列は常に空でした", got["fixture.exe"], sha)
	}
	if got["weak.exe"] != "0123456789abcdef" {
		t.Errorf("sha256 が無い場合のハッシュ = %q。"+
			"md5 まで順に落とす必要があります", got["weak.exe"])
	}
}

// The headline: a deleted file is reported as deleted.
func TestTheFileIntegrityListReportsTheRealChangeType(t *testing.T) {
	pool := renamePool(t)
	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.2"})

	marker := "/tmp/fim-fixture-" + uuid.NewString()[:8]
	for action, path := range map[string]string{
		"FILE_ACTION_DELETE": marker + "-deleted",
		"FILE_ACTION_CREATE": marker + "-created",
		"FILE_ACTION_MODIFY": marker + "-modified",
	} {
		seedEvent(t, pool, agentID, "file", map[string]any{
			"path": path, "operation": action,
		})
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/fim/files", NewFIMPageHandler(pool).ListSuspicious)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/fim/files", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data []struct {
			FilePath    string   `json:"file_path"`
			ChangeType  string   `json:"change_type"`
			RiskReasons []string `json:"risk_reasons"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]string{}
	reasons := map[string][]string{}
	for _, f := range body.Data {
		got[f.FilePath] = f.ChangeType
		reasons[f.FilePath] = f.RiskReasons
	}

	for path, want := range map[string]string{
		marker + "-deleted":  "deleted",
		marker + "-created":  "created",
		marker + "-modified": "modified",
	} {
		if got[path] != want {
			t.Errorf("%s の変更種別 = %q, want %q。"+
				"変更種別のキーは change_type ではなく operation で、"+
				"値は FileEvent.Action の enum 名です", path, got[path], want)
		}
	}

	// The default was not merely cosmetic: everything reported as "modified"
	// means the delete-specific risk reason could never be raised.
	found := false
	for _, r := range reasons[marker+"-deleted"] {
		if r == "System file deleted" {
			found = true
		}
	}
	if !found {
		t.Errorf("削除されたファイルに削除のリスク理由が付きません: %v。"+
			"キーが無い場合 COALESCE の既定値 'modified' が採用されるため、"+
			"画面は壊れて見えないまま全件を変更として報告していました",
			reasons[marker+"-deleted"])
	}
}

// The headline: the DNS security screen names the endpoint that made the query.
func TestTheDNSScreenShowsTheQueryingEndpointsAddress(t *testing.T) {
	pool := renamePool(t)
	agentID := seedTelemetryAgent(t, pool, []string{"192.0.2.77", "10.9.9.9"})

	query := "fixture-" + uuid.NewString()[:8] + ".example"
	seedEvent(t, pool, agentID, "dns", map[string]any{
		"query": query, "query_type": "A", "is_suspicious": true,
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dns/alerts", NewDNSSecurityHandler(pool).ListAlerts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dns/alerts", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data []struct {
			Domain   string  `json:"domain"`
			ClientIP string  `json:"client_ip"`
			AgentID  *string `json:"agent_id"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var found bool
	for _, a := range body.Data {
		if a.Domain != query {
			continue
		}
		found = true
		if a.ClientIP != "192.0.2.77" {
			t.Errorf("クライアントIP = %q, want %q。"+
				"DnsEvent に送信元IPのフィールドは無く、"+
				"引いたのは端末自身なので agents.ip_addresses が正しい値です",
				a.ClientIP, "192.0.2.77")
		}
		gotAgent := ""
		if a.AgentID != nil {
			gotAgent = *a.AgentID
		}
		if gotAgent != agentID {
			t.Errorf("agent_id = %q, want %q。"+
				"複数IPの端末ではどのIPから引いたかは決められないので、"+
				"端末の特定は agent_id で行えなければなりません", gotAgent, agentID)
		}
	}
	if !found {
		t.Fatalf("投入した DNS イベントが一覧に出ません: %s", w.Body.String())
	}
}
