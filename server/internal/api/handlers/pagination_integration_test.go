package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// 頁送りの補完を、要求から応答まで通して確かめます。
//
// **これは元の実測をそのまま検査にしたものです。** 実測 (2026-08-12)、
// 直す前の `/api/v1/vulnerabilities`:
//
//	per_page 指定なし → 200 / 50件 / total=120
//	per_page=0        → 200 / **0件** / total=120
//	per_page=abc      → 200 / **0件** / total=120（Atoi が 0 を返します）
//	per_page=-1       → **500**「脆弱性一覧の取得に失敗しました」
//	per_page=100000   → 200 / **120件**（上限なし）
//
// `TestEveryHandlerThatReadsPerPageClampsIt` は「補完を呼んでいるか」しか
// 見ません。**呼んでいても値が間違っていれば同じことが起きます。**
// ここは実際に返る件数を見ます。
//
// TEST_DATABASE_URL が無ければ飛ばします（この一覧の他の統合検査と同じ）。
func TestVulnerabilityListNeverAnswersWithAnEmptyPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	ctx := context.Background()

	const agentID = "c0c0c0c0-1111-2222-3333-444444444444"
	cleanup := func() { _, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) }
	cleanup()
	t.Cleanup(cleanup)

	if err := store.NewAgentStore(db).UpsertAgent(ctx, &store.AgentRow{
		ID:           agentID,
		Hostname:     "itest-vuln-paging",
		OSType:       "linux",
		OSVersion:    "Ubuntu 22.04",
		AgentVersion: "1.0.0",
		IPAddresses:  []string{"10.0.0.9"},
		Status:       "online",
	}); err != nil {
		t.Fatalf("端末を用意できません: %v", err)
	}
	// 既定（50）より多く入れます。**上限が効いていないことは、
	// 既定より多い件数が返ることでしか分かりません。**
	const seeded = 120
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO vulnerabilities (agent_id, cve_id, title, severity)
		SELECT $1, 'CVE-9999-'||lpad(g::text,4,'0'), 'itest vuln '||g, 'high'
		FROM generate_series(1,$2) g`, agentID, seeded); err != nil {
		t.Fatalf("脆弱性を用意できません: %v", err)
	}

	h := handlers.NewVulnHandler(store.NewVulnStore(db))
	r := gin.New()
	r.GET("/v", h.List)

	get := func(t *testing.T, query string) (int, int, int) {
		t.Helper()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v"+query, nil)
		r.ServeHTTP(w, req)
		var body struct {
			Data    []map[string]any `json:"data"`
			Total   int              `json:"total"`
			PerPage int              `json:"per_page"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: 応答を読めません: %v (%s)", query, err, w.Body.String())
		}
		return w.Code, len(body.Data), body.PerPage
	}

	const def = 50
	cases := []struct {
		query string
		why   string
	}{
		{"?agent_id=" + agentID, "指定なし"},
		{"?agent_id=" + agentID + "&per_page=0", "0 —— **通すと 0 件返り「該当なし」と見分けが付きません**"},
		{"?agent_id=" + agentID + "&per_page=abc", "数字でない —— Atoi が 0 を返します"},
		{"?agent_id=" + agentID + "&per_page=-1", "負 —— **Postgres が LIMIT を拒否して一覧が丸ごと落ちます**"},
		{"?agent_id=" + agentID + "&per_page=100000", "桁違い —— 上限が無いと全件返ります"},
		{"?agent_id=" + agentID + "&page=-3", "負のページ —— 負の OFFSET も拒否されます"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			status, n, perPage := get(t, tc.query)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", status, tc.why)
			}
			if n != def {
				t.Errorf("件数 = %d, want %d (%s)", n, def, tc.why)
			}
			if perPage != def {
				t.Errorf("応答の per_page = %d, want %d —— "+
					"**画面が頼んだ件数で頁送りを組み立ててしまいます**", perPage, def)
			}
		})
	}

	// 範囲内はそのまま通ること。**全部を既定に丸める実装でも上は緑です。**
	t.Run("範囲内の指定はそのまま通る", func(t *testing.T) {
		status, n, perPage := get(t, "?agent_id="+agentID+"&per_page=7")
		if status != http.StatusOK || n != 7 || perPage != 7 {
			t.Errorf("per_page=7: status=%d 件数=%d per_page=%d, want 200/7/7", status, n, perPage)
		}
	})
}
