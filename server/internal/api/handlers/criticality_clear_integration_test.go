package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/api/handlers"
)

// **手動 → 解除 → 自動計算の往復を、実際の DB で通します。**
//
// 構造の検査（`criticality_clear_test.go`）は「正しい行を狙っている」
// ことしか留めません。**鍵が合っていても、消したあとに読む側が印を
// 見ていなければ手動のままです** —— 消す側と読む側が噛み合っている
// ことは、行を実際に消してみないと分かりません。
//
// `TEST_DATABASE_URL` が無ければ飛ばします。
func TestManualCriticalityCanBeClearedBackToComputed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := testPool(t)
	ctx := context.Background()

	id := uuid.New().String()
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_metadata WHERE key = $1`, "agent_criticality_"+id)
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id, hostname, os_type, os_version, status)
		 VALUES ($1, $2, 'linux', '22.04', 'online')`,
		id, "criticality-clear-itest",
	); err != nil {
		t.Fatalf("検証用の端末を作れません: %v", err)
	}

	h := handlers.NewAssetCriticalityHandler(pool)
	r := gin.New()
	r.GET("/endpoints/:id/criticality", h.GetScore)
	r.PUT("/endpoints/:id/criticality", h.SetManualScore)
	r.DELETE("/endpoints/:id/criticality", h.ClearManualScore)

	call := func(method, body string) map[string]any {
		t.Helper()
		var rdr *bytes.Reader
		if body == "" {
			rdr = bytes.NewReader(nil)
		} else {
			rdr = bytes.NewReader([]byte(body))
		}
		req := httptest.NewRequest(method, "/endpoints/"+id+"/criticality", rdr)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 (%s)", method, w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s の応答を読めません: %v (%s)", method, err, w.Body.String())
		}
		return out
	}

	// 自動計算のときの点数を控えておきます。**解除が戻る先です。**
	computed := call(http.MethodGet, "")
	if computed["manual_override"] == true {
		t.Fatalf("作ったばかりの端末が手動になっています: %v", computed)
	}
	computedScore, ok := computed["score"].(float64)
	if !ok {
		t.Fatalf("計算値に点数がありません: %v", computed)
	}

	// 手動にします。
	call(http.MethodPut, `{"manual_score":95,"reason":"決済サーバ"}`)
	manual := call(http.MethodGet, "")
	if manual["manual_override"] != true || manual["score"] != float64(95) {
		t.Fatalf("手動が効いていません: %v。**この検査より先に、"+
			"手動そのものが動いていない可能性があります**", manual)
	}

	// 解除します。**応答は、戻った先の点数であること。**
	cleared := call(http.MethodDelete, "")
	if cleared["manual_override"] == true {
		t.Errorf("解除の応答に手動の印が残っています: %v", cleared)
	}
	if cleared["score"] != computedScore {
		t.Errorf("解除の応答の点数 = %v, want %v（自動計算の値）。"+
			"**画面は再取得を待たずにこれを出します**", cleared["score"], computedScore)
	}

	// 次の表示でも自動のままであること。**応答だけ自動で、行が残って
	// いれば、一覧には手動の点数が並びます。**
	after := call(http.MethodGet, "")
	if after["manual_override"] == true || after["score"] != computedScore {
		t.Errorf("解除後の再取得 = %v, want 自動の %v。"+
			"**手動の行が消えていません**", after, computedScore)
	}

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM system_metadata WHERE key = $1`, "agent_criticality_"+id,
	).Scan(&rows); err != nil {
		t.Fatalf("行を数えられません: %v", err)
	}
	if rows != 0 {
		t.Errorf("`system_metadata` に %d 行残っています。**解除は行を消します**", rows)
	}

	// もう一度解除しても 200。**「もともと自動だった」と「いま自動に
	// した」は、利用者にとって同じ結果です。**
	call(http.MethodDelete, "")
}
