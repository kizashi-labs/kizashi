package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Blocking a runtime threat ran `UPDATE events … WHERE id = $1`. The events
// table has no id column — its key is event_id — so the statement was rejected
// with 42703 and the handler answered 500 on every attempt. The feature has
// never worked.
//
// This is the write-side counterpart of the empty-screen defects: a read that
// disagrees with the schema shows nothing, which at least looks wrong. A write
// that disagrees leaves an operator believing they contained something.

// The headline: blocking a threat marks the event, and the mark is what the
// listing reads back.
func TestBlockingARuntimeThreatMarksTheEvent(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()

	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.6"})
	seedEvent(t, pool, agentID, "process", map[string]any{
		"process_name": "xmrig", "command_line": "xmrig --url stratum+tcp://pool",
		"container_id": "c0ffee", "privileged": true,
	})

	// The id the console blocks with is the one the threat listing hands out,
	// which is events.event_id.
	var eventID string
	if err := pool.QueryRow(ctx,
		`SELECT event_id::text FROM events WHERE agent_id = $1::uuid LIMIT 1`,
		agentID).Scan(&eventID); err != nil {
		t.Fatalf("read event id: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/threats/:id/block", NewCloudRuntimeHandler(pool).BlockThreat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/threats/"+eventID+"/block", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s\n"+
			"events の主キーは event_id で、id という列はありません — "+
			"文が 42703 で拒否されると脅威のブロックは毎回 500 になります",
			w.Code, w.Body.String())
	}

	// The response is not the evidence; the row is.
	var blocked *bool
	if err := pool.QueryRow(ctx,
		`SELECT (raw_data->>'blocked')::boolean FROM events WHERE event_id = $1::uuid`,
		eventID).Scan(&blocked); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if blocked == nil || !*blocked {
		t.Errorf("イベントに blocked が付いていません (%v)。"+
			"200 を返しても行が変わっていなければ、操作者は"+
			"止めたつもりの脅威を抱えたままです", blocked)
	}
}

// A threat that is not there must not answer "blocked". An UPDATE matching no
// row is not an error, so a handler that only checks err reports success for an
// id that does not exist.
func TestBlockingAThreatThatIsNotThereIsNotSuccess(t *testing.T) {
	pool := renamePool(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/threats/:id/block", NewCloudRuntimeHandler(pool).BlockThreat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/threats/"+uuid.NewString()+"/block", nil))
	if w.Code == http.StatusOK {
		t.Errorf("存在しない脅威のブロックが成功しました: %s。"+
			"0件更新はエラーではないので、err だけを見ると成功として返ります",
			w.Body.String())
	}
}

// And a malformed id must be a client error, not a 500. event_id is uuid, so
// binding an arbitrary string to it fails with 22P02 inside the query.
func TestAMalformedThreatIdIsNotSurfacedAsAServerFault(t *testing.T) {
	pool := renamePool(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/threats/:id/block", NewCloudRuntimeHandler(pool).BlockThreat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/threats/not-a-uuid/block", nil))
	if w.Code == http.StatusOK {
		t.Errorf("不正な ID のブロックが成功しました: %s", w.Body.String())
	}
	if w.Code >= 500 {
		t.Errorf("不正な ID で %d を返しています: %s。"+
			"入力の誤りをサーバ障害として報告しています", w.Code, w.Body.String())
	}
}
