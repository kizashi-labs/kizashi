package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// There are three different things a read can mean and only two of them were
// ever expressible:
//
//	200 + []   nothing has happened yet
//	500        the read failed, try again
//	501        nothing produces this data, and retrying will not change that
//
// GeoStats was the third case wearing the first two. `alerts` has no
// src_country column — no migration creates it, no agent sets it, and the
// server-side GeoIP enrichment the proto note assumes exists nowhere — so the
// query failed with 42703 every single time it ran. The handler answered with
// an empty list, and the dashboard turned that into FALLBACK_GEO_THREATS:
// China 142 critical, Russia 89, North Korea 54.
//
// An operator seeing an empty threat map waits for data. An operator seeing 501
// with what is missing knows to ask for the feature. The difference is whether
// the next hour is spent waiting or spent asking.

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("レスポンスが JSON ではありません: %v (%s)", err, w.Body.String())
	}
	return body
}

// The headline: the threat map endpoint says it is unimplemented rather than
// answering with a plausible empty list.
func TestGeoStatsSaysItIsUnimplementedRatherThanEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/alerts/geo-stats", nil)

	// Pool is nil on purpose. The old handler answered 200 + [] here too, so a
	// deployment with no database and a deployment with no feature looked the
	// same to the console.
	(&AlertHandler{}).GeoStats(c)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("geo-stats が %d を返しています (want 501)。"+
			"200+空は「まだ何も起きていない」と読まれ、ダッシュボードは"+
			"作り物の国別件数で埋めていました", w.Code)
	}

	body := decodeJSON(t, w)
	if body["not_implemented"] != true {
		t.Errorf("not_implemented フラグがありません: %v", body)
	}
	missing, _ := body["missing"].(string)
	if missing == "" {
		t.Error("何が足りないのかが書かれていません。501 だけでは、" +
			"読んだ人が次に何を頼めばいいのか分かりません")
	}
	// And it must not carry an empty result set alongside, or a client reading
	// `data` first sees the same nothing as before.
	if _, hasData := body["data"]; hasData {
		t.Errorf("501 なのに data を同梱しています: %v", body)
	}
}

// NotImplemented is driven directly because the healthy path of every other
// handler never reaches it, and a helper that is never called reads exactly
// like one that was deleted.
func TestNotImplementedCarriesTheStatusAndTheReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)

	NotImplemented(c, "機能名", "足りないもの")

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	body := decodeJSON(t, w)
	for field, want := range map[string]any{
		"not_implemented": true,
		"feature":         "機能名",
		"missing":         "足りないもの",
	} {
		if body[field] != want {
			t.Errorf("%s = %v, want %v", field, body[field], want)
		}
	}
	if msg, _ := body["error"].(string); msg == "" {
		t.Error("error メッセージが空です")
	}
}

// 501 has to stay outside the range the client treats as a server fault.
// frontend/lib/api.ts toasts on >= 500 except 501; if the two ever merged
// again, an unimplemented feature would look like an outage and be retried.
func TestNotImplementedIsNotInTheRetryableRange(t *testing.T) {
	if http.StatusNotImplemented != 501 {
		t.Fatalf("501 の定数が変わっています: %d", http.StatusNotImplemented)
	}
	if http.StatusInternalServerError == http.StatusNotImplemented {
		t.Fatal("500 と 501 が同じ扱いになっています")
	}
}
