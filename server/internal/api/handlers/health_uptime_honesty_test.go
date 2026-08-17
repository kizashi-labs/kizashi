package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/health/uptime served invented availability figures, and the route
// is unauthenticated — anyone could ask, and the public /status page rendered
// the answer as the product's SLA record.
//
// Measured against the migrated schema before this change:
//
//	uptime_events      MISSING
//	service_incidents  MISSING
//
//	GET /api/v1/health/uptime -> 200
//	  {"uptime_30d":99.9,"uptime_7d":100,"downtime_incidents":0,"last_incident":null}
//
// Both handlers probed for a table no migration creates and no code writes.
// The uptime probe's fallback was three hardcoded numbers; the incident
// probe's was an empty list, which alongside those numbers reads as "no
// incidents have occurred" rather than "nothing is recorded".
//
// These gates pin the absence of a number. There is no assertion here that
// uptime is correct, because it is not measured — the requirement is that the
// endpoint never reports a figure it did not measure.

// callHealth invokes a bare handler and decodes its JSON body.
func callHealth(t *testing.T, fn func(*gin.Context), path string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)
	fn(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("レスポンスがJSONではありません: %v (%s)", err, w.Body.String())
		}
	}
	return w.Code, decoded
}

// The uptime endpoint must not report a percentage it did not measure.
func TestUptimeIsReportedAsUnmeasuredRatherThanInvented(t *testing.T) {
	h := &DetailedHealthHandler{}

	code, body := callHealth(t, h.GetUptimeStats, "/api/v1/health/uptime")
	if code != http.StatusOK {
		t.Fatalf("稼働率エンドポイントが %d を返しました (期待: 200)", code)
	}
	if body["measured"] != false {
		t.Errorf("measured が %v です。計測していない事実を明示する必要があります", body["measured"])
	}
	for _, k := range []string{"uptime_30d", "uptime_7d", "downtime_incidents", "last_incident"} {
		v, present := body[k]
		if !present {
			t.Errorf("%s がレスポンスから消えました。既存の利用者がパースできなくなります", k)
			continue
		}
		if v != nil {
			t.Errorf("%s が %v を返しました。計測していない値を数値で返してはいけません", k, v)
		}
	}
	if body["note"] == nil || body["note"] == "" {
		t.Error("note が空です。数値を返さない理由を伝える必要があります")
	}
}

// The specific fabricated constants must never come back, whatever shape the
// response takes.
func TestTheFabricatedUptimeConstantsAreGone(t *testing.T) {
	h := &DetailedHealthHandler{}

	w := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/health/uptime", nil)
	h.GetUptimeStats(c)

	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	for k, v := range body {
		f, ok := v.(float64)
		if !ok {
			continue
		}
		// 99.9 and 100.0 were the invented figures; 0 was the invented
		// incident count. Any number at all in this response is a claim about
		// availability that nothing measured.
		t.Errorf("%s が数値 %v を返しました。稼働率は計測されていないため、"+
			"このレスポンスに数値が現れてはいけません", k, f)
	}
}

// An empty incident list must be labelled as unrecorded, not left to read as a
// clean record.
func TestTheIncidentHistorySaysItIsNotRecorded(t *testing.T) {
	h := &DetailedHealthHandler{}

	code, body := callHealth(t, h.GetIncidentHistory, "/api/v1/health/incidents")
	if code != http.StatusOK {
		t.Fatalf("障害履歴エンドポイントが %d を返しました (期待: 200)", code)
	}
	if body["measured"] != false {
		t.Errorf("measured が %v です。記録していない事実を明示する必要があります", body["measured"])
	}
	list, ok := body["incidents"].([]interface{})
	if !ok {
		t.Fatalf("incidents が配列ではありません: %v", body["incidents"])
	}
	if len(list) != 0 {
		t.Errorf("記録機構が無いのに %d 件返りました", len(list))
	}
	if body["note"] == nil || body["note"] == "" {
		t.Error("note が空です。空のリストが「障害なし」を意味しないことを伝える必要があります")
	}
}

// Neither handler may touch the database: both tables are absent, so any query
// here would be the dead code path returning. A nil pool would panic if one
// were reintroduced.
func TestTheHealthHandlersDoNotQueryAbsentTables(t *testing.T) {
	h := &DetailedHealthHandler{} // pool is nil

	if code, _ := callHealth(t, h.GetUptimeStats, "/api/v1/health/uptime"); code != http.StatusOK {
		t.Errorf("稼働率エンドポイントが %d を返しました", code)
	}
	if code, _ := callHealth(t, h.GetIncidentHistory, "/api/v1/health/incidents"); code != http.StatusOK {
		t.Errorf("障害履歴エンドポイントが %d を返しました", code)
	}
}
