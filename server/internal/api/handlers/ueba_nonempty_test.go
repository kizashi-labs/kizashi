package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

// Three UEBA endpoints scanned a timestamptz column into a Go string:
//
//	ListAnomalies   ueba_anomalies.created_at  -> Anomaly.CreatedAt  (string)
//	GetAnomaly      ueba_anomalies.created_at  -> Anomaly.CreatedAt  (string)
//	ListBaselines   ueba_baselines.updated_at  -> Baseline.UpdatedAt (string)
//
// pgx refuses that: "cannot scan timestamptz (OID 1184) in binary format into
// *string". It records the failure on the Rows, so rows.Err() turned it into a
// 500 for the list endpoints, while GetAnomaly reported it as 404 — an anomaly
// that exists indexed as one that does not.
//
// Every one of them therefore worked only while its table was empty. That is
// not an unlucky coincidence: the read-only smoke tests in this package drive
// these handlers against a database where nobody has inserted anything, so an
// endpoint that breaks on its first row passes them all. These tests seed a row
// first, which is the whole point of them.
//
// GetUserBehavior and ListUsers in the same file already scan into time.Time
// and format; the three above now match.
//
// Mutation-tested at 10 mutations, 9 killed. The survivor is the per-row
// slog.Warn added to ListAnomalies' scan loop: with the scan fixed, no fixture
// this test can build makes a row fail to scan, so no test here can tell
// whether the warning is there. It is recorded rather than covered by a test
// that only appears to check it.

// seedAnomaly inserts one UEBA anomaly and returns its id.
func seedAnomaly(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO ueba_anomalies (username, anomaly_type, severity, score, description, details, status)
		VALUES ($1,'process_spawn_rate','high',7.5,'unusual spawn rate','{"pid":4242}'::jsonb,'open')
		RETURNING id::text`, username).Scan(&id); err != nil {
		t.Fatalf("seed anomaly: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ueba_anomalies WHERE username=$1`, username)
	})
	return id
}

// seedBaseline inserts one UEBA baseline.
func seedBaseline(t *testing.T, pool *pgxpool.Pool, username string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ueba_baselines (username, metric_name, baseline_value, std_deviation, sample_days)
		VALUES ($1,'process_spawn_rate',12.5,2.5,30)`, username); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ueba_baselines WHERE username=$1`, username)
	})
}

// callUEBA invokes a handler and returns the status and decoded body.
func callUEBA(t *testing.T, target string, params gin.Params, h gin.HandlerFunc) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	c.Params = params
	h(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, w.Body.String())
	}
	return w.Code, body
}

// TestListingAnomaliesWorksWhenThereAreAnomalies is the core gate.
func TestListingAnomaliesWorksWhenThereAreAnomalies(t *testing.T) {
	pool := testPool(t)
	username := "ueba-nonempty-" + uuid.NewString()[:8]
	seedAnomaly(t, pool, username)

	h := &handlers.UEBAHandler{Pool: pool}
	code, body := callUEBA(t, "/api/v1/ueba/anomalies?username="+username, nil, h.ListAnomalies)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body %v). The endpoint scans a timestamptz column "+
			"into a Go string, so it answers 500 as soon as the table has a row — "+
			"it works only on an empty database.", code, body)
	}

	list, ok := body["anomalies"].([]interface{})
	if !ok || len(list) == 0 {
		t.Fatalf("no anomalies returned for a seeded user: %v", body)
	}
	first, _ := list[0].(map[string]interface{})
	created, _ := first["created_at"].(string)
	if created == "" {
		t.Fatal("the anomaly carries no created_at")
	}
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", created, err)
	}
	if first["username"] != username {
		t.Errorf("username = %v, want %s", first["username"], username)
	}
}

// TestGettingOneAnomalyWorks. The failure here was reported as 404, so an
// anomaly that exists was indistinguishable from one that does not — the
// console shows the row in the list and then cannot open it.
func TestGettingOneAnomalyWorks(t *testing.T) {
	pool := testPool(t)
	username := "ueba-one-" + uuid.NewString()[:8]
	id := seedAnomaly(t, pool, username)

	h := &handlers.UEBAHandler{Pool: pool}
	code, body := callUEBA(t, "/api/v1/ueba/anomalies/"+id,
		gin.Params{{Key: "id", Value: id}}, h.GetAnomaly)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body %v) for an anomaly that exists", code, body)
	}
	if body["username"] != username {
		t.Errorf("username = %v, want %s", body["username"], username)
	}
	created, _ := body["created_at"].(string)
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", created, err)
	}
}

// TestAnomalyThatDoesNotExistIsStillA404 is the floor: distinguishing "missing"
// from "could not read it" is the point of the change, so both answers have to
// remain reachable.
func TestAnomalyThatDoesNotExistIsStillA404(t *testing.T) {
	pool := testPool(t)
	h := &handlers.UEBAHandler{Pool: pool}

	id := uuid.NewString()
	code, _ := callUEBA(t, "/api/v1/ueba/anomalies/"+id,
		gin.Params{{Key: "id", Value: id}}, h.GetAnomaly)
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an anomaly that does not exist", code)
	}
}

// TestAMalformedAnomalyIDIsARequestError. Before the change GetAnomaly had one
// error path, so "the id is not a uuid" and "no such anomaly" produced the same
// 404 — and so did "the row could not be read". Separating them is the point;
// each answer has to be reachable on its own.
func TestAMalformedAnomalyIDIsARequestError(t *testing.T) {
	pool := testPool(t)
	h := &handlers.UEBAHandler{Pool: pool}

	code, _ := callUEBA(t, "/api/v1/ueba/anomalies/not-a-uuid",
		gin.Params{{Key: "id", Value: "not-a-uuid"}}, h.GetAnomaly)
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an id that is not a uuid", code)
	}
}

// TestADatabaseFailureIsNotReportedAsAMissingAnomaly. GetAnomaly had a single
// error path that answered 404, so every reason the read could fail — a
// timestamptz it could not scan, a database that is down — was presented to the
// operator as "this anomaly does not exist". That is the most misleading答え
// available: it invites them to conclude the record was deleted.
func TestADatabaseFailureIsNotReportedAsAMissingAnomaly(t *testing.T) {
	// A pool aimed at a port nothing is listening on. pgxpool connects lazily,
	// so construction succeeds and the first query fails — which is exactly the
	// shape of a database that has gone away under a running server.
	dead, err := pgxpool.New(context.Background(),
		"postgres://nobody@127.0.0.1:1/none?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(dead.Close)

	h := &handlers.UEBAHandler{Pool: dead}
	id := uuid.NewString()
	code, _ := callUEBA(t, "/api/v1/ueba/anomalies/"+id,
		gin.Params{{Key: "id", Value: id}}, h.GetAnomaly)
	if code == http.StatusNotFound {
		t.Error("a database that could not be reached is reported as \"anomaly not " +
			"found\", so an unreachable database looks like a deleted record")
	}
	if code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", code)
	}
}

// TestListingBaselinesWorksWhenThereAreBaselines.
func TestListingBaselinesWorksWhenThereAreBaselines(t *testing.T) {
	pool := testPool(t)
	username := "ueba-base-" + uuid.NewString()[:8]
	seedBaseline(t, pool, username)

	h := &handlers.UEBAHandler{Pool: pool}
	code, body := callUEBA(t, "/api/v1/ueba/baselines?username="+username, nil, h.ListBaselines)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body %v)", code, body)
	}
	list, ok := body["baselines"].([]interface{})
	if !ok || len(list) == 0 {
		t.Fatalf("no baselines returned for a seeded user: %v", body)
	}
	first, _ := list[0].(map[string]interface{})
	updated, _ := first["updated_at"].(string)
	if _, err := time.Parse(time.RFC3339, updated); err != nil {
		t.Errorf("updated_at %q is not RFC3339: %v", updated, err)
	}
}

// TestTheOtherUEBAReadsSurviveARow covers the endpoints in this file that
// already scanned correctly, so the change cannot have broken them and so the
// non-empty case is exercised across the whole handler rather than only where
// the bug was.
func TestTheOtherUEBAReadsSurviveARow(t *testing.T) {
	pool := testPool(t)
	username := "ueba-rest-" + uuid.NewString()[:8]
	seedAnomaly(t, pool, username)
	seedBaseline(t, pool, username)

	h := &handlers.UEBAHandler{Pool: pool}
	for _, tc := range []struct {
		name   string
		target string
		params gin.Params
		fn     gin.HandlerFunc
	}{
		{"UserBehavior", "/api/v1/ueba/users/" + username + "/behavior",
			gin.Params{{Key: "id", Value: username}}, h.GetUserBehavior},
		{"UserProfile", "/api/v1/ueba/users/" + username,
			gin.Params{{Key: "id", Value: username}}, h.GetUserProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tc.target, nil)
			c.Params = tc.params
			tc.fn(c)
			if w.Code != http.StatusOK {
				t.Errorf("status = %d (body %s)", w.Code, w.Body.String())
			}
			var any interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &any); err != nil {
				t.Errorf("invalid JSON: %v", err)
			}
		})
	}
}
