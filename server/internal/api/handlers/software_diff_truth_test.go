package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/store"
)

// The software inventory diff answers "what was installed or removed on this
// endpoint since yesterday" — the signal a SOC uses to notice unauthorised
// software. It was structurally incapable of answering anything else. Three
// faults, all reproduced against the migrated schema:
//
//	ComputeDiff read agent_software and agent_software_history. No migration
//	creates either, and both reads sat behind a tableExists guard, so both
//	sides of the comparison were empty on every call. Measured: an endpoint
//	that swapped curl for netcat between two reports produced
//	200 {"added":[],"added_count":0,"removed":[],"removed_count":0} — and that
//	empty answer was persisted as the day's finding.
//
//	software_inventory_snapshots held only software_count. A count cannot say
//	WHICH package appeared, so even with the first fault repaired the table
//	could not have produced a diff.
//
//	Nothing wrote a snapshot at all: CreateSnapshot's only caller was a
//	coverage test. Meanwhile UpsertBatch deletes the agent's rows before
//	re-inserting them, so yesterday's inventory was destroyed on every report.
//	Measured: two rows before the second report, two rows after — the earlier
//	inventory simply gone.
//
// Mutation-tested at 16 mutations, 15 killed. The sixteenth — moving the
// snapshot write to after the DELETE in UpsertBatch — is equivalent, not
// uncovered: the snapshot's contents come from the items argument rather than
// from the rows being replaced, and the two statements touch different tables
// inside one transaction. The comment on UpsertBatch was corrected to say so
// rather than claim an ordering requirement the code does not have.

func swPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testPool(t)
}

func swDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Connect(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return db
}

// swAgent seeds an agent and removes it, and everything keyed to it, afterwards.
func swAgent(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'software-diff-fixture','linux','online',NOW())`, id); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM software_inventory_diffs WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM software_inventory_snapshots WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM endpoint_software WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, id)
	})
	return id
}

// report drives the real inventory write path the agent's report handler uses.
func report(t *testing.T, db *store.DB, agentID string, items ...store.SoftwareEntry) {
	t.Helper()
	entries := make([]*store.SoftwareEntry, 0, len(items))
	for i := range items {
		entries = append(entries, &items[i])
	}
	if err := store.NewSoftwareInventoryStore(db).UpsertBatch(context.Background(), agentID, entries); err != nil {
		t.Fatalf("report inventory: %v", err)
	}
}

// backdateSnapshot moves today's snapshot into the past so the next report
// leaves a comparable predecessor. Ordinary operation gets this for free by the
// calendar advancing; a test cannot wait a day.
func backdateSnapshot(t *testing.T, pool *pgxpool.Pool, agentID string, days int) {
	t.Helper()
	tag, err := pool.Exec(context.Background(),
		`UPDATE software_inventory_snapshots
		 SET snapshot_date = CURRENT_DATE - $2::int
		 WHERE agent_id = $1::uuid AND snapshot_date = CURRENT_DATE`, agentID, days)
	if err != nil {
		t.Fatalf("backdate snapshot: %v", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatal("no snapshot was written for today's report, so there is nothing " +
			"to compare tomorrow's report against")
	}
}

// computeDiff calls the endpoint and returns the decoded body.
func computeDiff(t *testing.T, pool *pgxpool.Pool, agentID string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost,
		"/api/v1/endpoints/"+agentID+"/software/diffs/compute", nil)
	c.Params = gin.Params{{Key: "id", Value: agentID}}
	handlers.NewSoftwareDiffHandler(pool).ComputeDiff(c)

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, w.Body.String())
	}
	return w.Code, body
}

// names pulls the package names out of an added/removed list.
func names(t *testing.T, v interface{}) []string {
	t.Helper()
	list, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected a list, got %T", v)
	}
	var out []string
	for _, e := range list {
		m, ok := e.(map[string]interface{})
		if !ok {
			t.Fatalf("expected an object, got %T", e)
		}
		n, _ := m["name"].(string)
		out = append(out, n)
	}
	return out
}

func containsName(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestAnInstalledPackageShowsUpInTheDiff is the core gate.
func TestAnInstalledPackageShowsUpInTheDiff(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "curl", Version: "8.0"},
	)
	backdateSnapshot(t, pool, agentID, 1)

	// Today: curl is gone, netcat has appeared.
	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "netcat", Version: "1.10"},
	)

	code, body := computeDiff(t, pool, agentID)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body %v)", code, body)
	}
	if baseline, _ := body["baseline"].(bool); baseline {
		t.Fatal("the endpoint reports it has no predecessor to compare against, " +
			"but yesterday's report was made")
	}

	added := names(t, body["added"])
	removed := names(t, body["removed"])
	if !containsName(added, "netcat") {
		t.Errorf("added = %v, want netcat. The endpoint compares two tables no "+
			"migration creates, so it answers \"nothing changed\" whatever the "+
			"endpoint actually installed.", added)
	}
	if !containsName(removed, "curl") {
		t.Errorf("removed = %v, want curl", removed)
	}
	if containsName(added, "vim") || containsName(removed, "vim") {
		t.Errorf("vim was reported both days but appears in added=%v removed=%v",
			added, removed)
	}
}

// TestAnUpgradeIsAnAdditionAndARemoval. Keying on name alone would hide the
// version change, which is the one a vulnerability scanner cares about.
func TestAnUpgradeIsAnAdditionAndARemoval(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID, store.SoftwareEntry{Name: "openssl", Version: "3.0.1"})
	backdateSnapshot(t, pool, agentID, 1)
	report(t, db, agentID, store.SoftwareEntry{Name: "openssl", Version: "3.0.14"})

	_, body := computeDiff(t, pool, agentID)
	if n, _ := body["added_count"].(float64); n != 1 {
		t.Errorf("added_count = %v, want 1 (the new version)", body["added_count"])
	}
	if n, _ := body["removed_count"].(float64); n != 1 {
		t.Errorf("removed_count = %v, want 1 (the old version)", body["removed_count"])
	}
}

// TestNoChangeIsReportedAsNoChange is the floor. Without it the fix could be
// "report everything as added", which is the same uselessness inverted.
func TestNoChangeIsReportedAsNoChange(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})
	backdateSnapshot(t, pool, agentID, 1)
	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})

	_, body := computeDiff(t, pool, agentID)
	if n, _ := body["added_count"].(float64); n != 0 {
		t.Errorf("added_count = %v for an unchanged inventory", body["added_count"])
	}
	if n, _ := body["removed_count"].(float64); n != 0 {
		t.Errorf("removed_count = %v for an unchanged inventory", body["removed_count"])
	}
}

// TestTheFirstEverComputeSaysItIsABaseline. "0 added, 0 removed" on an endpoint
// that has never been compared is indistinguishable from "nothing was
// installed", which is precisely the answer this endpoint used to give always.
func TestTheFirstEverComputeSaysItIsABaseline(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})

	code, body := computeDiff(t, pool, agentID)
	if code != http.StatusOK {
		t.Fatalf("status = %d (body %v)", code, body)
	}
	if baseline, _ := body["baseline"].(bool); !baseline {
		t.Errorf("the first computation for an endpoint is reported as a real diff: %v", body)
	}

	var stored int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM software_inventory_diffs WHERE agent_id=$1::uuid`, agentID).Scan(&stored); err != nil {
		t.Fatalf("count diffs: %v", err)
	}
	if stored != 0 {
		t.Errorf("%d diff row(s) stored for a baseline; an empty diff on record "+
			"reads as \"we checked and nothing changed\"", stored)
	}
}

// TestReportingInventoryLeavesSomethingToCompareAgainst. UpsertBatch is a full
// refresh: it deletes the agent's rows before re-inserting them. Without a
// snapshot taken first there is nothing left of yesterday.
func TestReportingInventoryLeavesSomethingToCompareAgainst(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "curl", Version: "8.0"},
	)

	var count int
	var payload []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT software_count, software FROM software_inventory_snapshots
		 WHERE agent_id=$1::uuid AND snapshot_date = CURRENT_DATE`, agentID).
		Scan(&count, &payload); err != nil {
		t.Fatalf("read snapshot: %v — the report left no snapshot, so the previous "+
			"inventory is destroyed by the next report with nothing recorded", err)
	}
	if count != 2 {
		t.Errorf("software_count = %d, want 2", count)
	}

	var items []store.SoftwareItem
	if err := json.Unmarshal(payload, &items); err != nil {
		t.Fatalf("snapshot contents are not readable: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("snapshot holds %d item(s), want 2. A count alone cannot say WHICH "+
			"package appeared, so no diff can be built from it.", len(items))
	}
	for _, want := range []string{"vim", "curl"} {
		found := false
		for _, it := range items {
			if it.Name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("snapshot is missing %s", want)
		}
	}
}

// TestRecomputingReplacesTheDayRatherThanAddingARow. The endpoint is reachable
// from a button; without a unique key the day accumulates rows and
// GetLatestDiff's ORDER BY diff_date cannot choose between them, so a
// recomputation may still read back the older answer. The second computation
// must also succeed and must be the one on record.
func TestRecomputingReplacesTheDayRatherThanAddingARow(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})
	backdateSnapshot(t, pool, agentID, 1)
	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "netcat", Version: "1.10"},
	)
	if code, body := computeDiff(t, pool, agentID); code != http.StatusOK {
		t.Fatalf("first compute: status = %d (%v)", code, body)
	}

	// The agent reports again — nmap has appeared since — and the operator
	// recomputes.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO endpoint_software (agent_id, name, version) VALUES ($1::uuid,'nmap','7.94')`,
		agentID); err != nil {
		t.Fatalf("add package: %v", err)
	}
	code, body := computeDiff(t, pool, agentID)
	if code != http.StatusOK {
		t.Fatalf("recompute: status = %d (%v). A second computation for the same "+
			"day must replace the first, not fail.", code, body)
	}

	var rows int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM software_inventory_diffs
		 WHERE agent_id=$1::uuid AND diff_date = CURRENT_DATE`, agentID).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d diff rows for one day after two computations", rows)
	}

	var stored int
	if err := pool.QueryRow(context.Background(),
		`SELECT added_count FROM software_inventory_diffs
		 WHERE agent_id=$1::uuid AND diff_date = CURRENT_DATE`, agentID).Scan(&stored); err != nil {
		t.Fatalf("read stored diff: %v", err)
	}
	if stored != 2 {
		t.Errorf("stored added_count = %d, want 2 — the recomputation did not "+
			"replace the earlier answer, so the console still shows the stale one", stored)
	}
}

// TestTheMostRecentSnapshotIsTheOneCompared. An endpoint reports every day, so
// several prior snapshots exist; comparing against the oldest would report
// every change since the endpoint was first seen as though it happened today.
func TestTheMostRecentSnapshotIsTheOneCompared(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	// Four days ago: vim only.
	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})
	backdateSnapshot(t, pool, agentID, 4)
	// Yesterday: curl was already there too.
	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "curl", Version: "8.0"},
	)
	backdateSnapshot(t, pool, agentID, 1)
	// Today: netcat appears.
	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "curl", Version: "8.0"},
		store.SoftwareEntry{Name: "netcat", Version: "1.10"},
	)

	_, body := computeDiff(t, pool, agentID)
	added := names(t, body["added"])
	if !containsName(added, "netcat") {
		t.Errorf("added = %v, want netcat", added)
	}
	if containsName(added, "curl") {
		t.Errorf("added = %v includes curl, which was already installed yesterday. "+
			"The comparison is against the oldest snapshot rather than the most "+
			"recent, so every change since the endpoint was first seen is reported "+
			"as today's.", added)
	}
}

// TestAMalformedAgentIDIsARequestError. A non-uuid reaches Postgres as 22P02
// and comes back as a 500, which reads as a server fault for a bad request.
func TestAMalformedAgentIDIsARequestError(t *testing.T) {
	pool := swPool(t)
	if code, body := computeDiff(t, pool, "not-a-uuid"); code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body %v)", code, body)
	}
}

// TestAnOfflineWeekendIsStillCompared. The old handler looked for
// CURRENT_DATE - 1 exactly; an endpoint that reported nothing yesterday has no
// such row, so its changes would go unnoticed on the day it comes back.
func TestAnOfflineWeekendIsStillCompared(t *testing.T) {
	pool := swPool(t)
	db := swDB(t)
	t.Cleanup(db.Close)
	agentID := swAgent(t, pool)

	report(t, db, agentID, store.SoftwareEntry{Name: "vim", Version: "9.0"})
	backdateSnapshot(t, pool, agentID, 4) // last seen four days ago
	report(t, db, agentID,
		store.SoftwareEntry{Name: "vim", Version: "9.0"},
		store.SoftwareEntry{Name: "nmap", Version: "7.94"},
	)

	_, body := computeDiff(t, pool, agentID)
	if baseline, _ := body["baseline"].(bool); baseline {
		t.Fatal("an endpoint whose last snapshot is four days old is treated as " +
			"having no history at all")
	}
	if added := names(t, body["added"]); !containsName(added, "nmap") {
		t.Errorf("added = %v, want nmap", added)
	}
}
