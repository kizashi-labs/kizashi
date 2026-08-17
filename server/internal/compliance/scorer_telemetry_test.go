package compliance

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two CIS checks tested raw_data keys the agent never sends, so the condition
// could only ever be false and the check could only ever pass:
//
//	CIS-1.1  elevated       -> integrity_level ('High' | 'System')
//	CIS-3.1  is_suspicious  -> threat_intel_matched
//
// A compliance check that cannot fail is worse than one that is missing. It
// prints a green tick beside a control nobody is actually evaluating, and the
// score it feeds is correspondingly inflated.
//
// Neither was a naming slip. `elevated` is not collected in any form, but
// Windows elevation is `integrity_level`, the Sysmon label
// (Untrusted|Low|Medium|High|System) — and High/System is exactly what CIS-1.1
// means. `is_suspicious` is the agent's DGA/homograph verdict and exists on DNS
// events alone; the equivalent judgement on a network event is the threat-intel
// match. Reading either under the wrong name is a check that never fires.

func scorerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedScoredAgent inserts an agent plus the given events and returns its id.
func seedScoredAgent(t *testing.T, pool *pgxpool.Pool, events []struct {
	evType string
	raw    map[string]any
}) string {
	t.Helper()
	ctx := context.Background()

	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,$2,'windows','online',NOW())`,
		agentID, "scorer-fixture-"+agentID[:8]); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	for _, e := range events {
		b, _ := json.Marshal(e.raw)
		if _, err := pool.Exec(ctx, `
			INSERT INTO events (time, agent_id, event_type, raw_data)
			VALUES (NOW(), $1::uuid, $2, $3::jsonb)`,
			agentID, e.evType, string(b)); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	return agentID
}

// checkPassed pulls one check's verdict out of a score result.
func checkPassed(t *testing.T, pool *pgxpool.Pool, agentID, id string) bool {
	t.Helper()
	res, err := ScoreAgent(context.Background(), pool, agentID)
	if err != nil {
		t.Fatalf("ScoreAgent: %v", err)
	}
	for _, c := range res.Checks {
		if c.ID == id {
			return c.Passed
		}
	}
	t.Fatalf("%s が結果に含まれていません", id)
	return false
}

// The headline: an elevated process fails CIS-1.1.
func TestAnElevatedProcessFailsTheElevationCheck(t *testing.T) {
	pool := scorerPool(t)

	type ev = struct {
		evType string
		raw    map[string]any
	}

	// A UAC-elevated ordinary administrator: neither root nor SYSTEM, so the
	// username conditions beside this one cannot see it. This is the case the
	// check exists for.
	elevated := seedScoredAgent(t, pool, []ev{{"process", map[string]any{
		"process_name": "cmd.exe", "username": "CORP\\alice", "integrity_level": "High",
	}}})
	if checkPassed(t, pool, elevated, "CIS-1.1") {
		t.Error("昇格したプロセスがあるのに CIS-1.1 が合格しています。" +
			"elevated という真偽値は収集しておらず、Windows の昇格は " +
			"integrity_level (High/System) です — " +
			"root/SYSTEM の判定だけでは昇格した一般管理者を拾えません")
	}

	// And an ordinary user process must still pass, or the check is just
	// "always fail", which is no more useful than "always pass".
	normal := seedScoredAgent(t, pool, []ev{{"process", map[string]any{
		"process_name": "notepad.exe", "username": "CORP\\bob", "integrity_level": "Medium",
	}}})
	if !checkPassed(t, pool, normal, "CIS-1.1") {
		t.Error("Medium の整合性レベルで CIS-1.1 が不合格になりました。" +
			"昇格していないプロセスを昇格として数えています")
	}
}

// The headline: a connection the agent's threat intel flagged fails CIS-3.1.
func TestAThreatIntelMatchFailsTheNetworkCheck(t *testing.T) {
	pool := scorerPool(t)

	type ev = struct {
		evType string
		raw    map[string]any
	}

	// Port 443 — deliberately not one of the hard-coded C2 ports, so only the
	// verdict can fail this check.
	flagged := seedScoredAgent(t, pool, []ev{{"network", map[string]any{
		"dst_ip": "203.0.113.9", "dst_port": "443",
		"threat_intel_matched": true, "threat_intel_source": "fixture",
	}}})
	if checkPassed(t, pool, flagged, "CIS-3.1") {
		t.Error("脅威インテルが一致した通信があるのに CIS-3.1 が合格しています。" +
			"is_suspicious は dns イベント専用で、ネットワークイベントでの" +
			"対応するフラグは threat_intel_matched です")
	}

	// A clean connection on the same port must pass.
	clean := seedScoredAgent(t, pool, []ev{{"network", map[string]any{
		"dst_ip": "203.0.113.10", "dst_port": "443",
	}}})
	if !checkPassed(t, pool, clean, "CIS-3.1") {
		t.Error("何も一致していない通信で CIS-3.1 が不合格になりました")
	}
}
