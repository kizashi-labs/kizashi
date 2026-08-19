package zerotrust

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// collectPosture counted a device's open critical alerts and discarded the
// error. The count feeds calculateScore twice — NoActiveAlerts is worth +10 and
// ActiveAlertCount drives a penalty of up to -30 — so a failed query left the
// count at zero and handed the device the full 40-point spread it would have
// lost with six or more open critical alerts.
//
// CheckAccess gates `admin` and `live_response` at 80 and `api` and `reports`
// at 50. Forty points crosses both. The failure was therefore in the direction
// that grants access: a device the platform could not assess was scored as a
// device with nothing wrong with it.
//
// The second defect in the same function ran the other way. CompliancePassed
// read system_metadata under the key 'compliance_score_<agent_id>', which
// nothing in the tree writes — the per-agent score lives in compliance_scores,
// written by handlers.ComputeScore. So CompliancePassed was always false, and
// because DiskEncrypted is derived from it, every device lost 15 points
// permanently.

func posturePool(t *testing.T) *pgxpool.Pool {
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

// seedPostureAgent inserts an agent that looks healthy, so the score starts
// high enough that losing or gaining points is visible against the thresholds.
func seedPostureAgent(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (id,hostname,os_type,status,last_seen,agent_version,os_version)
		VALUES ($1::uuid,$2,'windows','online',NOW(),'1.0.0','10.0.19045')`,
		id, "zt-fixture-"+id[:8]); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, id)
		_, _ = pool.Exec(c, `DELETE FROM compliance_scores WHERE agent_id=$1`, id)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, id)
	})
	return id
}

func seedCriticalAlerts(t *testing.T, pool *pgxpool.Pool, agentID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO alerts (agent_id,severity,status,title,description)
			 VALUES ($1::uuid,9,'open','zt fixture alert','')`, agentID); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}
}

// The headline: a device the engine cannot assess does not get a trust score.
func TestADeviceThatCannotBeAssessedGetsNoTrustScore(t *testing.T) {
	pool := posturePool(t)
	agentID := seedPostureAgent(t, pool)

	// A cancelled context makes the counting query fail, exactly as a dropped
	// connection or a statement timeout would.
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	e := NewEngine(pool)
	posture, err := e.EvaluateDevice(dead, agentID)
	if err == nil {
		t.Fatalf("判定できないのにポスチャを返しました: score=%d alerts=%d noAlerts=%v。"+
			"アラート数のエラーを捨てるとカウントが0のまま残り、"+
			"NoActiveAlerts の +10 とペナルティ最大 -30 の計40点が"+
			"その端末に有利に働きます",
			posture.TrustScore, posture.ActiveAlertCount, posture.NoActiveAlerts)
	}
	if posture != nil {
		t.Errorf("エラーと同時にポスチャを返しています: %+v", posture)
	}

	// And nothing must have been cached, or CheckAccess would serve the
	// fabricated posture on the next call.
	if d := e.CheckAccess(agentID, "admin"); d.Allowed {
		t.Errorf("評価に失敗した端末に admin アクセスを許可しました: %+v", d)
	}
}

// The headline for the score itself: open critical alerts cost the device both
// the bonus and the penalty, and that is what keeps it away from the high-trust
// resources.
func TestOpenCriticalAlertsCostBothTheBonusAndThePenalty(t *testing.T) {
	pool := posturePool(t)
	ctx := context.Background()
	e := NewEngine(pool)

	clean := seedPostureAgent(t, pool)
	noisy := seedPostureAgent(t, pool)
	seedCriticalAlerts(t, pool, noisy, 6) // 6 x 5 = 30, the penalty cap

	cleanP, err := e.EvaluateDevice(ctx, clean)
	if err != nil {
		t.Fatalf("EvaluateDevice(clean): %v", err)
	}
	noisyP, err := e.EvaluateDevice(ctx, noisy)
	if err != nil {
		t.Fatalf("EvaluateDevice(noisy): %v", err)
	}

	if !cleanP.NoActiveAlerts {
		t.Errorf("アラートの無い端末が NoActiveAlerts=false です: %+v", cleanP)
	}
	if noisyP.NoActiveAlerts {
		t.Errorf("重大アラート6件の端末が NoActiveAlerts=true です: %+v", noisyP)
	}
	if noisyP.ActiveAlertCount < 6 {
		t.Errorf("アラート数 = %d, 6件以上を期待", noisyP.ActiveAlertCount)
	}

	// +10 for the bonus, -30 for the capped penalty.
	if gap := cleanP.TrustScore - noisyP.TrustScore; gap != 40 {
		t.Errorf("スコア差 = %d (清浄%d - 汚染%d), 40 を期待。"+
			"アラート数は NoActiveAlerts の +10 とペナルティ -30 の"+
			"両方に効きます — 問い合わせが失敗するとその両方が"+
			"最も有利な側に倒れます",
			gap, cleanP.TrustScore, noisyP.TrustScore)
	}
}

// The compliance factor must read the table that is actually written.
func TestTheComplianceFactorReadsTheStoredScore(t *testing.T) {
	pool := posturePool(t)
	ctx := context.Background()
	e := NewEngine(pool)

	agentID := seedPostureAgent(t, pool)

	// Before any score exists, the factor is simply unknown — not an error.
	p, err := e.EvaluateDevice(ctx, agentID)
	if err != nil {
		t.Fatalf("EvaluateDevice: %v", err)
	}
	if p.CompliancePassed {
		t.Errorf("スコア未登録の端末が CompliancePassed=true です: %+v", p)
	}
	without := p.TrustScore

	// A stored CIS score above the threshold must reach the posture. This is
	// what handlers.ComputeScore writes.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_scores (agent_id, framework, score, total_checks, passed_checks)
		VALUES ($1, 'CIS', 90, 8, 7)`, agentID); err != nil {
		t.Fatalf("seed score: %v", err)
	}
	p, err = e.EvaluateDevice(ctx, agentID)
	if err != nil {
		t.Fatalf("EvaluateDevice: %v", err)
	}
	if !p.CompliancePassed {
		t.Fatalf("compliance_scores に 90 点があるのに CompliancePassed=false です。"+
			"以前は system_metadata の 'compliance_score_<agent_id>' を読んでいましたが、"+
			"このキーを書くコードはツリーに存在しません: %+v", p)
	}
	// DiskEncrypted is derived from it, so the device gains that 15 too.
	if !p.DiskEncrypted {
		t.Errorf("CompliancePassed から DiskEncrypted が導かれていません: %+v", p)
	}
	if gap := p.TrustScore - without; gap != 15 {
		t.Errorf("スコア差 = %d, 15 を期待 (DiskEncrypted の配点)", gap)
	}

	// And a score below the threshold must not pass.
	if _, err := pool.Exec(ctx,
		`UPDATE compliance_scores SET score = 40 WHERE agent_id = $1`, agentID); err != nil {
		t.Fatalf("update score: %v", err)
	}
	p, err = e.EvaluateDevice(ctx, agentID)
	if err != nil {
		t.Fatalf("EvaluateDevice: %v", err)
	}
	if p.CompliancePassed {
		t.Errorf("40点で CompliancePassed=true です (閾値は70): %+v", p)
	}
}

// And no query on the posture path may go back to discarding its error. This is
// an access-control decision, so the prohibition is pinned rather than left to
// review.
func TestNoQueryOnThePosturePathDiscardsItsError(t *testing.T) {
	b, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatalf("read engine.go: %v", err)
	}
	src := string(b)

	if strings.Contains(src, "_ = e.pool.QueryRow") || strings.Contains(src, "_ = e.pool.Query(") {
		t.Error("engine.go がクエリのエラーを捨てています。" +
			"ここで捨てたエラーはトラストスコアに化け、CheckAccess の可否になります")
	}
	// The dead key must not come back either. It reads cleanly and returns
	// nothing, which is why it survived so long.
	if strings.Contains(src, "compliance_score_' || $1") {
		t.Error("system_metadata の 'compliance_score_<agent_id>' を読んでいます。" +
			"このキーを書くコードはツリーに存在せず、CompliancePassed は常に false になります")
	}
	if !strings.Contains(src, "FROM compliance_scores") {
		t.Error("端末別コンプライアンススコアの読み出し先が compliance_scores では" +
			"ありません。この表は handlers.ComputeScore が書きます")
	}
}
