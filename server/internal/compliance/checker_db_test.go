package compliance

// AssessAgent は agents と events を直接引く。実スキーマの列は
// agents.os_type (agents.os は存在しない) / events.time (events.created_at は
// 存在しない) で、いずれも取り違えると SQL が落ちる。agents 側の取り違えは
// AssessAgent 自体をエラーで終わらせ、events 側は握りつぶされて
// 「イベントが流れていない」という誤った判定になる。実 DB で確認する。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func complianceTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed compliance tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedAgentWithEvents は評価対象のエージェントと、直近 1 時間のイベントを用意する。
func seedAgentWithEvents(t *testing.T, pool *pgxpool.Pool, agentID string, events int) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE agent_id = $1`, agentID)
		_, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, agent_version, status, last_seen)
		VALUES ($1::uuid, 'compliance-itest-host', 'windows', '11', '1.0.0', 'online', NOW())`,
		agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if events == 0 {
		return
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (time, agent_id, event_type, raw_data)
		SELECT NOW() - (g || ' minutes')::INTERVAL, $1::uuid, 'process',
		       '{"process_name":"msmpeng.exe"}'::jsonb
		FROM generate_series(1, $2) g`, agentID, events); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

func TestAssessAgent_ReadsAgentAndEvents(t *testing.T) {
	pool := complianceTestPool(t)
	const agentID = "c0c0c0c0-0000-4000-8000-000000000001"
	seedAgentWithEvents(t, pool, agentID, 5)

	c := NewChecker(pool)
	got, err := c.AssessAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v (agents.os_type を引けていない可能性がある)", err)
	}
	if got == nil {
		t.Fatal("AssessAgent が nil を返した")
	}

	// agents.os を参照していた頃はここまで到達せずエラーで抜けていた。
	if got.Hostname != "compliance-itest-host" {
		t.Errorf("Hostname = %q, want compliance-itest-host", got.Hostname)
	}
	if got.OS != "windows" {
		t.Errorf("OS = %q, want windows (os_type を引けていない)", got.OS)
	}

	// events.created_at を参照していた頃は eventsFlowing が常に false だった。
	byID := map[string]*ComplianceCheck{}
	for _, ck := range got.Checks {
		byID[ck.CheckID] = ck
	}
	for _, id := range []string{"events_flowing", "logging_enabled", "av_running"} {
		ck, ok := byID[id]
		if !ok {
			t.Fatalf("チェック %q が結果に無い", id)
		}
		if ck.Status != "pass" {
			t.Errorf("%s の status = %q, want pass (直近 1 時間に 5 件投入済み。evidence: %s)",
				id, ck.Status, ck.Evidence)
		}
	}
}

// TestAssessAgent_NoEventsFails は「本当にイベントが無い」場合に fail になることを見る。
// これが無いと、上のテストは常に pass を返す実装でも通ってしまう。
func TestAssessAgent_NoEventsFails(t *testing.T) {
	pool := complianceTestPool(t)
	const agentID = "c0c0c0c0-0000-4000-8000-000000000002"
	seedAgentWithEvents(t, pool, agentID, 0)

	c := NewChecker(pool)
	got, err := c.AssessAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v", err)
	}

	for _, ck := range got.Checks {
		if ck.CheckID == "events_flowing" && ck.Status == "pass" {
			t.Errorf("イベント 0 件なのに events_flowing = pass (evidence: %s)", ck.Evidence)
		}
	}
}

// 幻のテーブル (endpoint_hardening / vuln_findings) を引いていた 3 項目の
// 再発防止。
//
// どちらの表も、どの migration も作っていない。クエリは毎回
// `relation ... does not exist` で失敗し、戻り値は `_ =` で捨てられていたため:
//
//	disk_encryption  … encryptionEnabled が false のまま → 全台が恒久的に不合格
//	firewall_enabled … 同上 → 全台が恒久的に不合格
//	patch_status     … criticalVulns が 0 のまま → patchOK=true で全台が恒久的に合格
//
// 最後の 1 つが特に危険で、未パッチの重大脆弱性があっても「良好」と報告する。
// 測れていないものは pass にも fail にもせず unknown にする。
func TestAssessAgent_UnmeasuredChecksAreUnknownNotPass(t *testing.T) {
	pool := complianceTestPool(t)
	ctx := context.Background()

	const agentID = "cc11cc11-0000-4000-8000-00000000c001"
	seedAgentWithEvents(t, pool, agentID, 3)

	got, err := NewChecker(pool).AssessAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v", err)
	}

	byID := map[string]*ComplianceCheck{}
	for _, c := range got.Checks {
		byID[c.CheckID] = c
	}

	// ファイアウォールの状態はどのテーブルにも無い。合格でも不合格でもなく unknown。
	fw := byID["firewall_enabled"]
	if fw == nil {
		t.Fatal("firewall_enabled のチェックが無い")
	}
	if fw.Status != "unknown" {
		t.Errorf("firewall_enabled = %q, want unknown (収集経路が無いものを断定しない)", fw.Status)
	}

	// 暗号化の報告が無いエージェントは「暗号化されていない」ではなく不明。
	enc := byID["disk_encryption"]
	if enc == nil {
		t.Fatal("disk_encryption のチェックが無い")
	}
	if enc.Status != "unknown" {
		t.Errorf("disk_encryption = %q, want unknown (endpoint_encryption に行が無い)", enc.Status)
	}

	// 脆弱性が 1 件も無いなら patch_status は正しく pass。
	// クエリが壊れていた頃も pass だったので、pass であること自体は証拠にならない。
	// 下の TestAssessAgent_PatchStatusFailsOnOldCriticalVuln が実際に数えられて
	// いることを示す。
	if p := byID["patch_status"]; p == nil || p.Status != "pass" {
		t.Errorf("patch_status = %v, want pass (脆弱性 0 件)", p)
	}

	// unknown は pass にも fail にも数えない。件数は固定せず、実際に
	// unknown だったものを数えて突き合わせる (収集経路が増えれば減るため)。
	unknown := 0
	for _, c := range got.Checks {
		if c.Status == "unknown" {
			unknown++
		}
	}
	if unknown == 0 {
		t.Error("unknown が 1 件も無い — 測っていない項目が pass/fail に倒れている")
	}
	if got.PassCount+got.FailCount != len(got.Checks)-unknown {
		t.Errorf("pass %d + fail %d, checks %d, unknown %d — unknown が数に混ざっている",
			got.PassCount, got.FailCount, len(got.Checks), unknown)
	}
}

// patch_status が実際に vulnerability_findings を数えていることを示す。
// 併せて、実表の status には 'patched' が無い (open/in_progress/resolved/
// accepted/false_positive) ため、旧実装の `status != 'patched'` では
// 解決済みまで未対応として数えてしまう点も押さえる。
func TestAssessAgent_PatchStatusFailsOnOldCriticalVuln(t *testing.T) {
	pool := complianceTestPool(t)
	ctx := context.Background()

	const agentID = "cc11cc11-0000-4000-8000-00000000c002"
	seedAgentWithEvents(t, pool, agentID, 3)

	cleanup := func() {
		if _, err := pool.Exec(ctx,
			`DELETE FROM vulnerability_findings WHERE agent_id = $1::uuid`, agentID); err != nil {
			t.Errorf("後片付けに失敗しました (vulnerability_findings): %v", err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	// 30 日より古い未対応の重大脆弱性 1 件と、解決済み 1 件。
	// 数えてよいのは前者だけ。
	for _, v := range []struct{ cve, status string }{
		{"CVE-2026-0001", "open"},
		{"CVE-2026-0002", "resolved"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO vulnerability_findings
			    (agent_id, cve_id, title, severity, status, first_seen)
			VALUES ($1::uuid, $2, 'itest', 'critical', $3, NOW() - INTERVAL '60 days')`,
			agentID, v.cve, v.status); err != nil {
			t.Fatalf("seed vulnerability_findings (%s): %v", v.cve, err)
		}
	}

	got, err := NewChecker(pool).AssessAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("AssessAgent: %v", err)
	}
	for _, c := range got.Checks {
		if c.CheckID != "patch_status" {
			continue
		}
		if c.Status != "fail" {
			t.Errorf("patch_status = %q, want fail (未対応の重大脆弱性が 1 件)", c.Status)
		}
		// resolved を数えていたら 2 件になる。
		if c.Evidence != "Critical unpatched vulns >30d: 1" {
			t.Errorf("evidence = %q, want 1 件 (resolved を数えていないこと)", c.Evidence)
		}
		return
	}
	t.Fatal("patch_status のチェックが無い")
}
