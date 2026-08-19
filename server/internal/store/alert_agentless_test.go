package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// エージェントの付かないアラートが、読めること。
//
// `SaveAlert` のコメントは agentless なアラートを明示的に扱っています ——
// クラウドの不審操作のように、端末ではなくクラウドアカウントを起点にする
// 検知です。ダークウェブ監視の「ランサムウェア被害確認」もこの形で、
// 実際に `agent_id IS NULL` の行が入ります。
//
// 読み出し側は `agent_id` / `hostname` / `os_type` を string に読んでいて、
// LEFT JOIN が外れると pgx が
//
//	cannot scan NULL into *string
//
// を返します。costs:
//
//   - `GetAlert` — そのアラートの詳細が開けません
//   - `ListAlerts` — **一覧が丸ごと失敗します。** 1件の agentless な
//     アラートが、その画面の全アラートを消します
//   - `TopThreatenedAgents` — ダッシュボードの上位端末が出ません
//
// 保存側は NULL を入れるよう明示的に直されていました（コメントに
// SQLSTATE 22P02 の経緯が書いてあります）。**書ける形にしたあと、
// 読める形にはなっていませんでした。**
//
// TEST_DATABASE_URL が無ければ飛ばします。単体では出ません。

func TestAgentlessAlertIsReadable(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)

	id := uuid.NewString()
	s := &AlertStore{pool: pool}
	if err := s.SaveAlert(ctx, &StoredAlert{
		ID: id, Severity: 7, Status: "open",
		Title: "[ランサムウェア被害確認] agentless",
		// AgentID は空 —— SaveAlert が NULL を入れます。
	}); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("GetAlert が失敗しました。エージェントの付かないアラートは"+
			"詳細を開けません: %v", err)
	}
	if got.AgentID != "" {
		t.Errorf("agent_id = %q, want 空", got.AgentID)
	}
	if got.Hostname != "" {
		t.Errorf("hostname = %q, want 空", got.Hostname)
	}

	alerts, _, err := s.ListAlerts(ctx, AlertFilter{Limit: 200})
	if err != nil {
		t.Fatalf("ListAlerts が失敗しました。**1件の agentless なアラートが"+
			"一覧全体を消しています**: %v", err)
	}
	found := false
	for _, a := range alerts {
		if a.ID == id {
			found = true
		}
	}
	if !found {
		t.Errorf("一覧に出てきません（%d 件返りました）", len(alerts))
	}

	if _, err := s.TopThreatenedAgents(ctx, 10); err != nil {
		t.Errorf("TopThreatenedAgents が失敗しました。"+
			"ダッシュボードの上位端末が出ません: %v", err)
	}
}

// エージェントの付いたアラートは、これまで通りホスト名が出ること。
// NULL を潰すついでに、出ていたものまで空にする形は避けます。
func TestAlertWithAgentStillCarriesHostname(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)
	agent := makeAgent(t, pool, tenant)

	id := uuid.NewString()
	s := &AlertStore{pool: pool}
	if err := s.SaveAlert(ctx, &StoredAlert{
		ID: id, AgentID: agent, Severity: 5, Status: "open", Title: "with agent",
	}); err != nil {
		t.Fatalf("保存できません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if got.AgentID != agent {
		t.Errorf("agent_id = %q, want %q", got.AgentID, agent)
	}
	if got.Hostname == "" {
		t.Error("hostname が空です。NULL を潰すときに、出ていたものまで消しています")
	}
	if got.OS != "linux" {
		t.Errorf("os_type = %q, want linux", got.OS)
	}
}
