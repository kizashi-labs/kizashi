package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// ai_attack_chain / ai_mitre_tags に値が入っていても、アラートが読めること。
//
// `ai_attack_chain` は TEXT[] の列ですが、読み出し側は []byte で受けて
// json.Unmarshal していました。**列が NULL のあいだは何も起きません。**
// 値が1件でも入ると pgx が
//
//	cannot scan _text (OID 1009) in binary format into *[]uint8
//
// を返し、
//
//   - `GetAlert` は失敗を返す（アラート詳細が開けません）
//   - `ListAlerts` は Scan の失敗が rows.Err() に出て**一覧が0件で返ります**
//
// になります。1件のアラートが一覧全体を落とします。
//
// いまこの列を書いている本番の経路はありません（`AIAnalysisUpdate.AttackChain`
// を設定する箇所が無く、常に NULL です）。**動いていない機能なので今日は
// 誰も踏みません。** ただし `ai_agent.go` は Claude の応答から attack_chain を
// 既に取り出していて、保存する1行を足した瞬間にアラート画面が落ちます。
//
// 単体テストでは出ません。列に値を入れて読み戻さないと分かりません。
// TEST_DATABASE_URL が無ければ飛ばします。

func TestAlertWithAIArraysIsReadable(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)
	agent := makeAgent(t, pool, tenant)

	id := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (id, agent_id, severity, status, title,
		                    ai_attack_chain, ai_mitre_tags, raw_event)
		VALUES ($1, $2, 9, 'open', 'ai analysed',
		        $3::text[], $4::text[], $5)`,
		id, agent,
		[]string{"initial-access", "execution", "persistence"},
		[]string{"TA0001", "TA0002"},
		`{"cmd":"whoami"}`,
	); err != nil {
		t.Fatalf("アラートを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	s := &AlertStore{pool: pool}

	// 1. 詳細が開けること。
	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("GetAlert が失敗しました。AI が分析したアラートは詳細を開けません: %v", err)
	}
	if len(got.AIAttackChain) != 3 || got.AIAttackChain[0] != "initial-access" {
		t.Errorf("ai_attack_chain = %v, want 3 件", got.AIAttackChain)
	}
	if len(got.AIMITRETags) != 2 {
		t.Errorf("ai_mitre_tags = %v, want 2 件", got.AIMITRETags)
	}

	// 2. 一覧に出ること。**この1件が一覧全体を落としていました。**
	alerts, _, err := s.ListAlerts(ctx, AlertFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListAlerts が失敗しました。1件が一覧全体を落としています: %v", err)
	}
	found := false
	for _, a := range alerts {
		if a.ID == id {
			found = true
			if len(a.AIAttackChain) != 3 {
				t.Errorf("一覧の ai_attack_chain = %v", a.AIAttackChain)
			}
		}
	}
	if !found {
		t.Errorf("一覧に出てきません（%d 件返りました）。"+
			"Scan に失敗した行は落ちるので、静かに消えます", len(alerts))
	}
}

// 列が NULL のときも、これまで通り読めること。
// 直したつもりで、今度は NULL 側を壊す形は避けます。
func TestAlertWithoutAIArraysIsStillReadable(t *testing.T) {
	pool := roundtripDB(t)
	tenant := makeTenant(t, pool)
	ctx := tenantCtx(tenant)
	agent := makeAgent(t, pool, tenant)

	id := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO alerts (id, agent_id, severity, status, title)
		VALUES ($1, $2, 4, 'open', 'no ai')`, id, agent); err != nil {
		t.Fatalf("アラートを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id = $1`, id)
	})

	s := &AlertStore{pool: pool}
	got, err := s.GetAlert(ctx, id)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if len(got.AIAttackChain) != 0 {
		t.Errorf("ai_attack_chain = %v, want 空", got.AIAttackChain)
	}
	if got.RawEventUnavailable != nil {
		t.Errorf("生イベントの無いアラートに、出せなかった理由が付いています: %s",
			*got.RawEventUnavailable)
	}
}
