package store_test

import (
	"context"
	"testing"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/store"
)

// 抑制ルールの「有効」の旗が2つあり、書き手と読み手が食い違っていました。
//
//	is_active   コンソールの抑制ルール画面 (store.SuppressionStore) が書き、
//	            **実際に適用される側** (server-detect の
//	            storeAdapter.ListActiveSuppressions) が読みます
//	enabled     internal/suppression.Engine の API が書き、Engine の
//	            LoadFromDB が読みます
//
// どちらも既定は TRUE です。**片方だけに書くと、書かなかった側は TRUE の
// まま残ります。**
//
// 直す前に測りました (2026-08-11、このコンテナ):
//
//	Engine と同じ形で enabled=false の1件を入れる
//	  → Engine から見える件数 (enabled=true)        0
//	  → **実際に適用される側から見える件数**        1
//
// つまり **API で抑制を解除したルールが、検知エンジンでは適用され続けます。**
// 抑制されたアラートは送られません —— 担当者から見ると、攻撃されていない
// 端末とまったく同じです。**届かなかったアラートは後から取り戻せません。**
//
// 直したのは両側です。読み手は2つとも TRUE のときだけ適用し（**抑制しない
// 方向に倒します** —— 余計に届いたアラートは消せますが、落ちたアラートは
// 戻りません）、書き手は2つに同じ値を書きます。

// isApplied asks the production loader, not a copy of its SQL.
//
// **最初はここに同じ問い合わせを書き写していました。** 変異検査で、
// 適用する側の判定を元に戻す変異が**6件そのまま生き残りました** ——
// 検査していたのは検査自身の写しです。このキャンペーンで `percentFrom` の
// ときに踏んだのと同じ穴で、写しが並んでいるのを見にきて、
// **自分でもう1つ作っていました。**
//
// （この注記は印の語を避けて書いてあります ——
// `TestNoNewLogicIsReproducedInTests` は語そのものを写しの印として数える
// ので、**写しでない説明文が1件として数えられます。**）
func isApplied(t *testing.T, db *store.DB, id string) bool {
	t.Helper()
	// 適用する側は #757 で internal/detection に集約された。写しではなく
	// **本番が読むもの**を訊く、という趣旨は変わらない。
	rules, err := detection.NewPoolSuppressionLoader(db.Pool()).
		ListActiveSuppressions(context.Background())
	if err != nil {
		t.Fatalf("ListActiveSuppressions: %v", err)
	}
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// idOf returns the id of the named rule.
func idOf(t *testing.T, db *store.DB, name string) string {
	t.Helper()
	var id string
	err := db.Pool().QueryRow(context.Background(),
		"SELECT id::text FROM suppression_rules WHERE name = $1", name).Scan(&id)
	if err != nil {
		t.Fatalf("%q が見つかりません: %v", name, err)
	}
	return id
}

func cleanupRule(t *testing.T, db *store.DB, name string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(),
			"DELETE FROM suppression_rules WHERE name = $1", name)
	})
}

// 片方の旗だけを落としたルールが、適用されないこと。
//
// **これが直す前の欠陥そのものです。**
func TestARuleDisabledOnEitherFlagIsNotApplied(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		column string
	}{
		{"suppflags-enabled-off", "enabled"},
		{"suppflags-is-active-off", "is_active"},
	} {
		t.Run(tc.column, func(t *testing.T) {
			cleanupRule(t, db, tc.name)
			_, err := db.Pool().Exec(ctx, `
				INSERT INTO suppression_rules (name, description, conditions, duration_h)
				VALUES ($1, '', '{"rule_name":"probe"}'::jsonb, 24)`, tc.name)
			if err != nil {
				t.Fatalf("作成に失敗しました: %v", err)
			}
			id := idOf(t, db, tc.name)
			if !isApplied(t, db, id) {
				t.Fatal("作った直後に適用されていません。この検査の前提が崩れています")
			}

			if _, err := db.Pool().Exec(ctx,
				"UPDATE suppression_rules SET "+tc.column+" = FALSE WHERE id = $1", id); err != nil {
				t.Fatalf("更新に失敗しました: %v", err)
			}
			if isApplied(t, db, id) {
				t.Errorf("%s を FALSE にしたのに、まだ適用されます。"+
					"**抑制を解除したつもりのルールがアラートを落とし続けます** —— "+
					"届かなかったアラートは、攻撃されていないことと区別がつきません",
					tc.column)
			}
		})
	}
}

// コンソール側の書き込みが、2つの旗を揃えること。
func TestTheConsoleWritesBothFlags(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "suppflags-console-create"
	cleanupRule(t, db, name)

	s := store.NewSuppressionStore(db)
	if err := s.Insert(ctx, &store.SuppressionRule{
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		DurationH:  24,
		IsActive:   false, // **無効なルールとして作ります**
	}); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}

	id := idOf(t, db, name)
	if isApplied(t, db, id) {
		t.Error("無効として作ったルールが適用されています")
	}
	var enabled, isActive bool
	if err := db.Pool().QueryRow(ctx,
		"SELECT enabled, is_active FROM suppression_rules WHERE id=$1", id).
		Scan(&enabled, &isActive); err != nil {
		t.Fatal(err)
	}
	if enabled != isActive {
		t.Errorf("旗が食い違っています: enabled=%v is_active=%v。"+
			"**書かなかった側は既定の TRUE のまま残ります**", enabled, isActive)
	}
}

// SetActive が、2つの旗を揃えること。
func TestSetActiveMovesBothFlags(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "suppflags-setactive"
	cleanupRule(t, db, name)

	s := store.NewSuppressionStore(db)
	if err := s.Insert(ctx, &store.SuppressionRule{
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		DurationH:  24,
		IsActive:   true,
	}); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}
	id := idOf(t, db, name)
	if !isApplied(t, db, id) {
		t.Fatal("有効として作ったのに適用されていません")
	}

	if err := s.SetActive(ctx, id, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if isApplied(t, db, id) {
		t.Error("画面から無効にしたのに、まだ適用されます。" +
			"**担当者は抑制を解除したつもりでいます**")
	}
	// **旗が揃っていること。** 片方だけ落としても「適用されない」には
	// なりますが、もう片方は TRUE のまま残ります。そのあと Engine 側が
	// そのルールを触ると、揃っていない旗から片方だけを書き戻して
	// **また適用され始めます。**
	if enabled, isActive := flagsOfRule(t, db, id); enabled != isActive {
		t.Errorf("SetActive(false) のあと旗が食い違っています: "+
			"enabled=%v is_active=%v", enabled, isActive)
	}

	// 戻せること。**片方向だけ直しても、戻せなければ使えません。**
	if err := s.SetActive(ctx, id, true); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if !isApplied(t, db, id) {
		t.Error("有効に戻したのに適用されません")
	}
	if enabled, isActive := flagsOfRule(t, db, id); enabled != isActive {
		t.Errorf("SetActive(true) のあと旗が食い違っています: "+
			"enabled=%v is_active=%v", enabled, isActive)
	}
}

// flagsOfRule reads both flags directly.
func flagsOfRule(t *testing.T, db *store.DB, id string) (enabled, isActive bool) {
	t.Helper()
	if err := db.Pool().QueryRow(context.Background(),
		"SELECT enabled, is_active FROM suppression_rules WHERE id = $1", id).
		Scan(&enabled, &isActive); err != nil {
		t.Fatalf("旗を読めません: %v", err)
	}
	return
}
