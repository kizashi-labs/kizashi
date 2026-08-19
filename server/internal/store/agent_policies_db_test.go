package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// defaultPolicyID は非公開です。**公開しません** —— 外から使う人が
// いないので、公開すると `TestStoreSymbolsAreReachable` の数が増えます。
// 値はマイグレーションが入れる固定の UUID です。
const defaultPolicyIDForTest = "00000000-0000-0000-0000-000000000002"

// 既定ポリシーの削除拒否と、TenantID の nil 化。
//
// **検査ファイルには、製品の2行を検査の本文で書き直したものが置いて
// ありました** —— `isBlocked := func(id string) bool { return id ==
// defaultPolicyID }` を定義して、それを試す。製品を1行も通りません。
//
// 既定ポリシーが消せてしまうと、`GetForGroup` が「グループにポリシーが
// 無ければ既定を返す」経路で行を見つけられなくなります。**端末が
// どのポリシーも受け取らない状態**になります。

// restoreDefaultPolicy puts the row back if this test managed to remove it.
//
// **この検査は、守りが外れたときに本当に消してしまいます。** 実際に
// 起きました —— 変異検査でガードを外したら、共有の DB から既定ポリシーの
// 行が消え、**変異を戻したあとも消えたままで**、他の検査が外部キー違反で
// 落ち続けました。ソースは戻っても、DB は戻りません。
//
// 消えたら入れ直します。migrations/034 と同じ行です。
func restoreDefaultPolicy(t *testing.T, db *store.DB) {
	t.Helper()
	t.Cleanup(func() {
		_, err := db.Pool().Exec(context.Background(), `
			INSERT INTO agent_policies (id, name, description)
			VALUES ($1::uuid, 'Default Policy', 'デフォルトエージェントポリシー')
			ON CONFLICT DO NOTHING`, defaultPolicyIDForTest)
		if err != nil {
			t.Errorf("既定ポリシーを戻せません: %v", err)
		}
	})
}

func TestDeletingTheDefaultPolicyIsRefused(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	restoreDefaultPolicy(t, db)
	s := store.NewAgentPolicyStore(db.Pool())

	err := s.Delete(ctx, defaultPolicyIDForTest)
	if err == nil {
		t.Fatal("既定ポリシーが削除できました。**どのグループにも" +
			"ポリシーが無い状態になります**")
	}
	if !strings.Contains(err.Error(), "デフォルト") {
		t.Errorf("理由が伝わりません: %v", err)
	}

	// **消えていないこと。** 断ったと言いながら消していたら同じです。
	if _, err := s.Get(ctx, defaultPolicyIDForTest); err != nil {
		t.Errorf("既定ポリシーが読めません: %v", err)
	}
}

// 存在しないポリシーの削除は、成功と区別されること。
//
// **0行の DELETE は「消した」ではありません。**
func TestDeletingAMissingPolicyIsNotSuccess(t *testing.T) {
	db := covTestDB(t)
	s := store.NewAgentPolicyStore(db.Pool())

	err := s.Delete(context.Background(), "99999999-9999-9999-9999-999999999999")
	if err == nil {
		t.Fatal("存在しないポリシーの削除が成功として返りました")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound。**呼び出し側が"+
			"「消えた」と「無かった」を区別できません**", err)
	}
}
