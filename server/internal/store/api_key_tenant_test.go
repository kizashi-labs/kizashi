package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// APIキーが、持ち主のテナントを持って返ること。
//
// `api_keys` にテナントの列はありません。認証層はそれを
// **無条件に空文字**として扱っていました:
//
//	c.Set("tenant_id", "")   // router.go, APIキー認証
//
// 空のテナントは、この製品では「テナント分離の無い配備」を意味します。
// アプリ層の防御は素通しし、RLS の方針（4テーブルすべて）は
// `app.tenant_id` が空なら**全テナント可**として扱い、
// `TenantMiddleware` は空を ctx に入れないのでその状態が続きます。
// **APIキーは、あらゆるテナントの端末・アラート・インシデント・利用者に
// 届いていました。**
//
// 鍵は利用者に紐づき、利用者はテナントに紐づきます。繋がっていなかった
// だけなので、`FindByKey` が一緒に引くようにしました。

func TestAPIKeyCarriesItsOwnersTenant(t *testing.T) {
	pool := roundtripDB(t)
	ctx := context.Background()

	tenant := makeTenant(t, pool)
	userID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, full_name, role, tenant_id)
		 VALUES ($1, $2, 'x', 'key owner', 'analyst', $3)`,
		userID, "key-"+userID[:8]+"@example.test", tenant); err != nil {
		t.Fatalf("利用者を作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	s := NewAPIKeyStore(pool)
	raw, err := s.Create(ctx, userID, "roundtrip", nil, nil)
	if err != nil {
		t.Fatalf("鍵を作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1`, userID) })

	found, err := s.FindByKey(ctx, raw)
	if err != nil {
		t.Fatalf("鍵を引けません: %v", err)
	}
	if found.TenantID != tenant {
		t.Errorf("tenant = %q, want %q。空だと、この鍵はあらゆるテナントに"+
			"届きます", found.TenantID, tenant)
	}
}

// 持ち主のテナントが分からない鍵は、テナントも空のままであること。
//
// **空を「全テナント」と読み替えないのが、この一連の直しの要点です。**
// 呼び出し側（ensureAgentInTenant / TenantOrAbort）が拒否する側に倒します。
//
// 最初は「実在しない利用者の鍵」で試しましたが、外部キーがあるので作れず
// **skip になりました。skip は何も言いません。** `users.tenant_id` は
// NULL 可なので、そちらで測ります。
func TestAPIKeyWhoseOwnerHasNoTenantGetsNoTenant(t *testing.T) {
	pool := roundtripDB(t)
	ctx := context.Background()

	userID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, full_name, role, tenant_id)
		 VALUES ($1, $2, 'x', 'no tenant', 'analyst', NULL)`,
		userID, "nt-"+userID[:8]+"@example.test"); err != nil {
		t.Fatalf("利用者を作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	s := NewAPIKeyStore(pool)
	raw, err := s.Create(ctx, userID, "no tenant", nil, nil)
	if err != nil {
		t.Fatalf("鍵を作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1`, userID) })

	found, err := s.FindByKey(ctx, raw)
	if err != nil {
		t.Fatalf("鍵を引けません: %v", err)
	}
	if found.TenantID != "" {
		t.Errorf("tenant = %q, want 空", found.TenantID)
	}
}
