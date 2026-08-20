package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/auth"
)

// users を fail-closed にしたとき、**認証そのものが通るか**を実 DB で測る。
//
// ## なぜ users だけ別の検査が要るのか
//
// agents / alerts / incidents は、テナントが決まったあとで読み書きします。
// users は違います —— **誰なのかを users に聞くまで、テナントは決まりません。**
// 鶏と卵です。
//
// `authMiddleware` は要求ごとに 2 回 users に届きます:
//
//	FindByKey           `LEFT JOIN users` で API キーの持ち主のテナントを引く
//	UserCache.IsActive  `SELECT is_active FROM users WHERE id = $1`
//
// どちらもテナントが決まる**前**に走ります。抜け道を落とすと、素の接続では
// この 2 本が 0 行になります。**そして 0 行の読まれ方が、2 本とも違う向きに
// 悪いです:**
//
//	IsActive   行が無い → 「削除された利用者」→ **全員が締め出されます**
//	FindByKey  行は在る（api_keys に RLS は無い）→ **テナントだけが静かに
//	           落ちて**、すでに fail-closed な 3 表が 0 行になります
//
// 後者が厄介です。API キーの要求は 200 を返し続け、中身だけが空になります。
//
// ## この検査が留めているもの
//
// `authMiddleware` は `store.WithSystemAccess` でこの 2 本だけを名乗らせて
// います。**下の 4 本のうち 2 本は、その名乗りが無い世界を実際に作って、
// 上の 2 つの壊れ方を見せます。** 名乗りを外したら緑のままになる検査では、
// 外れたことに気づけません。
//
// `RLS_FAILCLOSED=1` が要ります（4 表の方針を差し替えるので DB を専有します）。

// 名乗った接続は、テナントを知らないまま利用者を引けること。
//
// **ここが落ちると、ログインの後に全員が締め出されます。**
func TestFailClosedTheClaimStillFindsTheUser(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	row := seedTenantRows(t, seedPool)
	if _, err := seedPool.Exec(context.Background(),
		`UPDATE users SET is_active = TRUE WHERE id = $1`, row.user); err != nil {
		t.Fatalf("利用者を有効にできません: %v", err)
	}
	withStrictPolicies(t, seedPool)

	pool := failClosedPool(t)
	cache := auth.NewUserStatusCache(pool)

	if !cache.IsActive(WithSystemAccess(context.Background()), row.user) {
		t.Fatal("名乗った接続が利用者を引けませんでした。" +
			"**この状態では、認証済みの要求が全部「アカウントが無効化されています」" +
			"で弾かれます。**")
	}
}

// 素の接続は利用者を引けないこと —— **つまり全員が締め出されること。**
//
// これは「望ましい挙動」ではありません。**名乗りを外すと何が起きるかを、
// 実物で見せている**だけです。ここが逆に緑（引けてしまう）になったら、
// users の抜け道が戻っています。
func TestFailClosedABareContextLocksEveryoneOut(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	row := seedTenantRows(t, seedPool)
	if _, err := seedPool.Exec(context.Background(),
		`UPDATE users SET is_active = TRUE WHERE id = $1`, row.user); err != nil {
		t.Fatalf("利用者を有効にできません: %v", err)
	}
	withStrictPolicies(t, seedPool)

	pool := failClosedPool(t)
	cache := auth.NewUserStatusCache(pool)

	// **IsActive は DB 障害では通します（意図した fail-open）。** ここで
	// false が返るのは「行が無い」= `pgx.ErrNoRows` の枝に落ちたときだけ
	// なので、false であること自体が「RLS に切られた」の証拠になります。
	if cache.IsActive(context.Background(), row.user) {
		t.Fatal("テナントも名乗りも持たない接続が、有効な利用者を引けました。" +
			"**users の抜け道が戻っています。**")
	}
}

// 名乗った接続では、API キーが持ち主のテナントを連れてくること。
func TestFailClosedTheClaimKeepsTheAPIKeysTenant(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	row := seedTenantRows(t, seedPool)
	raw := seedAPIKeyFor(t, seedPool, row.user)
	withStrictPolicies(t, seedPool)

	keys := NewAPIKeyStore(failClosedPool(t))
	got, err := keys.FindByKey(WithSystemAccess(context.Background()), raw)
	if err != nil {
		t.Fatalf("名乗った接続が API キーを引けません: %v", err)
	}
	if got.TenantID != row.tenant {
		t.Fatalf("API キーのテナントが %q ではなく %q でした", row.tenant, got.TenantID)
	}
}

// 素の接続では、鍵は見つかるのに**テナントだけが落ちること。**
//
// `api_keys` に RLS はありません。落ちるのは `LEFT JOIN users` の側だけ
// なので、**呼び出し側から見ると成功します。** これが 4 表の中でいちばん
// 静かな壊れ方です —— 要求は 200 を返し、一覧だけが空になります。
func TestFailClosedABareContextSilentlyDropsTheAPIKeysTenant(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	row := seedTenantRows(t, seedPool)
	raw := seedAPIKeyFor(t, seedPool, row.user)
	withStrictPolicies(t, seedPool)

	keys := NewAPIKeyStore(failClosedPool(t))
	got, err := keys.FindByKey(context.Background(), raw)
	if err != nil {
		// 鍵そのものが引けなくなったのなら、それは静かではありません。
		// この検査の前提（api_keys に RLS が無い）が変わったということなので、
		// 上の説明ごと見直してください。
		t.Fatalf("鍵まで引けなくなりました。api_keys に RLS が付いた可能性が"+
			"あります。この検査の前提を見直してください: %v", err)
	}
	if got.TenantID != "" {
		t.Fatalf("テナントも名乗りも持たない接続が、鍵のテナント %q を引けました。"+
			"**users の抜け道が戻っています。**", got.TenantID)
	}
}

// seedAPIKeyFor は、本番と同じ `Create` で鍵を作ります。
//
// ハッシュの取り方を写すと、**写しが合っているあいだしか正しくありません。**
// 種まきは所有者の接続で行います（`api_keys` に RLS はありませんが、
// 揃えておきます）。
func seedAPIKeyFor(t *testing.T, pool *pgxpool.Pool, userID string) string {
	t.Helper()
	raw, err := NewAPIKeyStore(pool).Create(
		context.Background(), userID, "fc-"+userID[:8], []string{"read"}, nil)
	if err != nil {
		t.Fatalf("API キーを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_keys WHERE user_id = $1`, userID)
	})
	return raw
}
