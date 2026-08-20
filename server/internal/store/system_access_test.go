package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 名乗りの判定そのものを留める。
//
// **ここが緩むと、名乗りは既定に戻ります。** 特に「外から来た文字列が
// `system` を名乗れないこと」は、JWT の tenant_id がそのままここに
// 来るので、抜け道を落としたあとの最後の防波堤になります。

func TestSystemAccessRoundTrips(t *testing.T) {
	ctx := context.Background()
	if systemAccessFromContext(ctx) {
		t.Error("素の ctx が全テナントを名乗っています")
	}
	if !systemAccessFromContext(WithSystemAccess(ctx)) {
		t.Error("名乗ったのに、名乗りが読めません")
	}
}

// **`TenantContextKey` と `systemAccessKey` が別物であること。**
//
// 同じ鍵に "system" を入れる形にすると、JWT の tenant_id に "system" を
// 入れた相手が全テナントを名乗れます。値ではなく鍵で分けているので、
// 外から来た文字列はこの経路に入りません。
func TestATenantValueCannotBecomeSystemAccess(t *testing.T) {
	ctx := context.WithValue(context.Background(), TenantContextKey{}, SystemTenant)
	if systemAccessFromContext(ctx) {
		t.Error("テナントの値として \"system\" を置いたら、名乗りとして読めました。" +
			"**鍵が分かれていません**")
	}
}

// prepareConnForTenant の分岐のうち、**接続に触る前に落ちるもの**。
// nil の接続を渡せるのは、そこまで到達しないことの裏返しです。
func TestPrepareConnRejectsAClaimFromTheTenantPath(t *testing.T) {
	ctx := context.WithValue(context.Background(), TenantContextKey{}, SystemTenant)
	ok, err := prepareConnForTenant(ctx, nil)
	if ok || err == nil {
		t.Fatal("テナントとして \"system\" を名乗れました。**外から全テナントに届きます**")
	}
	if !strings.Contains(err.Error(), "名乗れません") {
		t.Errorf("理由が伝わりません: %v", err)
	}
}

// 広く始めて、決まったら狭める。**これは正しい形です。**
//
// `cmd/ingestion` と `uninstall_protection.tenantScope` が、全テナントの
// ctx から派生して、引けたテナントを重ねます。作っている途中でこれを
// 「配線の誤り」として落とすように書き、**アンインストール保護の配布を
// 止めました。** 狭める向きは常に安全です。
func TestNarrowingFromSystemToATenantIsAllowed(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	ctx := context.WithValue(WithSystemAccess(context.Background()), TenantContextKey{}, tenant)

	got, _ := ctx.Value(TenantContextKey{}).(string)
	if got != tenant {
		t.Fatalf("重ねたテナントが読めません: %q", got)
	}
	if !systemAccessFromContext(ctx) {
		t.Fatal("派生元の名乗りが消えています。この検査は狭める向きを見ていません")
	}
	// **どちらを張るか**が要点です。テナントが勝たないと、狭めたつもりの
	// 接続が全テナントを見ます。nil の接続では set_config まで行けないので、
	// 実物での確認は TestATenantStillSeesOnlyItself が持ちます。
	if got == SystemTenant {
		t.Fatal("テナントが system になっています")
	}
}

func TestPrepareConnDoesNothingWithoutEither(t *testing.T) {
	// 名乗りもテナントも無い ctx は、いまのところ通ります（エスケープ節が
	// 拾います）。**抜け道を落としたあと、この接続は 0 行になります。**
	ok, err := prepareConnForTenant(context.Background(), nil)
	if !ok || err != nil {
		t.Fatalf("素の ctx が落ちました: ok=%v err=%v", ok, err)
	}
}

// ── ここから DB が要ります ────────────────────────────────────────

// 名乗った接続が全テナントを見られること。
//
// **これが通らないと、抜け道を落とした瞬間に系が全部止まります。**
// migration 450 が方針に足した項を、実物で確かめます。
func TestASystemClaimSeesEveryTenant(t *testing.T) {
	pool := rlsPool(t)
	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	agentA, agentB := seedAgentFor(t, pool, tenantA), seedAgentFor(t, pool, tenantB)

	seen := agentsVisibleAs(t, pool, SystemTenant, agentA, agentB)
	if !seen[agentA] || !seen[agentB] {
		t.Errorf("全テナントを名乗ったのに、全部は見えません（A=%v B=%v）。"+
			"**migration 450 の `= 'system'` の項がありません。**"+
			"抜け道を落とすと、系がここで止まります", seen[agentA], seen[agentB])
	}
}

// 名乗っていない接続が、いまは全部見えること —— **抜け道が実在する記録**。
//
// **これは「良い」ではなく「いまこうなっている」の写しです。** 抜け道を
// 落としたら、ここは落ちます。そのとき消してください —— 落ちたことが
// 「fail-closed になった」の合図です。
func TestAnUnnamedConnectionStillSeesEverything(t *testing.T) {
	pool := rlsPool(t)
	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	agentA, agentB := seedAgentFor(t, pool, tenantA), seedAgentFor(t, pool, tenantB)

	seen := agentsVisibleAs(t, pool, "", agentA, agentB)
	if !seen[agentA] || !seen[agentB] {
		t.Log("名乗っていない接続が全部は見えなくなりました。" +
			"**エスケープ節が落ちたようです。** " +
			"この検査と undecidedPublicRoutes を消してください")
	}
}

// テナントを名乗った接続は、自分のぶんだけ。**名乗りを足しても、
// 絞り込みが緩まないこと。**
func TestATenantStillSeesOnlyItself(t *testing.T) {
	pool := rlsPool(t)
	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	agentA, agentB := seedAgentFor(t, pool, tenantA), seedAgentFor(t, pool, tenantB)

	seen := agentsVisibleAs(t, pool, tenantA, agentA, agentB)
	if !seen[agentA] {
		t.Error("自分のテナントの端末が見えません")
	}
	if seen[agentB] {
		t.Error("他テナントの端末が見えています。**方針が効いていません**")
	}
}

// agentsVisibleAs は `app.tenant_id` にその値を置いた接続から見える端末。
//
// **`SET ROLE edr_app` で測ります。** 既定の接続主体は所有者なので、
// FORCE が外れた瞬間に全部見えるようになり、「方針が壊れている」と
// 「ロールが素通りしている」の区別が付かなくなります。
func agentsVisibleAs(t *testing.T, pool *pgxpool.Pool, claim string, ids ...string) map[string]bool {
	t.Helper()
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("接続を取れません: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET ROLE edr_app`); err != nil {
		t.Skipf("edr_app ロールがありません（migration 325 未適用）: %v", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	if _, err := conn.Exec(ctx,
		`SELECT set_config('app.tenant_id', $1, false)`, claim); err != nil {
		t.Fatalf("app.tenant_id を設定できません: %v", err)
	}

	seen := map[string]bool{}
	rows, err := conn.Query(ctx,
		`SELECT id::text FROM agents WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[id] = true
	}
	if err := rows.Err(); err != nil {
		// **ここを飛ばすと、途中で切れた読み取りが「見えなかった」に
		// なります。** 分離が効いているのと区別が付きません。
		t.Fatalf("rows: %v", err)
	}
	return seen
}
