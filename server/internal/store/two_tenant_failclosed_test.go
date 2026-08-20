package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// エスケープ節を落とした状態を、落とす前に実測する。
//
// ## なぜ落とす前に測るのか
//
// 4 表 (agents / alerts / incidents / users) の RLS には、まだ
// 「`app.tenant_id` が未設定なら全行」の抜け道が残っています。落とすと、
// テナントも名乗りも持たない接続は **0 行**になります。
//
// **壊れる向きが「静かに 0 行」です。** 検知が止まっても、隔離が空振り
// しても、画面は正常に見えます。落としてから気づくのでは遅いので、
// **この検査の中だけ**でポリシーを厳格版に差し替えて、その世界で何が
// 起きるかを先に見ます。終わったら元に戻します。
//
// ## 差し替える形
//
//	USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
//	       OR current_setting('app.tenant_id', TRUE) = 'system')
//
// migration 450 が足した名乗りの項だけを残し、`IS NULL` と `= ''` を
// 落とした形です。**次の migration で入れる予定のものと同じ文字列**なので、
// ここが緑なら、その migration は一度実物で走ったことになります。
//
// ## 測る 4 通り
//
//	テナント A    自分の行だけが見え、他テナントは見えない
//	テナント B    同上（向きを逆にして、A 専用の細工が無いことを見る）
//	名乗り        両方見える。**ここが落ちると系が全部止まります**
//	素の ctx      **0 行。これが fail-closed の証拠です**
//
// 読みだけでなく書きも見ます。**読めない行が書けると、書けるが二度と
// 読めない行ができます。**

// strictPolicy は「次の migration で入れる形」。
//
// **ここを変えるときは migration 側も一緒に変えてください。** 片方だけ
// 変わると、この検査は実在しない世界を測ることになります。
func strictPolicy(table string) string {
	return fmt.Sprintf(
		`DROP POLICY IF EXISTS %[1]s_tenant_isolation ON %[1]s;
		 CREATE POLICY %[1]s_tenant_isolation ON %[1]s
		     USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
		            OR current_setting('app.tenant_id', TRUE) = 'system');`, table)
}

// alreadyFailClosed は、**もう抜け道を持たない表**です。
//
// **戻し先を間違えると、migration を黙って取り消します。** agents は
// migration 451 で抜け道を落としました。この検査の後始末が「緩い形」で
// 戻すと、テストを走らせるたびに agents の抜け道が復活します ——
// 走らせるほど安全でなくなる検査になります。
//
// 表を落とすたびに、ここに足してください。
var alreadyFailClosed = map[string]bool{
	"agents":    true, // migration 451
	"alerts":    true, // migration 453
	"incidents": true, // migration 454
}

// restorePolicy は「その表の、migration が定めるいまの形」。**戻し先です。**
func restorePolicy(table string) string {
	if alreadyFailClosed[table] {
		return strictPolicy(table)
	}
	return fmt.Sprintf(
		`DROP POLICY IF EXISTS %[1]s_tenant_isolation ON %[1]s;
		 CREATE POLICY %[1]s_tenant_isolation ON %[1]s
		     USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
		            OR current_setting('app.tenant_id', TRUE) = 'system'
		            OR current_setting('app.tenant_id', TRUE) IS NULL
		            OR current_setting('app.tenant_id', TRUE) = '');`, table)
}

var failClosedTables = []string{"agents", "alerts", "incidents", "users"}

// testDatabaseURL — DB が無ければ飛ばします。
//
// **飛ばしたことは、まとめに残ります**（`go test` の SKIP）。
// 「走って通った」と「そもそも走っていない」を同じ緑にしません。
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	return dsn
}

// requireExclusiveDatabase — **この検査は DB を専有します。**
//
// 4 表のポリシーを一時的に差し替えるので、同じ DB を使う他の検査が
// 同時に走っていると巻き添えで落ちます。`go test ./...` は package を
// **並列に**走らせる（`-p` の既定は GOMAXPROCS）ので、通常の実行に
// 混ぜると他 package が「テナント無しで 0 行」になって不安定になります。
//
// **不安定な検査は無視されるようになり、無視される検査は消えます。**
// なので既定では飛ばし、専用の実行でだけ走らせます:
//
//	RLS_FAILCLOSED=1 go test ./internal/store/ -run FailClosed
//
// ci.yml の server-test と scripts/verify.sh がこの形で呼びます。
// **飛ばしたことは SKIP として残ります** —— 「走って通った」と
// 「そもそも走っていない」を同じ緑にしません。
func requireExclusiveDatabase(t *testing.T) {
	t.Helper()
	if os.Getenv("RLS_FAILCLOSED") != "1" {
		t.Skip("RLS_FAILCLOSED=1 が要ります（この検査は DB を専有します。" +
			"`go test ./...` の並列実行に混ぜると他 package を巻き添えにします）")
	}
}

// withStrictPolicies は 4 表を厳格版に差し替え、**必ず元に戻します。**
//
// 戻し損ねると、この検査のあとに走る検査が全部「テナント無しで 0 行」に
// なります。`t.Cleanup` は検査が落ちても走ります。
func withStrictPolicies(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	requireExclusiveDatabase(t)
	ctx := context.Background()

	t.Cleanup(func() {
		for _, table := range failClosedTables {
			if _, err := pool.Exec(context.Background(), restorePolicy(table)); err != nil {
				// **ここが落ちたら、後続の検査がまとめて壊れます。**
				t.Errorf("%s の方針を戻せませんでした。**このデータベースは"+
					"厳格版のまま残っています**: %v", table, err)
			}
		}
	})

	for _, table := range failClosedTables {
		if _, err := pool.Exec(ctx, strictPolicy(table)); err != nil {
			t.Fatalf("%s の方針を差し替えられません: %v", table, err)
		}
	}
}

// failClosedPool は本番と同じ hook を持つプール。
//
// **`SET ROLE edr_app` を足しています。** 検査の接続主体はスーパーユーザ
// なので、RLS を無条件で素通りします（FORCE を付けても、スーパーユーザは
// 対象外です）。本番では `APP_DATABASE_URL` が非スーパーユーザを指すこと
// で同じ状態になります —— **ここで役を替えないと、この検査は「方針が
// 効いている」ではなく「素通りしている」を測ります。**
//
// PrepareConn と AfterRelease は本番の関数そのものです。写しを持つと、
// 検査が通っても本番が同じ経路を通っているとは限りません。
func failClosedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDatabaseURL(t)

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("DSN を読めません: %v", err)
	}
	config.MaxConns = 4
	config.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		if _, err := c.Exec(ctx, `SET ROLE edr_app`); err != nil {
			return false, fmt.Errorf("edr_app になれません（migration 325 未適用）: %w", err)
		}
		return prepareConnForTenant(ctx, c)
	}
	config.AfterRelease = clearConnTenant

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("プールを作れません: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("edr_app で繋げません（migration 325 未適用）: %v", err)
	}
	return pool
}

// **飛ばした理由が「役が無い」なら、それは 1 か所で落とします。**
//
// 上の検査群は `edr_app` が無いと `t.Skip` します。飛ばすこと自体は
// 正しい（役が無ければ測れません）のですが、**飛ばしっぱなしだと
// 「fail-closed を確かめた」と読めてしまいます。**
//
// DB を渡している以上、migration は当たっているはずです。当たっていない
// ことをここ 1 本で落として、上の SKIP が「環境の話」であることを
// はっきりさせます。
func TestTheAppRoleExistsWhenADatabaseIsGiven(t *testing.T) {
	pool := rlsPool(t)
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edr_app')`).Scan(&exists); err != nil {
		t.Fatalf("役を確かめられません: %v", err)
	}
	if !exists {
		t.Fatal("`edr_app` がありません（migration 325 未適用）。" +
			"**RLS の検査はこの役でしか測れないので、すべて飛んでいます** —— " +
			"飛んだことは緑に見えます")
	}
}

// ── 種まき ────────────────────────────────────────────────────────

type tenantRows struct {
	tenant   string
	agent    string
	alert    string
	incident string
	user     string
}

// seedTenantRows は 4 表それぞれに 1 行ずつ。**所有者の接続で入れます**
// （RLS を素通りできる主体でないと、両テナントぶんを用意できません）。
func seedTenantRows(t *testing.T, pool *pgxpool.Pool) tenantRows {
	t.Helper()
	ctx := context.Background()
	r := tenantRows{tenant: makeTenant(t, pool)}
	r.agent = seedAgentFor(t, pool, r.tenant)

	r.alert = uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO alerts (id, severity, title, agent_id, tenant_id)
		 VALUES ($1, 3, $2, $3, $4)`,
		r.alert, "fc-"+r.alert[:8], r.agent, r.tenant); err != nil {
		t.Fatalf("アラートを作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM alerts WHERE id=$1`, r.alert) })

	r.incident = uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO incidents (id, title, tenant_id) VALUES ($1, $2, $3)`,
		r.incident, "fc-"+r.incident[:8], r.tenant); err != nil {
		t.Fatalf("インシデントを作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM incidents WHERE id=$1`, r.incident) })

	r.user = uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, tenant_id) VALUES ($1, $2, $3)`,
		r.user, "fc-"+r.user[:8]+"@example.test", r.tenant); err != nil {
		t.Fatalf("利用者を作れません: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, r.user) })

	return r
}

func (r tenantRows) idFor(table string) string {
	switch table {
	case "agents":
		return r.agent
	case "alerts":
		return r.alert
	case "incidents":
		return r.incident
	case "users":
		return r.user
	}
	return ""
}

// visible は「その ctx で、その行が見えるか」。
//
// **プール経由で引きます。** 直接 `SET` すると、本番が通る
// PrepareConn / AfterRelease を飛ばしてしまいます。
func visible(t *testing.T, pool *pgxpool.Pool, ctx context.Context, table, id string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = $1`, table), id).Scan(&n)
	if err != nil {
		t.Fatalf("%s を読めません: %v", table, err)
	}
	return n > 0
}

// ── ここから検査 ──────────────────────────────────────────────────

// テナントの ctx は、自分の行だけを見ること。**両方向で測ります。**
//
// 片方向だけだと、「A に絞られている」と「たまたま A の行しか無い」の
// 区別が付きません。
func TestFailClosedTenantsSeeOnlyThemselves(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	a := seedTenantRows(t, seedPool)
	b := seedTenantRows(t, seedPool)
	withStrictPolicies(t, seedPool)
	pool := failClosedPool(t)

	ctxA := WithTenant(context.Background(), a.tenant)
	ctxB := WithTenant(context.Background(), b.tenant)

	for _, table := range failClosedTables {
		if !visible(t, pool, ctxA, table, a.idFor(table)) {
			t.Errorf("%s: テナント A が自分の行を見られません。"+
				"**抜け道を落とすと、この経路は空を返します**", table)
		}
		if visible(t, pool, ctxA, table, b.idFor(table)) {
			t.Errorf("%s: テナント A から B の行が見えています。"+
				"**分離が効いていません**", table)
		}
		if !visible(t, pool, ctxB, table, b.idFor(table)) {
			t.Errorf("%s: テナント B が自分の行を見られません", table)
		}
		if visible(t, pool, ctxB, table, a.idFor(table)) {
			t.Errorf("%s: テナント B から A の行が見えています", table)
		}
	}
}

// 名乗った接続は、両方見えること。
//
// **ここが落ちると、抜け道を落とした瞬間に検知・相関・保持削除・集計が
// 全部止まります。** 止まっても落ちないので、気づくのは「アラートが
// 出ない」と誰かが言ったときです。
func TestFailClosedSystemClaimStillSeesEverything(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	a := seedTenantRows(t, seedPool)
	b := seedTenantRows(t, seedPool)
	withStrictPolicies(t, seedPool)
	pool := failClosedPool(t)

	ctx := WithSystemAccess(context.Background())
	for _, table := range failClosedTables {
		if !visible(t, pool, ctx, table, a.idFor(table)) ||
			!visible(t, pool, ctx, table, b.idFor(table)) {
			t.Errorf("%s: 名乗ったのに全テナントが見えません。"+
				"**背景の仕事がここで止まります**", table)
		}
	}
}

// **これが fail-closed の証拠です。**
//
// テナントも名乗りも持たない接続が 0 行になること。いまは抜け道が
// これを通しています —— つまり「設定し忘れ」と「全権限」が同じ形です。
func TestFailClosedBareContextSeesNothing(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	a := seedTenantRows(t, seedPool)
	b := seedTenantRows(t, seedPool)
	withStrictPolicies(t, seedPool)
	pool := failClosedPool(t)

	bare := context.Background()
	sys := WithSystemAccess(context.Background())
	for _, table := range failClosedTables {
		// **先に「行が実在する」ことを確かめます。** これが無いと、
		// 種まきが失敗していても「0 行だから合格」になります ——
		// 何も無い机を見て「散らかっていない」と言うのと同じです。
		if !visible(t, pool, sys, table, a.idFor(table)) ||
			!visible(t, pool, sys, table, b.idFor(table)) {
			t.Fatalf("%s: 名乗った接続からも行が見えません。"+
				"**種まきが効いていないので、この検査は何も測れません**", table)
		}
		if visible(t, pool, bare, table, a.idFor(table)) ||
			visible(t, pool, bare, table, b.idFor(table)) {
			t.Errorf("%s: テナントも名乗りも無い接続に行が見えています。"+
				"**厳格版の方針が効いていません** —— この検査は"+
				"fail-closed を確かめられていません", table)
		}
	}
}

// 書きも同じ条件で絞られること。
//
// **読めない行が書けると、書けるが二度と読めない行ができます。**
// migration 446 / 450 が WITH CHECK を書かず USING に任せているのは、
// 2 つの条件がずれないようにするためです。ここでそれを確かめます。
func TestFailClosedWritesFollowTheSameRule(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	a := seedTenantRows(t, seedPool)
	withStrictPolicies(t, seedPool)
	pool := failClosedPool(t)

	// テナント A の ctx なら、tenant_id を書かなくても列の DEFAULT が
	// `app.tenant_id` を拾うので、A の行として入ります。
	newID := uuid.NewString()
	t.Cleanup(func() {
		_, _ = seedPool.Exec(context.Background(), `DELETE FROM incidents WHERE id=$1`, newID)
	})
	if _, err := pool.Exec(WithTenant(context.Background(), a.tenant),
		`INSERT INTO incidents (id, title) VALUES ($1, $2)`,
		newID, "fc-write"); err != nil {
		t.Fatalf("自テナントへの書き込みが拒まれました: %v", err)
	}
	if !visible(t, pool, WithTenant(context.Background(), a.tenant), "incidents", newID) {
		t.Error("書いた行が、同じテナントから読めません。" +
			"**書けるが読めない行です**")
	}

	// 素の ctx では書けないこと。DEFAULT は既定テナントを入れますが、
	// WITH CHECK（＝ USING）は `= ''` を要求するので通りません。
	orphan := uuid.NewString()
	t.Cleanup(func() {
		_, _ = seedPool.Exec(context.Background(), `DELETE FROM incidents WHERE id=$1`, orphan)
	})
	_, err := pool.Exec(context.Background(),
		`INSERT INTO incidents (id, title) VALUES ($1, $2)`, orphan, "fc-orphan")
	if err == nil {
		t.Error("テナントも名乗りも無い接続が書き込めました。" +
			"**読めない行を作れます**")
	} else if !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("拒まれましたが、理由が RLS ではありません: %v", err)
	}
}

// 接続を使い回しても、前のテナントが残らないこと。
//
// **`AfterRelease` が消し損ねると、次に引いた「テナント無しの仕事」が
// 前のテナントに絞られた結果を読みます。** 抜け道があるうちは全行が
// 見えるので気づけません。厳格版では 0 行になるはずで、**もし前の
// テナントの行が見えたら、消し漏れです。**
func TestFailClosedNoTenantBleedThroughThePool(t *testing.T) {
	requireExclusiveDatabase(t)
	seedPool := rlsPool(t)
	a := seedTenantRows(t, seedPool)
	withStrictPolicies(t, seedPool)

	// 1 本だけのプールにして、**必ず同じ接続が返るようにします。**
	// 複数あると、たまたま別の接続を引いて通ってしまいます。
	dsn := testDatabaseURL(t)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("DSN を読めません: %v", err)
	}
	config.MaxConns = 1
	config.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		if _, err := c.Exec(ctx, `SET ROLE edr_app`); err != nil {
			return false, err
		}
		return prepareConnForTenant(ctx, c)
	}
	config.AfterRelease = clearConnTenant
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("プールを作れません: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("edr_app で繋げません: %v", err)
	}

	if !visible(t, pool, WithTenant(context.Background(), a.tenant), "agents", a.agent) {
		t.Fatal("テナント A で自分の端末が見えません。この検査の前提が崩れています")
	}
	if visible(t, pool, context.Background(), "agents", a.agent) {
		t.Error("接続を返したあと、テナント無しの ctx に前のテナントの端末が" +
			"見えています。**AfterRelease が消し漏らしています**")
	}
}

// 差し替えが本当に効いていること —— **この検査自身の空振り防止。**
//
// `withStrictPolicies` が黙って失敗すると、上の検査は全部「いまの緩い
// 方針」を測って緑を返します。それは「fail-closed を確かめた」と読めて
// しまうので、方針の本文を読んで確かめます。
func TestTheStrictSwapActuallyChangedThePolicies(t *testing.T) {
	requireExclusiveDatabase(t)
	pool := rlsPool(t)
	withStrictPolicies(t, pool)

	for _, table := range failClosedTables {
		var qual string
		err := pool.QueryRow(context.Background(), `
			SELECT COALESCE(pg_get_expr(p.polqual, p.polrelid), '')
			FROM pg_class c
			JOIN pg_policy p ON p.polrelid = c.oid
			WHERE c.relname = $1`, table).Scan(&qual)
		if err != nil {
			t.Fatalf("%s の方針を読めません: %v", table, err)
		}
		if strings.Contains(qual, "IS NULL") || strings.Contains(qual, "= ''::text") {
			t.Errorf("%s の方針に抜け道が残っています。**上の検査は"+
				"fail-closed を測っていません**:\n  %s", table, qual)
		}
		if !strings.Contains(qual, "'system'") {
			t.Errorf("%s の方針から名乗りが消えています。"+
				"**背景の仕事が止まる形になっています**:\n  %s", table, qual)
		}
	}
}
