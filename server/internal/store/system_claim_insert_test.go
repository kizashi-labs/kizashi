package store

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 名乗った接続が、4 表に**書ける**こと。
//
// ## 見落としました
//
// `alerts` / `incidents` / `users` の `tenant_id` 列は、DEFAULT で
// `app.tenant_id` を読みます:
//
//	COALESCE(NULLIF(current_setting('app.tenant_id', true), '')::uuid,
//	         '00000000-0000-0000-0000-000000000001'::uuid)
//
// **`'system'::uuid` は uuid として不正です。** 名乗った接続が
// `tenant_id` を書かずに INSERT すると、
//
//	ERROR: invalid input syntax for type uuid: "system"
//
// で落ちます。`SaveAlert` は `tenant_id` を書きません —— **列の DEFAULT が
// ctx のテナントを読むことに寄りかかった設計**で、それは意図されたもの
// です（`encryptionTenant` の注釈が「同じ出どころなので、行の tenant_id と
// 鍵のテナントは構造上ずれません」と書いています）。
//
// 名乗りを入れたとき、そこを見ていませんでした。**検知エンジンと取り込みは
// 名乗る側なので、アラートが 1 件も書けなくなっていました。**
//
// ## なぜ検査をすり抜けたか
//
//   - store の検査はほとんどスーパーユーザで繋ぎます。**RLS は素通り
//     しますが、列の DEFAULT は役に関係なく評価されます** —— つまり
//     RLS の話ではなく、この経路を名乗りで通した検査が無かっただけです。
//   - 演習 (`two_tenant_failclosed_test.go`) は**テナントの ctx で**書き、
//     素の ctx で拒まれることを見ていました。**名乗りで書く経路が
//     抜けていました。**
//
// ここはその穴を塞ぎます。4 表すべてを、名乗った接続から書きます。

// insertableWithoutTenant は「tenant_id を書かずに INSERT する経路が
// 実在する表」と、その最小の INSERT です。
//
// agents は DEFAULT が固定値なので `app.tenant_id` を読みません。
// それでも入れてあるのは、**将来 DEFAULT を揃えたときに気づくため**です。
var insertableWithoutTenant = map[string]string{
	"agents": `INSERT INTO agents (id, hostname, os_type, status, source, settings)
	           VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb)`,
	"alerts": `INSERT INTO alerts (id, severity, title)
	           VALUES ($1, 3, $2)`,
	"incidents": `INSERT INTO incidents (id, title) VALUES ($1, $2)`,
	"users":     `INSERT INTO users (id, email) VALUES ($1, $2)`,
}

// label は 2 つめの引数。**`$1` を文字列としても使うと型が決まらず
// 42P08 になります**（id は uuid 列なので）。別の引数にして避けます。
func label(table, id string) string {
	if table == "users" {
		return "sc-" + id[:8] + "@example.test"
	}
	return "sc-" + id[:8]
}

// **名乗った接続が書けること。** ここが落ちると、検知エンジンと取り込みは
// アラートを 1 件も書けません —— しかも落ち方は例外なので、**静かでは
// ありません**。それでも気づかなかったのは、この経路を通す検査が
// 無かったからです。
func TestASystemClaimCanWriteToEveryTable(t *testing.T) {
	pool := claimWritePool(t)
	ctx := WithSystemAccess(context.Background())

	for table, stmt := range insertableWithoutTenant {
		id := uuid.NewString()
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(),
				"DELETE FROM "+table+" WHERE id = $1", id)
		})
		if _, err := pool.Exec(ctx, stmt, id, label(table, id)); err != nil {
			t.Errorf("%s: 名乗った接続が書けません: %v\n"+
				"    **`tenant_id` 列の DEFAULT が `app.tenant_id` を uuid に"+
				"変換しようとしていませんか。** `'system'` は uuid では"+
				"ないので落ちます", table, err)
			continue
		}

		// 書けたなら、**同じ接続から読めること**。書けるが読めない行は、
		// 二度と触れません。
		var n int
		if err := pool.QueryRow(ctx,
			"SELECT count(*) FROM "+table+" WHERE id = $1", id).Scan(&n); err != nil {
			t.Errorf("%s: 書いた行を読めません: %v", table, err)
			continue
		}
		if n != 1 {
			t.Errorf("%s: 書いた行が、書いた接続から見えません（%d 件）。"+
				"**書けるが読めない行です**", table, n)
		}
	}
}

// テナントを名乗った接続も、同じように書けること。
//
// **名乗りを直すときに、こちらを壊さないための対です。** DEFAULT の式を
// いじるので、両方が同時に成り立つことを見ます。
func TestATenantCanStillWriteWithoutNamingTheColumn(t *testing.T) {
	pool := claimWritePool(t)
	seed := rlsPool(t)
	tenant := makeTenant(t, seed)
	ctx := WithTenant(context.Background(), tenant)

	for table, stmt := range insertableWithoutTenant {
		id := uuid.NewString()
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(),
				"DELETE FROM "+table+" WHERE id = $1", id)
		})
		if _, err := pool.Exec(ctx, stmt, id, label(table, id)); err != nil {
			t.Errorf("%s: テナントの接続が書けません: %v", table, err)
			continue
		}

		// agents は DEFAULT が固定値なので、テナントは既定のままです。
		// **そこは今回の対象ではありません** —— 落ちないことだけを見ます。
		if table == "agents" {
			continue
		}
		var got string
		if err := pool.QueryRow(ctx,
			"SELECT tenant_id::text FROM "+table+" WHERE id = $1", id).Scan(&got); err != nil {
			t.Errorf("%s: 書いた行を読めません: %v", table, err)
			continue
		}
		if got != tenant {
			t.Errorf("%s: 列の DEFAULT が ctx のテナントを拾っていません "+
				"(got %s, want %s)。**行のテナントと、暗号化に使う鍵の"+
				"テナントがずれます**", table, got, tenant)
		}
	}
}

// claimWritePool は本番と同じ hook を持つプール。
//
// **役は替えません。** ここで見たいのは RLS ではなく**列の DEFAULT** で、
// DEFAULT は接続主体に関係なく評価されます。役を替えると、RLS の
// 絞り込みが混ざって「どちらで落ちたのか」が分からなくなります。
func claimWritePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDatabaseURL(t)

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("DSN を読めません: %v", err)
	}
	config.MaxConns = 4
	config.PrepareConn = prepareConnForTenant
	config.AfterRelease = clearConnTenant

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("プールを作れません: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("繋げません: %v", err)
	}
	return pool
}

// **列の DEFAULT が `'system'` を uuid にしようとしていないこと。**
//
// 上の検査は落ちれば教えてくれますが、理由は式を読まないと分かりません。
// ここは式そのものを見て、次に触る人に何を直すのかを示します。
func TestTheTenantDefaultToleratesTheSystemClaim(t *testing.T) {
	pool := rlsPool(t)
	for table := range insertableWithoutTenant {
		var def string
		if err := pool.QueryRow(context.Background(), `
			SELECT COALESCE(column_default, '')
			FROM information_schema.columns
			WHERE table_name = $1 AND column_name = 'tenant_id'`, table).Scan(&def); err != nil {
			t.Fatalf("%s: DEFAULT を読めません: %v", table, err)
		}
		if !strings.Contains(def, "current_setting") {
			continue // 固定値。`app.tenant_id` を読まないので関係ありません
		}
		if !strings.Contains(def, "'system'") {
			t.Errorf("%s の tenant_id の DEFAULT が `app.tenant_id` を読みますが、"+
				"`'system'` を除いていません。**名乗った接続からの INSERT が "+
				"`invalid input syntax for type uuid` で落ちます**:\n  %s",
				table, def)
		}
	}
}
