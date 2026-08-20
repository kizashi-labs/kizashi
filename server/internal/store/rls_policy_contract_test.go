package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RLS の方針が、いつのまにか緩まないこと。
//
// テナント分離の最後の砦は PostgreSQL の行レベルセキュリティです。
// いま有効なのは4テーブル（agents / alerts / incidents / users）で、
// **4つとも FORCE 付き**なので所有者ロールでも効きます。
//
// **agents はもう抜け道を持ちません**（migration 451）。残る 3 表
// (alerts / incidents / users) には、まだこの形が残っています:
//
//	current_setting('app.tenant_id', true) IS NULL
//	OR current_setting('app.tenant_id', true) = ''
//
// **「テナントが設定されていなければ全テナント可」です。** 意図した
// 抜け道でしたが、**「設定し忘れた接続」と「全テナントを見る権利のある
// 接続」が同じ形**になります。実際に一度漏れました —— APIキー認証が
// `tenant_id` に空文字を置き、鍵1本であらゆるテナントの行に届いていました。
//
// 代わりに置いたのが**名乗り**です（migration 450）。全テナントが要る
// 接続は `store.WithSystemAccess` で `app.tenant_id = 'system'` を張ります。
// 忘れた接続は、抜け道を落とした表では 0 行になります。
//
// 落とすのは 1 表ずつです。**壊れる向きが「静かに 0 行」**なので、
// 4 表を一度に落とすと切り分けられません。agents を先にしたのは、
// 検知パイプラインが最も強く依存する表だからです。
//
// この検査は、いまの姿を写して固定します。テーブルが増えたとき、
// 方針が消えたとき、FORCE が外れたときに落ちます。**抜け道の是非では
// なく、それが黙って広がらないことを見ています。**

// needsSystemClaim は「名乗り (`= 'system'`) が要る表」です。
//
// **抜け道の有無とは別の話です。** 抜け道を落とした表は、名乗りが
// 無ければ背景の仕事（検知・相関・保持削除・集計）がそこで 0 行に
// なります。落とす前の表でも、落とした瞬間に同じことが起きます。
// **どちらの状態でも要るので、4 表すべてで見ます。**
var needsSystemClaim = map[string]bool{
	"agents": true, "alerts": true, "incidents": true, "users": true,
}

// rlsTables は RLS を有効にしているテーブルと、その理由です。
var rlsTables = map[string]string{
	"agents":    "端末。隔離などの対応アクションの対象で、テナントを跨ぐと他社の端末を操作できます",
	"alerts":    "検知。生イベントを含み、他社の侵害内容がそのまま読めます",
	"incidents": "インシデント。対応記録と担当者が入ります",
	"users":     "利用者。他社の担当者の氏名とメールが読めます",
	// #683 (アンインストール保護) が RLS 付きで足した 2 表。
	"uninstall_guards": "アンインストール保護の材料 (PBKDF2 の salt と digest)。" +
		"パスワードそのものではないが、テナントを跨ぐと**他社の端末の" +
		"アンインストール保護を突破する材料**になります",
	"uninstall_attempts": "アンインストールの試行記録。どの端末で誰がいつ" +
		"試したかが入り、他社の運用と端末名がそのまま読めます",
}

// permissiveWhenUnset は「app.tenant_id が未設定なら全行」の抜け道を持つ
// テーブルです。**空にできていないのは事実なので、数ではなく名前で残します。**
//
// **agents は落としました**（migration 451）。残る 3 表を落とすときも、
// 同じ手順を踏んでください:
//
//  1. `two_tenant_failclosed_test.go` の演習で、落とした世界を先に測る
//  2. 木全体を `-count=1` で走らせる（**結果キャッシュに注意** ——
//     DB の状態は go test の入力に入らないので、前の成功が再利用されます）
//  3. 落ちたのが台帳だけなら、台帳を更新して落とす
//
// agents ではこの手順で、落ちたのは台帳 2 件だけでした。
var permissiveWhenUnset = map[string]string{
	// agents は **もう抜け道を持ちません**（migration 451）。取り込みと
	// 対応系は `store.WithSystemAccess` で名乗るようになったので、
	// テナント無しで繋ぐ経路はありません。**4 表のうち最初の 1 表です。**
	"alerts":    "検知エンジンとアラートパイプラインがテナント無しで繋ぎます",
	"incidents": "相関エンジンがテナント無しで繋ぎます",
	"users":     "認証がテナントを決める前に利用者を引きます（鶏と卵）",

	// uninstall_guards / uninstall_attempts は **もう抜け道を持ちません**
	// (migration 446)。379 は agents / alerts と同じ形で作りましたが、
	// この2表には「テナントを決められない経路」が1つもありませんでした:
	//
	//   管理コンソール  JWT のテナント。単一テナント配備では JWT が持たない
	//                   ので tenantScope が既定テナントに落として ctx にも
	//                   載せます（載せていなかったのが抜け道への落ち先でした）
	//   ハートビート    端末は名乗らないが、agents 行がテナントを持つ
	//   試行の通報      同じく agents 行から。引けなければ既定テナントへ
	//
	// **問い合わせが絞っていることは、方針が絞っていることの代わりに
	// なりません。** WHERE を書き忘れた1本、あるいは新しく足した1本が、
	// 抜け道の下では全テナントを返します。
}

func rlsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("接続できません: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type rlsPolicy struct {
	table  string
	forced bool
	qual   string
}

func livePolicies(t *testing.T, pool *pgxpool.Pool) map[string]rlsPolicy {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT c.relname, c.relforcerowsecurity,
		       COALESCE(pg_get_expr(p.polqual, p.polrelid), '')
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_policy p ON p.polrelid = c.oid
		WHERE n.nspname = 'public' AND c.relrowsecurity`)
	if err != nil {
		t.Fatalf("方針を読めません: %v", err)
	}
	defer rows.Close()

	out := map[string]rlsPolicy{}
	for rows.Next() {
		var p rlsPolicy
		if err := rows.Scan(&p.table, &p.forced, &p.qual); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[p.table] = p
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func TestRLSPoliciesMatchWhatWeRecorded(t *testing.T) {
	pool := rlsPool(t)
	live := livePolicies(t, pool)

	if len(live) == 0 {
		t.Fatal("RLS を有効にしたテーブルが1つも見つかりません。" +
			"この検査は何も見ていません")
	}

	for table, p := range live {
		reason, known := rlsTables[table]
		if !known {
			t.Errorf("%s が RLS を有効にしていますが、一覧にありません。"+
				"なぜテナント分離が要るのかを rlsTables に書いてください", table)
			continue
		}
		_ = reason

		// FORCE が無いと、所有者ロール（アプリはこれで繋ぎます）は
		// **方針を丸ごと素通りします。** 有効にしただけでは効きません。
		if !p.forced {
			t.Errorf("%s は RLS が FORCE ではありません。アプリは所有者ロールで"+
				"繋ぐので、方針は一度も適用されません", table)
		}
		if p.qual == "" {
			t.Errorf("%s は RLS が有効ですが、方針が1つもありません。"+
				"既定は全拒否なので、読めなくなっています", table)
		}

		// 方針がテナントを見ていること。**これを確かめないと、
		// `USING (true)` —— いちばん緩い方針 —— が「抜け道が無くなった」
		// と報告されます。** 変異で実際にそう出ました: 方針を true に
		// 潰したのに、メッセージは「permissiveWhenUnset から消してください」
		// でした。緩めたことと、絞ったことが同じ姿になっていました。
		if !strings.Contains(p.qual, "tenant_id") {
			t.Errorf("%s の方針が tenant_id を見ていません。"+
				"**テナント分離になっていません**:\n  %s", table, p.qual)
			continue
		}

		permissive := strings.Contains(p.qual, "IS NULL") ||
			strings.Contains(p.qual, "= ''::text")
		_, recorded := permissiveWhenUnset[table]
		if permissive && !recorded {
			t.Errorf("%s の方針は app.tenant_id が未設定なら全行を許します。"+
				"**新しくこの形を足すなら、なぜ要るのかを permissiveWhenUnset に"+
				"書いてください。** 書けないなら、それは抜け道です:\n  %s",
				table, p.qual)
		}
		if !permissive && recorded {
			t.Errorf("%s は抜け道を持たなくなりました。"+
				"permissiveWhenUnset から消してください", table)
		}

		// 抜け道を持つ表は、**名乗りの項も持っていること**（migration 450）。
		//
		// 抜け道を落とすとき、名乗りの項が無い表は**そのまま 0 行**に
		// なります。落とす側と受ける側は別の migration なので、片方だけ
		// 入った状態が実在します。ここが落ちるのは「まだ落とせない」の
		// 合図です。
		if needsSystemClaim[table] && !strings.Contains(p.qual, "'system'") {
			t.Errorf("%s は抜け道を持ちますが、名乗り（`= 'system'`）の項が"+
				"ありません。**この表だけ、抜け道を落とした瞬間に系が"+
				"0 行になります**:\n  %s", table, p.qual)
		}
	}

	for table := range rlsTables {
		if _, ok := live[table]; !ok {
			t.Errorf("%s を RLS 有効として記録していますが、"+
				"実際には有効ではありません。**テナント分離が外れています**", table)
		}
	}
}

// テナント分離が、方針として正しいこと。
//
// **接続しているロールが誰かに左右されないよう、`SET ROLE edr_app` で
// 測ります。** 既定の接続主体（スーパーユーザ edr）は RLS を無条件で
// 素通りするので、そのまま測ると「方針が壊れている」と「ロールが
// 素通りしている」の区別が付きません。migration 325 が用意している
// 本番用の非スーパーユーザ・ロールで、方針そのものを見ます。
func TestRLSSeparatesTenantsUnderTheAppRole(t *testing.T) {
	pool := rlsPool(t)
	ctx := context.Background()

	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	agentA, agentB := seedAgentFor(t, pool, tenantA), seedAgentFor(t, pool, tenantB)

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
		`SELECT set_config('app.tenant_id', $1, false)`, tenantA); err != nil {
		t.Fatalf("app.tenant_id を設定できません: %v", err)
	}

	seen := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT id::text FROM agents WHERE id = ANY($1::uuid[])`,
		[]string{agentA, agentB})
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if !seen[agentA] {
		t.Error("自分のテナントの端末が見えません。分離が強すぎます")
	}
	if seen[agentB] {
		t.Error("他テナントの端末が見えています。**方針が効いていません**")
	}
}

// テナントを設定しない接続が、agents では **0 行**になること。
//
// **これが fail-closed です**（migration 451）。以前ここは「全部見える」を
// 記録していました —— 抜け道が実在することの写しで、「良い」ではなく
// 「いまこうなっている」の記録でした。落としたので、向きが逆になります。
//
// 取り込み・検知・スケジューラは `store.WithSystemAccess` で名乗るように
// なったので、この 0 行に当たりません。**当たるとしたら、それは名乗り
// 忘れです** —— 忘れたら見えない、が新しい既定です。
func TestAnUnsetConnectionSeesNoAgents(t *testing.T) {
	pool := rlsPool(t)
	ctx := context.Background()

	tenantA, tenantB := makeTenant(t, pool), makeTenant(t, pool)
	agentA, agentB := seedAgentFor(t, pool, tenantA), seedAgentFor(t, pool, tenantB)

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("接続を取れません: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET ROLE edr_app`); err != nil {
		t.Skipf("edr_app ロールがありません: %v", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM agents WHERE id = ANY($1::uuid[])`,
		[]string{agentA, agentB}).Scan(&n); err != nil {
		t.Fatalf("読めません: %v", err)
	}
	if n != 0 {
		t.Errorf("テナントも名乗りも無い接続に agents が %d 件見えています"+
			"（0 件のはず）。**migration 451 の抜け道除去が効いていません** —— "+
			"「設定し忘れ」と「全テナントを見る権利」がまた同じ形です", n)
	}

	// **行が実在することも確かめます。** 種まきが効いていなくても
	// 「0 件だから合格」になってしまうので、名乗った接続から見えることを
	// 見ます —— 何も無い机を見て「散らかっていない」と言わないために。
	if _, err := conn.Exec(ctx,
		`SELECT set_config('app.tenant_id', 'system', false)`); err != nil {
		t.Fatalf("名乗れません: %v", err)
	}
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM agents WHERE id = ANY($1::uuid[])`,
		[]string{agentA, agentB}).Scan(&n); err != nil {
		t.Fatalf("読めません: %v", err)
	}
	if n != 2 {
		t.Fatalf("名乗った接続からも %d 件しか見えません（2件のはず）。"+
			"**種まきが効いていないので、この検査は何も測れていません**", n)
	}
}

// 既定の接続主体が RLS を素通りすることを、記録として固定します。
//
// **方針が正しくても、素通りするロールで繋げば一度も適用されません。**
// migration 325 のコメントが書いているとおり、既定は意図的にこの状態です
// （edr_app は NOLOGIN・パスワード未設定で、切替はオペレータの2手順）。
//
// この検査は良し悪しを言いません。**変わったときに気づくため**にあります ——
// 切り替えたのに気づかない、あるいは切り替えたつもりで戻っている、の
// どちらも落とします。
func TestWhetherTheConnectingRoleBypassesRLSIsRecorded(t *testing.T) {
	pool := rlsPool(t)

	// TEST_DATABASE_URL が誰で繋いでいるか。CI とローカルでは所有者
	// （スーパーユーザ）です。本番で APP_DATABASE_URL に切り替えると
	// edr_app になり、ここが false になります。
	const recordedBypass = true

	var super, bypass bool
	if err := pool.QueryRow(context.Background(),
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&super, &bypass); err != nil {
		t.Fatalf("ロールを読めません: %v", err)
	}
	got := super || bypass
	if got != recordedBypass {
		t.Errorf("接続ロールが RLS を素通りするか = %v（記録は %v）。\n"+
			"true→false なら、テナント分離が実効するようになりました ——"+
			"喜ばしいことなので recordedBypass を false にして、"+
			"docs/security/マルチテナント分離ハードニング.md を更新してください。\n"+
			"false→true なら、**分離が外れています。**", got, recordedBypass)
	}
}

func seedAgentFor(t *testing.T, pool *pgxpool.Pool, tenant string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (id, hostname, os_type, status, source, settings, tenant_id)
		 VALUES ($1, $2, 'linux', 'online', 'agent', '{}'::jsonb, $3)`,
		id, "rls-"+id[:8], tenant); err != nil {
		t.Fatalf("エージェントを作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id = $1`, id)
	})
	return id
}
