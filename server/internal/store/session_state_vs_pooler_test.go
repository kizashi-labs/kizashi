package store

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// **セッションに残す設定と、トランザクション単位の接続プーラは両立しません。**
//
// テナントの絞り込みは PostgreSQL の RLS が行い、その入力は接続の
// セッション変数 `app.tenant_id` 1つです（`prepareConnForTenant`）。
// 第3引数の `false` は「セッション有効」で、**そうでないと、設定した
// Exec の暗黙のトランザクションが終わった時点で消え、同じ要求の続きの
// クエリからは見えません** —— `postgres.go` のコメントにその通り
// 書いてあります。
//
// **`deploy/docker/pgbouncer.ini` は `pool_mode = transaction` です。**
// トランザクション単位のプーリングは、まさに「トランザクションが
// 終わった時点で別のサーバ接続に移る」ことをします。さらに
// `server_reset_query = DISCARD ALL` がセッション状態を明示的に消します。
// `docker-compose.scale.yml` は**8つのサービス全部の `DATABASE_URL` を
// pgbouncer に向けています。**
//
// 実測 (2026-08-12)。PostgreSQL 16 と pgbouncer 1.22 を同じ設定で立て、
// `Connect()` が組み立てるプールと同じ形（`PrepareConn` =
// `prepareConnForTenant`）で、テナント A の要求を 200 回:
//
//	直接つないだとき            見えた行 1 が 200 回
//	pgbouncer 経由（transaction） 見えた行 2 が 199 回、1 が 1 回
//
// **2 は「両方のテナントの行」です。** RLS のポリシーは
// `app.tenant_id IS NULL OR ''` を全件アクセスとして通すので
// （migration 027 / 324）、セッション変数が届かない接続では**絞り込みが
// 事実上外れます。**
//
// もう1つ実測されたこと: pgx の既定（拡張プロトコル＋文キャッシュ）では
// pgbouncer の transaction モードに**そもそも繋がりません**
// （`prepared statement "stmtcache_…" already exists`, SQLSTATE 42P05）。
// 上の 199/200 は `default_query_exec_mode=simple_protocol` を足して
// 初めて測れました。**いまの `docker-compose.scale.yml` は、繋がらない
// ことで漏れていないだけ**です。
//
// どう直すかは配置の判断なので、`docs/判断待ちの一覧.md` に置いて
// あります（session プーリングにする／絞り込みをセッション状態から
// 外す）。**この検査は、判断が済むまで黙って進まないためのものです。**

// 読む先。**リポジトリの中の、実際に配られる設定です。**
const (
	poolerConfigPath  = "../../../deploy/docker/pgbouncer.ini"
	scaleComposePath  = "../../../docker-compose.scale.yml"
	tenantSourcePath  = "postgres.go"
	sessionScopedCall = "set_config('app.tenant_id', $1, false)"
)

// **床。** ここが 0 でも `broken()` は false になり、検査は黙ります ——
// 「プーラを経由していない配置」と「読む先を間違えた」が同じ形に
// なります。実測 (2026-08-12): 7 サービス。
const routedFloor = 5

var poolModeLine = regexp.MustCompile(`(?m)^\s*pool_mode\s*=\s*(\w+)`)

// poolerVerdict is the judgement, kept out of the test body so it can be
// exercised with combinations that do not exist in the tree.
type poolerVerdict struct {
	sessionScoped bool // コードがセッションに残す設定に頼っている
	poolMode      string
	routed        bool // 配置がサービスをプーラ経由にしている
}

// broken reports whether this combination silently turns tenant filtering off.
func (v poolerVerdict) broken() bool {
	return v.sessionScoped && v.routed &&
		(v.poolMode == "transaction" || v.poolMode == "statement")
}

func TestSessionScopedTenantStateIsNotBehindATransactionPooler(t *testing.T) {
	src, err := os.ReadFile(tenantSourcePath)
	if err != nil {
		t.Fatalf("%s を読めません: %v", tenantSourcePath, err)
	}
	v := poolerVerdict{sessionScoped: strings.Contains(string(src), sessionScopedCall)}
	if !v.sessionScoped {
		t.Fatalf("%s に %q が見つかりません。**テナントの絞り込みが"+
			"セッション変数から離れたなら、この検査を書き直してください** ——"+
			"探して無かったのと探していないのは、ここでは同じ形になります",
			tenantSourcePath, sessionScopedCall)
	}

	ini, err := os.ReadFile(poolerConfigPath)
	if err != nil {
		t.Fatalf("%s を読めません: %v", poolerConfigPath, err)
	}
	m := poolModeLine.FindStringSubmatch(string(ini))
	if m == nil {
		t.Fatalf("%s に pool_mode がありません", poolerConfigPath)
	}
	v.poolMode = m[1]

	compose, err := os.ReadFile(scaleComposePath)
	if err != nil {
		t.Fatalf("%s を読めません: %v", scaleComposePath, err)
	}
	routed := strings.Count(string(compose), "@pgbouncer:")
	v.routed = routed > 0

	if routed < routedFloor {
		t.Fatalf("%s の中で pgbouncer を向いている DATABASE_URL が %d 個"+
			"しかありません（床 %d）。**読む先が動いたなら追ってください** ——"+
			"0 個なら、この検査は何も言わずに通ります",
			scaleComposePath, routed, routedFloor)
	}

	if v.broken() {
		t.Errorf("`pool_mode = %s` のプーラに %d 個のサービスの "+
			"DATABASE_URL が向いていますが、テナントの絞り込みは"+
			"セッション変数 `app.tenant_id` 1つに乗っています。\n"+
			"  **実測 (2026-08-12): テナント A の要求 200 回のうち 199 回が、"+
			"両方のテナントの行を見ました。**\n"+
			"  RLS のポリシーは `app.tenant_id` が空のとき全件を通します"+
			"（migration 027 / 324）。トランザクション単位のプーリングは"+
			"セッション変数を次のクエリまで運びません。\n"+
			"  直し方は `docs/判断待ちの一覧.md` にあります"+
			"（session プーリングにする／絞り込みをセッション状態から外す）。",
			v.poolMode, routed)
	}
}

// 判定そのものが動くこと。木が直ったあと、上の検査は何も言わなくなります。
func TestThePoolerRuleActuallyFires(t *testing.T) {
	for _, c := range []struct {
		name string
		v    poolerVerdict
		want bool
	}{
		{"いまの木", poolerVerdict{true, "transaction", true}, true},
		{"statement プーリング", poolerVerdict{true, "statement", true}, true},
		{"session プーリング", poolerVerdict{true, "session", true}, false},
		{"プーラを経由しない", poolerVerdict{true, "transaction", false}, false},
		{"セッションに頼っていない", poolerVerdict{false, "transaction", true}, false},
		{"何も無い", poolerVerdict{}, false},
	} {
		if got := c.v.broken(); got != c.want {
			t.Errorf("%s: broken = %v, want %v", c.name, got, c.want)
		}
	}
}

// 読む先が実在すること。**3つとも読めなければ、この検査は「探したが
// 無かった」を「問題無し」と読みます。**
func TestThePoolerScanReadsRealFiles(t *testing.T) {
	for _, p := range []string{poolerConfigPath, scaleComposePath, tenantSourcePath} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s を読めません: %v", p, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("%s が空です", p)
		}
	}
	if got := poolModeLine.FindStringSubmatch("pool_mode       = transaction\n"); got == nil || got[1] != "transaction" {
		t.Errorf("pool_mode を読めていません: %v", got)
	}
	if poolModeLine.MatchString("; pool_mode = session\n") {
		t.Error("コメント行の pool_mode を読んでいます")
	}
	// **床そのものが意味を持っていること。** 0 にすると、読む先を
	// 間違えても検査は黙ります —— 「プーラを経由していない配置」と
	// 「読めていない」が同じ形になります。
	if routedFloor < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}
