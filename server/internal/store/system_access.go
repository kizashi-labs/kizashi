package store

import "context"

// 全テナントを見る接続に、**名乗らせる**。
//
// ## いまの形
//
// 4 表 (agents / alerts / incidents / users) の RLS 方針は、
// `app.tenant_id` が未設定なら全行を通します:
//
//	USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
//	       OR current_setting('app.tenant_id', TRUE) IS NULL
//	       OR current_setting('app.tenant_id', TRUE) = '')
//
// **「設定し忘れた接続」と「全テナントを見る権利のある接続」が、
// 同じ形をしています。** 落ちた側に倒れるのが「全部見える」なので、
// 事故は静かで、見つかるのは漏れたあとです。実際に一度起きました ——
// APIキー認証が `tenant_id` に空文字を置き、**鍵 1 本であらゆるテナントの
// 行に届いていました。**
//
// ## 名乗り
//
// `SystemTenant` は「全テナントを見る」と明示的に言うための値です。
// migration 450 が方針に項を足し、名乗った接続だけを通します。
// 忘れた接続は（エスケープ節を落としたあと）**0 行**になります。
//
// 落ちる向きが逆になるのが要点で、**忘れたら見えない**なら、事故は
// 漏れではなく機能停止として出ます。片方は静かで、もう片方は騒がしい。
//
// ## ロールを分ける案との違い
//
// docs/security/RLS-fail-closed設計.md は `edr_worker` ロールを作って
// ロール別方針で分ける形でした。測った結果、この配備では効きません:
//
//   - 既定の配備は DSN が 1 本です（`APP_DATABASE_URL` は未設定で
//     `DATABASE_URL` に落ちます）。**API と系が同じロールで繋ぐので、
//     ロール別方針は両者を区別できません。**
//   - CI の Postgres も所有者 `edr` の 1 本です。つまりロール案は
//     **CI で一度も実行されません。**
//
// 名乗りは方針の中で完結するので、どのロールで繋いでいても効きます。
// ロール分割と併用もできます（多層防御としては上乗せになります）。
const SystemTenant = "system"

// systemAccessKey は「全テナントを見る」を運ぶ鍵です。
//
// **`TenantContextKey` と別にしてあります。** 同じ鍵に "system" という
// 文字列を入れる形にすると、JWT の `tenant_id` に "system" を入れた
// 相手が全テナントを名乗れます。値ではなく**鍵で**区別すれば、
// 外から来た文字列がこの経路に入ることはありません。
type systemAccessKey struct{}

// WithSystemAccess marks ctx as needing all-tenant access.
//
// 使う場所は 2 つだけです:
//
//	背景の仕事      cmd/{api,ingestion,detection} のプロセス ctx。
//	                検知・相関・保持削除・集計はテナントを跨ぎます。
//	認証前の経路    ログイン・ハートビート・登録・取り込み。
//	                **テナントが決まる前に走ります**（鶏と卵）。
//
// **それ以外に足さないでください。** 足せる場所が増えるほど、
// 「名乗り」は「既定」に戻ります。台帳
// (internal/api/system_access_ledger_test.go) が一覧を留めます。
func WithSystemAccess(ctx context.Context) context.Context {
	return context.WithValue(ctx, systemAccessKey{}, true)
}

// systemAccessFromContext reports whether ctx named itself as all-tenant.
func systemAccessFromContext(ctx context.Context) bool {
	on, _ := ctx.Value(systemAccessKey{}).(bool)
	return on
}

// WithTenant carries a tenant into a context that does not inherit one.
//
// **要求から離れる仕事のためにあります。** ハンドラが `go func()` で
// 続きを走らせるとき、`context.Background()` から新しい ctx を作ります
// —— 要求の ctx は応答を返した時点で切れるからです。**そこでテナントが
// 落ちます。**
//
// 落ちた ctx は `app.tenant_id` を張らないので、いまは RLS のエスケープ節
// が拾って**全テナントを見せます**。つまり:
//
//	テナント A が頼んだレポートに、B のアラートが入ります
//	テナント A が始めた資産探索が、B の端末を数えます
//
// **これは fail-closed 化を待たずに直すべき漏れです。** 抜け道を落とせば
// 0 行になって止まりますが、それは「止まる」であって「正しくなる」では
// ありません。要求のテナントを持っていくのが正しい形です。
//
// 全テナントが要る背景の仕事（検知・相関・保持削除）は
// `WithSystemAccess` です。**こちらは要求から生えた仕事のためのもの**で、
// 使い分けを間違えると、片方は漏れ、もう片方は止まります。
func WithTenant(ctx context.Context, tenantID string) context.Context {
	if tenantID == "" {
		return ctx
	}
	return context.WithValue(ctx, TenantContextKey{}, tenantID)
}
