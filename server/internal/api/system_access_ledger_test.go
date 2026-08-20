package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 全テナントを名乗る経路の台帳。
//
// ## なぜ台帳が要るか
//
// 4 表 (agents / alerts / incidents / users) の RLS は、いま
// `app.tenant_id` が未設定なら全行を通します。**「設定し忘れた接続」と
// 「全テナントを見る権利のある接続」が同じ形をしています。** 落ちた側に
// 倒れるのが「全部見える」なので、事故は静かです。実際に一度起きました
// —— APIキー認証が空文字を置き、鍵 1 本で全テナントに届いていました。
//
// migration 450 が「名乗り」の項を足し、`store.WithSystemAccess` を通った
// 接続だけが全テナントになります。抜け道を落とすのは次の migration で、
// そのとき**名乗っていない経路は 0 行**になります。
//
// **名乗れる場所が増えるほど、名乗りは既定に戻ります。** ここは増えた
// ことが見えるようにするための一覧で、数ではなく名前で持ちます。
//
// ## この検査が見ていないこと
//
// router.go の公開経路を機械的に数え上げてはいません。gin の group 変数は
// 関数をまたいで同じ名前が使われるので（`dw` が 2 か所、`v1` / `taxii` も）、
// 素朴な走査は誤判定します。ここが留めるのは **`sysAccess` を張った場所と
// この一覧が 1:1 であること**だけです。新しい公開経路が 4 表に触るのに
// 張り忘れた場合、この検査は落ちません —— **抜け道を落とした時点で
// 0 行になって落ちます。** それが分かるようにここに書いておきます。
var systemAccessRoutes = map[string]string{
	// ── group ごと ──────────────────────────────────────────
	"auth":           "users。**テナントは利用者を引いて初めて決まります**（鶏と卵）",
	"invitePublic":   "users。招待の宛先を作ります",
	"pwReset":        "users。メールアドレスから利用者を引きます",
	"emailMFAPublic": "users。ログインの途中で、まだテナントが決まっていません",
	"evPublic":       "users。確認トークンから利用者を引きます",
	"lrAgent":        "agents。端末は名乗りますが、テナントは名乗りません",
	"ingestGroup":    "agents / alerts。外部からの取り込み。トークン認証のみ",

	// ── 経路ごと ────────────────────────────────────────────
	"/agents/:id/heartbeat":         "agents。端末は名乗りますが、テナントは名乗りません",
	"/agents/:id/software/report":   "agents",
	"/agents/:id/encryption/report": "agents",
	"/agents/:id/hardening/report":  "agents",
	"/agents/:id/yara-rules":        "agents",
	"/agents/:id/scan-results":      "agents / alerts",
	"/agents/:id/quarantine-result": "agents",
	"/ingest/:source_name":          "agents / alerts",
	"/enrollment/request":           "agents。登録。**この時点では行がありません**",
}

// undecidedPublicRoutes は公開経路のうち、4 表に触るかどうかを
// **まだ確かめていない**ものです。
//
// **空にできていないのは事実なので、黙って落とさず名前で残します。**
// 触らないなら消してください。触るなら systemAccessRoutes に移して
// `sysAccess` を張ってください。**どちらかが決まるまで、抜け道は
// 落とせません** —— 落とすと、ここが 0 行になって静かに壊れます。
var undecidedPublicRoutes = map[string]string{
	"/agents/:id/cert/ca": "CA 証明書を返します。agents 行を引いているかを未確認",
	"/api/v1/process-rules/agent/:agent_id": "端末ごとのプロセス規則。" +
		"agents との結合があるかを未確認",
	"/ws/alerts":            "alerts を流します。token クエリでの認証があるかを未確認",
	"/ws/agents/:id/events": "同上（agents）",
	"/taxii2":               "TAXII 2.1 の公開エンドポイント。4 表に触るかを未確認",
	"/api/v1/stream":        "SSE。注釈は authMiddleware で守られると書いていますが、group に付いていません",
}

var (
	useSysAccess   = regexp.MustCompile(`^\s*(\w+)\.Use\(sysAccess\)`)
	routeSysAccess = regexp.MustCompile(`\.(?:GET|POST|PUT|PATCH|DELETE|Any)\("([^"]*)",\s*sysAccess,`)
)

func wiredSystemAccess(t *testing.T) map[string]int {
	t.Helper()
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	got := map[string]int{}
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue // 注釈。**説明している場所ほど数えてしまいます**
		}
		if m := useSysAccess.FindStringSubmatch(line); m != nil {
			got[m[1]]++
		}
		if m := routeSysAccess.FindStringSubmatch(line); m != nil {
			got[m[1]]++
		}
	}
	return got
}

func TestEverySystemAccessIsInTheLedger(t *testing.T) {
	got := wiredSystemAccess(t)
	if len(got) == 0 {
		t.Fatal("router.go に sysAccess が1つもありません。**この検査は何も見ていません**")
	}
	for name := range got {
		if _, ok := systemAccessRoutes[name]; !ok {
			t.Errorf("%s に sysAccess を張っていますが、台帳にありません。"+
				"**なぜ全テナントが要るのかを systemAccessRoutes に書いてください。**"+
				"書けないなら、それは張りすぎです", name)
		}
	}
}

func TestEveryLedgerEntryIsActuallyWired(t *testing.T) {
	got := wiredSystemAccess(t)
	var missing []string
	for name := range systemAccessRoutes {
		if got[name] == 0 {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s を台帳に書いていますが、router.go で張っていません。"+
			"**台帳にあることと、張ってあることは別です** —— "+
			"抜け道を落とした時点でこの経路は 0 行になります", name)
	}
}

func TestNoLedgerEntryIsWiredTwice(t *testing.T) {
	// 同じ group に 2 回張っても害はありませんが、**片方を消したときに
	// 「消した」が効かなくなります。**
	for name, n := range wiredSystemAccess(t) {
		if n > 1 {
			t.Errorf("%s に sysAccess を %d 回張っています。1 回にしてください", name, n)
		}
	}
}

func TestTheUndecidedListIsNotSilentlyWired(t *testing.T) {
	got := wiredSystemAccess(t)
	for name := range undecidedPublicRoutes {
		if got[name] > 0 {
			t.Errorf("%s は「未判定」の一覧にありますが、sysAccess を張っています。"+
				"**判定してから張ってください** —— "+
				"undecidedPublicRoutes から systemAccessRoutes に移してください", name)
		}
		if _, both := systemAccessRoutes[name]; both {
			t.Errorf("%s が両方の一覧にあります。どちらかにしてください", name)
		}
	}
}

// **未判定が空になったら、この検査が教えます。** 空になって初めて
// エスケープ節を落とせます（落とすと、名乗っていない経路は 0 行）。
func TestTheUndecidedListStillHasEntries(t *testing.T) {
	if len(undecidedPublicRoutes) != 0 {
		t.Logf("公開経路のうち %d 件が未判定です。"+
			"**これが 0 になるまで RLS のエスケープ節は落とせません**",
			len(undecidedPublicRoutes))
		return
	}
	t.Log("未判定が空になりました。**エスケープ節を落とせます** —— " +
		"migration で 4 表の `IS NULL` / `= ''` の項を外し、" +
		"この検査と undecidedPublicRoutes を消してください")
}
