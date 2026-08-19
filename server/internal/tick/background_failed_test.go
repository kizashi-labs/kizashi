package tick_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// **`metrics.BackgroundFailed` を、どこで呼んでよいか。**
//
// 失敗を報告する綴りは3つあります。実測 (2026-08-12):
//
//	fail(ctx, err, msg)                  147 箇所（internal/scheduler の中だけ）
//	metrics.BackgroundFailed(comp, …)     58 箇所（18 package）
//	tick.Fail / tick.FailComponent        …   （internal/tick）
//
// **どれも「失敗を報告する」ですが、答える問いが違います:**
//
//	BackgroundFailed  この部品が失敗した（edr_background_failures_total）
//	Fail              この回が仕事を終えられなかった（last_success を押さない）
//	FailComponent     その両方
//
// 「回」があるのは、**周期的に回る仕事の中だけ**です。`tick.Run` /
// `trackRun` で回している仕事の中で `BackgroundFailed` を直に呼ぶのは
// 違反で、それは `TestTrackedWorkersDoNotReportPastTheRun` が 0 件に
// 留めています。
//
// **ここは、その外の 58 か所を分類して留めます。** 読んでみて、1つは
// 分類できませんでした —— `detection/correlation.go:upsertCase` は
// `tick.Run` で回している `runOnce` から呼ばれています。直に渡している
// 関数しか見ていなかったので、上の検査からも漏れていました。
// `tick.FailComponent` に移し、残り 56 を分類しました。
// 前に「そのままで
// 正しいはず」と書いたまま確かめていなかったので、1つずつ読みました。
// 分類は5つで、**どれも「回」の単位を持ちません**:
//
//	起動時        プロセス起動時に一度だけ。次の回はありません。
//	要求ごと      利用者が待っていて、応答でも分かります。
//	イベントごと  1件ごと。呼び出し側は次のイベントです。
//	errorを返す   呼び出し側が受け取ります。件数はここが足します。
//	仕組み        `internal/tick` 自身。
//
// **新しく増えた箇所は、ここに分類を書くまで通りません。** 書けない
// （＝「回」の単位が要る）なら、それは `tick.Run` で包む合図です。
//
// **6つ目を足しました (2026-08-12)。**
//
//	未追跡        周期的に回っているのに、`tick.Run` を通っていない。
//
// これは分類ではなく**欠陥の記録**です。`ExpireOldSessions` を
// `BackgroundFailed` に通そうとして、呼び出し側を見たら
// `cmd/api/main.go` の5分の ticker でした ——「回」が無いのではなく、
// **誰も作っていない**だけです。
//
// 実測 (2026-08-12): `cmd/` の ticker ループは **8つ**（`cmd/api/main.go`
// に6、`cmd/detection/main.go` に2）で、**`tick.Run` を通っているものは
// 0 です。** この campaign の走査は `server/internal` しか見ておらず、
// `cmd/` は最初から範囲の外でした。
//
// `catUntracked` の件数は上限です。**包んだら減らしてください** ——
// 増える方向は、新しい未追跡のワーカーが生えたということです。

const (
	catStartup   = "起動時"
	catPerReq    = "要求ごと"
	catPerEvent  = "イベントごと"
	catReturns   = "errorを返す"
	catMechanism = "仕組み"
	catUntracked = "未追跡"
)

// **`metrics.BackgroundFailed` を呼んでいる場所と、その分類。**
// 鍵は `パス:関数名` です。
var backgroundFailedSites = map[string]string{
	// ── 起動時（プロセス起動時に一度だけ。次の回はありません） ───────
	"api/handlers/event_forwarder.go:Start":        catStartup,
	"detection/alert_pipeline.go:Start":            catStartup,
	"detection/alert_pipeline.go:ReloadSigmaRules": catStartup,
	"investigation/subscriber.go:Start":            catStartup,
	"notification/dispatcher.go:LoadChannels":      catStartup,
	"notification/email_notifier.go:Start":         catStartup,
	"reports/scheduler.go:LoadFromDB":              catStartup,
	"threatintel/feed.go:LoadFromDB":               catStartup,

	// ── 要求ごと（利用者が待っていて、応答でも分かります） ───────────
	"api/handlers/event_stream_handler.go:streamFromNATS":    catPerReq,
	"api/handlers/phishing_handler.go:CreateCampaign":        catPerReq,
	"api/handlers/update_handler.go:TriggerUpdate":           catPerReq,
	"api/handlers/yara_handler.go:ReclassifyCategories":      catPerReq,
	"api/handlers/platform_upgrade_handler.go:RecordStartup": catPerReq,

	// ── イベントごと（呼び出し側は次のイベントです） ─────────────────
	"api/handlers/event_forwarder.go:handleMessage":         catPerEvent,
	"api/handlers/event_forwarder.go:deliver":               catPerEvent,
	"detection/alert_pipeline.go:handleEvent":               catPerEvent,
	"detection/alert_pipeline.go:createAlertFromCustomRule": catPerEvent,
	"detection/engine.go:runAIAnalysis":                     catPerEvent,
	"detection/engine.go:monitorConsumerLag":                catPerEvent,
	"detection/playbook_runner.go:Run":                      catPerEvent,
	"ingestion/handler.go:publishEventBatch":                catPerEvent,
	"intel/feed_importer.go:skippedLines":                   catPerEvent,
	"investigation/investigator.go:ReadModeFromDB":          catPerEvent,
	"notification/webhook.go:dispatch":                      catPerEvent,
	"notify/notifier.go:SendAlert":                          catPerEvent,
	"notify/notifier.go:dispatch":                           catPerEvent,
	"notify/notifier.go:postJSON":                           catPerEvent,
	"notify/notifier.go:sendEmail":                          catPerEvent,
	"scheduler/realtime_correlator.go:handleAlertMessage":   catPerEvent,

	// ── error を返す（呼び出し側が受け取ります） ─────────────────────
	"api/handlers/mobile_app_inventory.go:ingestMobileApps": catReturns,
	"detection/anomaly_detector.go:SaveBaselinesToDB":       catReturns,
	"detection/custom_rules.go:compileRegexConditions":      catReturns,
	"detection/rules/rule_engine.go:Evaluate":               catReturns,
	"ldap/connector.go:SyncUsers":                           catReturns,
	"store/alerts.go:SaveAlert":                             catReturns,
	"store/alerts.go:autoInvestigateThreshold":              catReturns,
	"timeline/builder.go:BuildIncidentTimeline":             catReturns,

	// ── 仕組み ───────────────────────────────────────────────────────
	"tick/tick.go:FailComponent": catMechanism,

	// ── 要求ごと（応答はもう返っています） ───────────────────────────
	//
	// どれも goroutine で、呼び出し側は待っていません。**応答では
	// 分からない**ので、部品ごとの件数が残る唯一の跡です。
	"store/users.go:Authenticate":             catPerReq,
	"api/handlers/bas_handler.go:simulateRun": catPerReq,
	// **応答には載せられない、要求ごとの失敗**です。応答は別のことを
	// 答えていて（コマンドの取り出し、同期の結果、webhook の受理）、
	// その「記録」が書けたかどうかは別の話です。
	"api/handlers/live_response_handler.go:AgentPoll":                catPerReq,
	"api/handlers/mdm_integration_handler.go:noteSyncResult":         catPerReq,
	"api/handlers/mdm_integration_handler.go:recordCredentialExpiry": catPerReq,
	"billing/handler.go:StripeWebhook":                               catPerReq,
	// **要求に答えた「あと」の記録**です (2026-08-12)。操作そのものは
	// 済んでいて、応答もそれを答えています —— 残るのは記録で、
	// それが書けたかどうかは別の話です。
	"api/handlers/agents_handler.go:noteResponseAction": catPerReq,
	// **応答は重要度そのものを答えています。** 手動の値を読めなかった
	// ときは、計算値を返したうえで件数に出します —— 要求を失敗させると、
	// 一度も手で決めていない端末の重要度まで見られなくなります。
	"api/handlers/asset_criticality_handler.go:storedCriticality": catPerReq,
	// 一覧の方も同じです。壊れている行は飛ばして計算値で並べ、
	// **飛ばしたことだけを件数に出します。**
	"api/handlers/asset_criticality_handler.go:allManualCriticality": catPerReq,
	"api/handlers/agents_handler.go:Heartbeat":                       catPerReq,
	"api/handlers/auth_handler.go:Login":                             catPerReq,
	"api/handlers/users_handler.go:UpdatePassword":                   catPerReq,
	"api/handlers/threat_feeds_handler.go:Sync":                      catPerReq,
	"api/handlers/reports_handler.go:generateReport":                 catPerReq,
	// **応答も変えたもの**です。件数は「何回起きたか」を残すために
	// 併せて出します —— 利用者は 500 で知りますが、**何回起きているかは
	// 応答からは分かりません。**
	"api/handlers/quarantine_handler.go:Restore":    catPerReq,
	"api/handlers/webhooks_handler.go:CreateConfig": catPerReq,

	// **要求は別のことを答えています。** 取り込みの応答はアラートの
	// ことなので、端末の last_seen が書けなかったのは件数にだけ出ます。
	"api/handlers/ingest_handler.go:upsertAgent": catPerReq,

	// ── イベントごと ─────────────────────────────────────────────────
	// **転送1件ごと**です。goroutine の中なので答える相手がいません。
	"siem/connector.go:sendOne":              catPerEvent,
	"detection/engine.go:noteSuppressionHit": catPerEvent,
	"webhooks/dispatcher.go:recordDelivery":  catPerEvent,
	"webhooks/dispatcher.go:updateLastFired": catPerEvent,
	"suppression/engine.go:incrementHit":     catPerEvent,
	// **通知1回ごと**です。ここは送信そのものではなく、ファンアウト
	// 1 回分の結末（全滅 / 一部失敗）を数えています。呼び出し元は
	// 検知エンジンと定期スキャンの両方で、どちらも答える相手が
	// いません ---アラートは通知が届かなくても画面に残り、定期実行は
	// 人が見ていない。件数に出す以外に伝える手段がありません。
	"notification/dispatcher.go:Notify": catPerEvent,
}

// 実測 (2026-08-12): 58 か所 / 47 の宛先 → `correlation.upsertCase` で
// 56 / 46 → **`tick.Run` から3段たどって見つかった 8 か所**（shipper /
// wazuh / compliance / heartbeat_monitor / virustotal）を
// `tick.FailComponent` に移して 48 / 40 → 走査を package ごとに直したら
// もう2つ（`threatintel` の `FetchURLhaus` と `syncPublicFeeds`）出て
// 46 / 38 → **捨てていた書き込みのうち「報告する相手がいない」6つ**を
// 通して 54 / 44 (2026-08-12) → **抑制ルールのヒット数の報告を
// `noteSuppressionHit` に切り出して 71 → 70**。同じ報告が
// `processEventData` の中に2回書いてあり、1つの関数になりました
// （切り出した理由は `suppression_hit_report_test.go`）。
// → **通知の配信結果を数え始めて 76 / 61** (2026-08-17)。
// `notification.Dispatcher.Notify` に 2 か所（全滅 / 一部失敗）。
// センダーを作れなかった側 (`LoadChannels` = `notification_channels`) と
// 分けてあるので、宛先は 1 つ増えて 2 か所になっています。
const (
	backgroundFailedCount = 76
	backgroundFailedFuncs = 61
)

func TestEveryBackgroundFailedSiteIsClassified(t *testing.T) {
	sites := backgroundFailedCallSites(t)

	if len(sites) != backgroundFailedCount {
		t.Errorf("`metrics.BackgroundFailed` が %d か所です（留めているのは %d）。"+
			"**増えたなら分類してください。減らしたなら数を下げてください**",
			len(sites), backgroundFailedCount)
	}

	seen := map[string]bool{}
	for _, s := range sites {
		key := s.file + ":" + s.fn
		seen[key] = true
		if siteNeedsClassifying(key, backgroundFailedSites) {
			t.Errorf("%s:%d %s が `metrics.BackgroundFailed` を呼んでいますが、"+
				"分類がありません。**「この部品が失敗した」だけでよいのか、"+
				"「この回は終えられなかった」も要るのかが分かりません** —— "+
				"5つの分類のどれかを書くか、書けないなら `tick.Run` で"+
				"包んでください", s.file, s.line, s.fn)
		}
	}
	if len(seen) != backgroundFailedFuncs {
		t.Errorf("宛先が %d 個です（留めているのは %d）", len(seen), backgroundFailedFuncs)
	}

	for _, key := range staleClassificationKeys(backgroundFailedSites, seen) {
		t.Errorf("%s の分類が残っていますが、その箇所はもうありません。"+
			"**消した分は分類からも消してください**", key)
	}
	t.Logf("`metrics.BackgroundFailed`: %d か所 / %d 宛先 / 分類 %d 件",
		len(sites), len(seen), len(backgroundFailedSites))
}

// siteNeedsClassifying — その箇所が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
func siteNeedsClassifying(key string, m map[string]string) bool {
	return m[key] == ""
}

// isKnownCategory — 6つのどれかか。**自由文だと分類になりません** ——
// 「あとで見る」でも通ってしまいます。
func isKnownCategory(cat string) bool {
	switch cat {
	case catStartup, catPerReq, catPerEvent, catReturns, catMechanism, catUntracked:
		return true
	}
	return false
}

// **分類ごとの数。** 「分かれているか」だけだと、1件を別の分類へ
// 移す動きが止められません —— `未追跡`（欠陥の記録）を `イベントごと`
// に書き換える変異が、これを足すまで生き残りました。
var backgroundFailedCounts = map[string]int{
	// **0 が規則です。** `catUntracked` は分類ではなく欠陥の記録なので、
	// 中身が在ること自体が「まだ包んでいない周期処理がある」という
	// 意味になります。実測 (2026-08-12): 1 → `cmd/api/main.go` の
	// ticker を `tick.Run` で包んで 0。
	catUntracked: 0,
	catMechanism: 1,
}

// enoughSpread — 分類がちゃんと分かれているか。
//
// **1種類に全部寄せたら、それは分類ではありません。** いま5種類使って
// いるので、閾値を下げても挙がる件数は変わりません —— 見本で確かめます。
func enoughSpread(counts map[string]int) bool {
	return len(counts) >= 4
}

// **数の少ない分類は、そのまま留めます。** 多い方（起動時・要求ごと・
// イベントごと・errorを返す）は増減するので上の総数で見ます。
func TestTheSmallCategoriesKeepTheirCount(t *testing.T) {
	counts := map[string]int{}
	for _, cat := range backgroundFailedSites {
		counts[cat]++
	}
	for cat, want := range backgroundFailedCounts {
		if counts[cat] != want {
			t.Errorf("`%s` が %d 件です（実測は %d）。**別の分類へ移した"+
				"なら、こちらも直してください** —— `未追跡` は分類ではなく"+
				"欠陥の記録なので、黙って消えると直したことになりません",
				cat, counts[cat], want)
		}
	}
}

func TestTheClassificationJudgementsRecogniseTheRealThing(t *testing.T) {
	m := map[string]string{"a/x.go:Known": catStartup}
	if !siteNeedsClassifying("a/x.go:New", m) {
		t.Error("**分類の無い箇所を違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if siteNeedsClassifying("a/x.go:Known", m) {
		t.Error("分類が書いてあるものを違反にしています")
	}
	if !isKnownCategory(catPerEvent) {
		t.Error("**5つのうちの1つを「知らない」と言っています。**")
	}
	if isKnownCategory("あとで見る") {
		t.Error("**自由文を分類として通しています。** " +
			"それは分類ではなく、先送りの札です")
	}
	if isKnownCategory("") {
		t.Error("空文字を分類として通しています")
	}
	if enoughSpread(map[string]int{catPerEvent: 56}) {
		t.Error("**全部を1つの分類に寄せたものを通しています。** " +
			"分類が1種類なら、それは分類ではありません")
	}
	if !enoughSpread(map[string]int{
		catStartup: 8, catPerReq: 5, catPerEvent: 21, catReturns: 11,
	}) {
		t.Error("4種類を「寄せすぎ」と言っています")
	}
}

// staleClassificationKeys — 宛先の消えた分類。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
func staleClassificationKeys(m map[string]string, seen map[string]bool) []string {
	var stale []string
	for key := range m {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

// 分類の名前が、どれか5つであること。**自由文だと分類になりません。**
func TestEveryClassificationIsOneOfTheFive(t *testing.T) {
	counts := map[string]int{}
	for key, cat := range backgroundFailedSites {
		if !isKnownCategory(cat) {
			t.Errorf("%s の分類 %q は5つのどれでもありません", key, cat)
		}
		counts[cat]++
	}
	// **どれか1つに全部寄せていないこと。** 分類が1種類なら、それは
	// 分類ではありません。
	if !enoughSpread(counts) {
		t.Errorf("分類が %d 種類しか使われていません: %v", len(counts), counts)
	}
	t.Logf("分類の内訳: %v", counts)
}

func TestTheClassificationStalenessScanRecognisesTheRealThing(t *testing.T) {
	got := staleClassificationKeys(map[string]string{
		"a/x.go:Live": catStartup,
		"a/x.go:Gone": catStartup,
	}, map[string]bool{"a/x.go:Live": true})
	if strings.Join(got, ",") != "a/x.go:Gone" {
		t.Errorf("古い分類 = %v, want a/x.go:Gone", got)
	}
	if len(staleClassificationKeys(map[string]string{"a/x.go:Live": catStartup},
		map[string]bool{"a/x.go:Live": true})) != 0 {
		t.Error("**在る宛先の分類を「古い」と言っています。**")
	}
}

type bgSite struct {
	file string
	fn   string
	line int
}

func backgroundFailedCallSites(t *testing.T) []bgSite {
	t.Helper()
	fset := token.NewFileSet()
	var out []bgSite
	err := filepath.WalkDir(workerRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, workerRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if callsBackgroundFailed(n) {
					out = append(out, bgSite{rel, fn.Name.Name, fset.Position(n.Pos()).Line})
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return out
}
