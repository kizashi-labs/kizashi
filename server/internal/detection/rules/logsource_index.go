package rules

import (
	"log/slog"
	"sort"
)

// logsource インデックス — イベント種別に無関係なルールを評価対象から外す。
//
// Evaluate は長らく全ルールを線形に総当たりしていた。2026-08-05 の実測
// (rule_engine_bench_test.go)で、2,500 ルールでは 1 イベントあたり 31.4 ミリ秒・
// 42,500 アロケーションを消費し、単一スレッド換算 32 events/sec しか出ないことが分かった。
// FP ソークが 1.67 シミュレートホスト日/回に縛られている原因がこれである。
//
// 検証環境の実分布(直近7日 303万イベント)で見積もると:
//
//	process    1,573,507 件 (52%) → 1,866 ルール ( 1.2x)
//	file         587,780 件 (19%) →    69 ルール (33.7x)
//	image_load   474,021 件 (16%) →   150 ルール (15.5x)
//	network      261,692 件  (9%) →   101 ルール (23.0x)
//	dns           83,922 件  (3%) →    69 ルール (33.7x)
//	                              全体 2.29x (130 ev/s → 約 297 ev/s)
//
// 個別には 30 倍を超える種別があるのに全体で 2.3 倍に留まるのは、最多の process
// イベントでルールの 70% が process_creation に集中しているため。process 側の
// 二段目の絞り込み(Image|endswith 等の定数索引)は本インデックスの範囲外で、別途必要。
//
// ■ 安全性の原則 — 「速いが取りこぼす」に化けさせないための三つの逃げ道
//
//	(1) category を判定できないルールは常に評価する。
//	    logsource 未指定、behavioral ルール、そして **eventTypeCategories に
//	    現れない category** はすべてここに落とす。SigmaHQ 同期で新しい category が
//	    増えても、マッピングを更新するまでは「常に評価」= 従来どおりの挙動になる。
//	    黙って評価対象から消える経路は作らない。
//	(2) 未知のイベント種別は全ルールを評価する。
//	    新しいセンサーが増えたとき、マッピングに載るまでは絞り込まない。
//	(3) SetLogsourceIndex(false) で機能ごと無効化できる。
//	    platformGate と同じエスケープハッチ。絞り込みが原因で検知が落ちたと疑ったら
//	    まずこれを切って再現するかを見る。

// eventTypeCategories は「イベント種別 → そのイベントに該当しうる Sigma logsource category」。
//
// 対応を広めに取ってあるのは意図的である。ここで絞りすぎると検知が静かに落ち、
// 外形は「検知能力の欠落」と区別がつかない。逆に広すぎても失うのは速度だけ。
//
// 左辺は EventEnvelope.Type(= events.event_type)。検証環境の実測値は
// process / file / image_load / network / dns / process_stats / service_installed /
// registry / auth / memory / create_remote_thread / script / tls_handshake / ps_module。
// 右辺に空を割り当てた種別は「対応する Sigma category が存在しない」という意味で、
// その場合も (1) の常時評価ルールは必ず走る。
// ⚠ **この対応は Sigma の規約どおりではなく、本コードベースの実測に合わせてある。**
// 本来 logsource.category はイベント種別と 1:1 に対応するはずだが、ここでは
// コマンドライン系の3カテゴリが**双方向にクロスしている**ことがテストで確定している:
//
//   - `category: process_creation` のルールが `type:"script"` のイベントで発火する
//     (screen_capture_rule_test.go — ScriptBlockText に CopyFromScreen)
//   - `category: ps_script` のルールが `type:"process"` のイベントで発火する
//     (recursive_file_enum_test.go — CommandLine の Get-ChildItem -Recurse)
//   - `category: create_remote_thread` のルールが `type:"process"` のイベントで発火する
//     (migration_field_support_test.go — Process Hollowing の source_image/target_image)
//
// FlatMap が種別をまたいでフィールドを載せる(script イベントに ScriptBlockText、
// process イベントに CommandLine や source_image)ため、ルールは category と無関係に
// マッチしうる。したがって process はコマンドライン系3カテゴリと create_remote_thread を
// すべて評価する。それでも process で評価するルールは 1,875 件で、全カテゴリ 2,326 件の
// 8割にとどまる。全体の削減効果(試算 2.29x)は image_load / file / network / dns 側で
// 稼いでいるので、process 側が広くても損なわれない。
//
// 新しい種別・カテゴリを足すときは、必ず「そのルールが本当にその種別でしか
// 発火しないか」をテストで確かめること。ここを狭めると検知が静かに落ちる。
var eventTypeCategories = map[string][]string{
	"process":              {"process_creation", "ps_script", "ps_module", "create_remote_thread"},
	"script":               {"ps_script", "process_creation", "ps_module"},
	"ps_module":            {"ps_module", "ps_script", "process_creation"},
	"file":                 {"file_event", "file_change", "file_delete", "file_rename", "file_access"},
	"image_load":           {"image_load"},
	"network":              {"network_connection", "firewall"},
	"dns":                  {"dns_query", "dns"},
	"registry":             {"registry_set", "registry_event", "registry_add", "registry_delete", "registry_rename"},
	"create_remote_thread": {"create_remote_thread"},
	"pipe_created":         {"pipe_created"},
	"driver_load":          {"driver_load"},
	"wmi":                  {"wmi_event"},

	// ⚠ ここに載せていない種別(process_stats / service_installed / auth / memory /
	//   tls_handshake など)は**意図的に載せていない**。載せると「その種別では
	//   常時評価ルールしか走らない」という意味になるが、FlatMap は種別に関係なく
	//   フィールドを載せるため、その保証が無い。
	//
	//   実際 logsource_index_test.go の on/off 一致テストが、tls_handshake に
	//   Image を持たせたケースで結果の差を検出した(process_creation ルールが
	//   評価されなくなっていた)。「この種別にはこのフィールドしか来ない」と
	//   決めつけられない以上、対応 category を確信できない種別は
	//   candidates() のフォールバック(= 全ルール評価)に任せるのが正しい。
	//
	//   これらの種別は実測で全イベントの 1.5%(44,244 / 303万)しかないので、
	//   全ルール評価にしても全体の削減効果はほぼ変わらない。
	//   「絞れるかもしれない」より「絞らない」を選ぶ場面である。
}

// knownCategories は eventTypeCategories の右辺に一度でも現れる category の集合。
// ここに無い category を持つルールは「どのイベント種別に紐づくか不明」なので
// 常時評価に落とす(安全側)。
var knownCategories = func() map[string]bool {
	m := make(map[string]bool)
	for _, cats := range eventTypeCategories {
		for _, c := range cats {
			m[c] = true
		}
	}
	return m
}()

// logsourceIndex は「イベント種別 → 評価すべきルールID」を事前計算したもの。
// イベント種別は有限(十数種)なので、評価時に集合演算をせず引くだけで済む。
type logsourceIndex struct {
	byEventType map[string][]string // 種別 → ルールID(常時評価ぶんを含む)
	always      []string            // category を判定できない = 常に評価
	all         []string            // フォールバック(未知の種別 / インデックス無効時)
}

// buildLogsourceIndex は現在のルール集合からインデックスを構築する。
// sigmaByID は compileSigmaRule に成功したルールのみを含む(失敗したルールは
// そもそも評価されないので、インデックスに載せる必要も無い)。
func buildLogsourceIndex(rules map[string]*DetectionRule, sigmaByID map[string]*compiledSigmaRule) *logsourceIndex {
	idx := &logsourceIndex{byEventType: make(map[string][]string, len(eventTypeCategories))}

	byCategory := make(map[string][]string)
	unknownCats := make(map[string]int)

	for id := range rules {
		cs := sigmaByID[id]
		// sigma 以外(behavioral 等)、logsource 未指定、未知 category は常時評価。
		if cs == nil || cs.category == "" || !knownCategories[cs.category] {
			if cs != nil && cs.category != "" {
				unknownCats[cs.category]++
			}
			idx.always = append(idx.always, id)
			continue
		}
		byCategory[cs.category] = append(byCategory[cs.category], id)
	}

	sort.Strings(idx.always)
	for et, cats := range eventTypeCategories {
		ids := make([]string, 0, len(idx.always)+8)
		ids = append(ids, idx.always...)
		for _, c := range cats {
			ids = append(ids, byCategory[c]...)
		}
		sort.Strings(ids)
		idx.byEventType[et] = ids
	}

	idx.all = make([]string, 0, len(rules))
	for id := range rules {
		idx.all = append(idx.all, id)
	}
	sort.Strings(idx.all)

	// 観測性。絞り込みは「効きすぎている」ことが最も危険なので、内訳を必ず出す。
	// 未知 category はマッピング更新の宿題として名前で出す(黙って常時評価に
	// 落とすと、性能が出ない理由が分からなくなる)。
	slog.Info("logsource インデックスを構築しました",
		"総ルール", len(idx.all),
		"常時評価", len(idx.always),
		"category別", len(byCategory))
	if len(unknownCats) > 0 {
		names := make([]string, 0, len(unknownCats))
		for c := range unknownCats {
			names = append(names, c)
		}
		sort.Strings(names)
		slog.Warn("未知の logsource category があります(常時評価にしています)",
			"categories", names, "件数", len(unknownCats))
	}
	return idx
}

// candidates は評価すべきルールIDを返す。
// 未知のイベント種別では全ルールを返す — 絞り込めないのではなく、絞り込まない。
func (i *logsourceIndex) candidates(eventType string) []string {
	if ids, ok := i.byEventType[eventType]; ok {
		return ids
	}
	return i.all
}
