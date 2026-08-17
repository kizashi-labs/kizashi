package ingestion

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// この 1 本が守るのは、3 度再発した同一クラスの欠陥である。
//
// promoteEventType が返す型は events.event_type にそのまま書かれる。その値が
// events_event_type_check に載っていないと INSERT は 23514 で拒否されるが、
// publishEventBatch は「永続化 → publish」の順なので **NATS への publish は成功する**。
// つまり検知は鳴り、アラートは出て、events テーブルにだけ証跡が残らない。
// 加えて insertEvents は複数行 INSERT の失敗を 1 件ずつの INSERT にフォールバック
// させるため、拒否される 1 件を含むバッチは 1 往復が 501 往復に化ける。
// どちらもエラーとして表に出ないので、実際に 3 回とも数週間〜1 か月見逃されている:
//
//	migration 269 (2026-06-19) : process_block / image_load / script
//	migration 373 (2026-08-??) : device_event
//	migration 380 (2026-08-12) : tls_handshake / ps_module / pipe_created /
//	                             eventlog_cleared / service_installed
//
// 新しいイベント型を足すときは、コレクタと promoteEventType だけでなく
// **migration も同じ PR に入れること**。忘れるとこのテストが落ちる。

// eventTypeConstraintMigrations は events_event_type_check を作る/書き換える
// migration を拾う条件。002 は制約に名前を付けずテーブル定義内に CHECK を書いて
// いるので、両方の綴りを見る。
var eventTypeConstraintMarkers = []string{
	"events_event_type_check",
	"CHECK (event_type IN",
}

// sqlLineComment は -- から行末まで。コメント中に型名を引用符付きで書いても
// 「許可されている」と誤認しないよう、リテラル抽出の前に落とす。
var sqlLineComment = regexp.MustCompile(`--[^\n]*`)

// sqlIdentLiteral は SQL の単一引用符リテラルのうち、イベント型名がとりうる形
// (小文字英数字とアンダースコア)だけ。
var sqlIdentLiteral = regexp.MustCompile(`'([a-z0-9_]+)'`)

// permittedEventTypesFromMigrations は migrations 一式から「events.event_type に
// 許可されうる値」の上界を復元する。
//
// 制約の組み立て方は歴史的に 3 通りある(225/269 系の全置換、322/370/373 系の
// 1 値追記、380 の複数値追記)。どの形かを解釈しようとすると SQL パーサを書く
// はめになるので、**制約に触れる migration に現れる引用符付きリテラルを全部
// 集める**という粗い上界を取る。過大評価にはなるが、このテストが主張するのは
// 「producible ⊆ 許可集合」の一方向だけなので、過大評価は偽陰性の方向にしか
// 効かない——そして実際の欠陥(型名がどの migration にも一度も現れない)は
// この粗さでも確実に捕まる。
func permittedEventTypesFromMigrations(t *testing.T) (map[string]bool, int) {
	t.Helper()

	dir := filepath.Join("..", "..", "migrations")
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatalf("migrations の走査に失敗しました: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("migrations が 1 本も見つかりません (%s)。テストの参照パスが壊れています", dir)
	}
	sort.Strings(paths)

	permitted := make(map[string]bool)
	matched := 0
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s の読み込みに失敗しました: %v", p, err)
		}
		body := string(b)

		relevant := false
		for _, marker := range eventTypeConstraintMarkers {
			if strings.Contains(body, marker) {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}
		matched++

		for _, m := range sqlIdentLiteral.FindAllStringSubmatch(sqlLineComment.ReplaceAllString(body, ""), -1) {
			permitted[m[1]] = true
		}
	}
	return permitted, matched
}

// TestProducibleEventTypesArePermittedByConstraint は promoteEventType が返しうる
// 全ての型が events_event_type_check に載っていることを確認する。
func TestProducibleEventTypesArePermittedByConstraint(t *testing.T) {
	permitted, matched := permittedEventTypesFromMigrations(t)

	// 発見側の健全性確認。glob やマーカーが壊れて 0 件になったとき、
	// 「許可集合が空 = 何も落ちない」ではなく明示的に落とす。
	if matched < 5 {
		t.Fatalf("event_type 制約に触れる migration が %d 本しか見つかりません。"+
			"eventTypeConstraintMarkers が実態と合っていない可能性があります", matched)
	}
	if !permitted["process"] {
		t.Fatalf("復元した許可集合に基本型 'process' すら含まれていません。"+
			"リテラル抽出が壊れています: %v", sortedKeys(permitted))
	}

	var missing []string
	for _, evtType := range producibleEventTypes() {
		if !permitted[evtType] {
			missing = append(missing, evtType)
		}
	}
	if len(missing) > 0 {
		t.Errorf("promoteEventType が返す型 %v が events_event_type_check に含まれていません。\n"+
			"この状態だと INSERT は 23514 で拒否される一方 NATS への publish は成功するため、"+
			"検知は鳴るのに events テーブルに証跡が残りません(しかも複数行 INSERT が"+
			"1 件ずつにフォールバックして往復数が跳ねます)。\n"+
			"server/migrations に許可値を追記する migration を同じ PR で足してください"+
			"(直近の例: 380_events_event_type_missing_five.sql)。", missing)
	}
}

// TestProducibleEventTypesCoversKnownSet は producibleEventTypes 自体が壊れて
// 空集合や部分集合になっていないことを確認する。上のテストは
// producible が空なら無条件に通ってしまうため、その抜けを塞ぐ。
func TestProducibleEventTypesCoversKnownSet(t *testing.T) {
	got := make(map[string]bool)
	for _, v := range producibleEventTypes() {
		got[v] = true
	}

	// enum 由来と id 接頭辞由来の両方から代表を取る。
	for _, want := range []string{
		"process", "file", "network", "dns", "registry", "auth", "image_load", "script",
		"process_stats", "process_block", "memory", "credential_access", "host_integrity",
		"create_remote_thread", "tls_handshake", "ps_module", "pipe_created",
		"wmi_activity", "eventlog_cleared", "service_installed", "device_event",
	} {
		if !got[want] {
			t.Errorf("producibleEventTypes に %q が含まれていません: %v", want, sortedKeys(got))
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
