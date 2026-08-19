// auth_query_test.go — 実機検証(2026-07-26)で判明した「認証イベント0件」の回帰テスト。
// ビルドタグを付けないことで Linux CI でも回る(本体は windows タグ配下で回らない)。

package windows

import (
	"strings"
	"testing"
)

// Windows イベントログの XPath は時刻比較に timediff() しか許さない。
// リテラル比較(@SystemTime>='…')に戻すと EvtQuery が ERROR_EVT_INVALID_QUERY で
// 失敗し、認証イベントが恒久的に0件になる。
func TestBuildAuthQuery_UsesTimediffNotLiteralComparison(t *testing.T) {
	q := buildAuthQuery(70_000)

	if !strings.Contains(q, "timediff(@SystemTime)") {
		t.Errorf("時刻フィルタは timediff() でなければならない: %s", q)
	}
	if strings.Contains(q, "@SystemTime>=") || strings.Contains(q, "@SystemTime >=") {
		t.Errorf("Windows が受け付けないリテラル時刻比較が含まれている: %s", q)
	}
	if !strings.Contains(q, "<= 70000") {
		t.Errorf("指定した時間窓が反映されていない: %s", q)
	}
}

// 失敗ログオン(4625)は T1110 ブルートフォース検知の唯一の入力なので、
// 選択対象から外れてはならない。
// 4769 は Kerberos サービスチケット要求で、Kerberoasting 検知の唯一の観測点。
// ここから漏れると parseAuthEvent 以降がいくら正しくても一件も収集されない —
// 下流のテストは全部通ったまま、検知だけが沈黙する。
func TestBuildAuthQuery_SelectsFailedLogon(t *testing.T) {
	q := buildAuthQuery(10_000)
	for _, id := range []string{"4624", "4625", "4634", "4672", "4769"} {
		if !strings.Contains(q, "EventID="+id) {
			t.Errorf("EventID=%s が選択対象に含まれていない: %s", id, q)
		}
	}
}

// 購読クエリ側も同じ ID を選ぶこと。ポーリングだけ直して購読側を直し忘れると、
// リアルタイム経路だけが静かに欠落する。
func TestBuildAuthSubscribeQuery_SelectsTheSameEventIDs(t *testing.T) {
	q := buildAuthSubscribeQuery()
	for _, id := range []string{"4624", "4625", "4634", "4672", "4769"} {
		if !strings.Contains(q, "EventID="+id) {
			t.Errorf("購読クエリに EventID=%s が含まれていない: %s", id, q)
		}
	}
}

// 非正の窓を渡してもクエリが壊れないこと(時計のずれで負値になり得る)。
func TestBuildAuthQuery_ClampsNonPositiveWindow(t *testing.T) {
	for _, ms := range []int64{0, -1, -60_000} {
		q := buildAuthQuery(ms)
		if strings.Contains(q, "<= 0") || strings.Contains(q, "<= -") {
			t.Errorf("窓 %d が clamp されていない: %s", ms, q)
		}
	}
}

// 購読クエリは将来イベントのみ配送されるため時刻述語を持たない。
// timediff を入れると購読が何も返さなくなる。
func TestBuildAuthSubscribeQuery_HasNoTimePredicate(t *testing.T) {
	q := buildAuthSubscribeQuery()
	if strings.Contains(q, "timediff") || strings.Contains(q, "SystemTime") {
		t.Errorf("購読クエリに時刻述語があってはならない: %s", q)
	}
	if !strings.Contains(q, "EventID=4625") {
		t.Errorf("購読クエリが失敗ログオンを含んでいない: %s", q)
	}
}

// 4765/4766 (SID-History 付与) が購読・問い合わせの両方に入っていること。
//
// T1134.005 はこの 2 つ以外に痕跡を残さない——プロセス生成もログオンも伴わない
// アカウント属性の書き換えである。述語から漏れると、サーバ側でどれだけルールを
// 書いても検知できない。実際 2026-08-14 まで漏れており、migration 384 の第 1 波で
// この技法のルールだけが「値が来ないので入れられない」として外されていた。
func TestAuthQueries_IncludeSIDHistoryEvents(t *testing.T) {
	for _, q := range []string{buildAuthQuery(10_000), buildAuthSubscribeQuery()} {
		for _, id := range []string{"4765", "4766"} {
			if !strings.Contains(q, "EventID="+id) {
				t.Errorf("EventID=%s が選択対象に含まれていない: %s", id, q)
			}
		}
	}
}
