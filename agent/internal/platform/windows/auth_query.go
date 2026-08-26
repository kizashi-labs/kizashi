// auth_query.go — Security チャネルに投げる XPath クエリの組み立て。
//
// このファイルにだけビルドタグを付けていないのは意図的である。認証イベント収集の
// 本体(auth_collector.go)は windows タグ配下で Linux CI からは一切コンパイルも
// テストもされない。実機検証(2026-07-26)で、その死角にあったクエリの不具合が
// 24時間で auth イベント0件という形で表面化した。クエリ組み立ては syscall を
// 含まない純粋な文字列処理なので、ここに切り出せばどのプラットフォームの CI でも
// 回帰テストできる。

package windows

import "fmt"

// authEventIDPredicate は収集対象の Windows Security イベントID。
// 4624 ログオン成功 / 4625 ログオン失敗 / 4634 ログオフ / 4672 特権付与 /
// 4765 SID-History 付与成功 / 4766 SID-History 付与失敗。
//
// 4765/4766 は 2026-08-14 に追加した。T1134.005(SID-History 注入)は
// **この 2 つ以外に痕跡を残さない**——攻撃者が別ドメインの特権 SID を account の
// sIDHistory 属性に接ぎ木する操作で、プロセス生成もログオンも伴わない。
// mimikatz の `sid::` を拾う `SID-History Injection via Offensive Tooling`
// (migration 384) はツール実行を見るので、DCShadow や正規 API 経由の付与は
// 素通りする。購読に入れて初めて検知の入口ができる。
//
// 4769 は Kerberos サービスチケット要求 (TGS-REQ)。Kerberoasting の唯一の
// 観測点で、弱い暗号化方式のチケットだけを parseAuthEvent 側で絞り込む
// (collector.KerberoastableTicket)。ドメインコントローラでは 4769 自体が
// 毎秒数千件出るため、絞り込みなしで転送することはできない。
//
// 4648(明示的資格情報でのログオン試行)は**意図的に含めない**。成否を表さない
// イベントであり、AuthEvent の Success(bool) では表現できない。取り込んだうえで
// 成功として扱っていたため、失敗ログオンから偽の「アカウント侵害」アラートが
// 出ていた(2026-08-05 実機)。取得しなければ変換側の誤りも起こり得ない。
// 詳細は auth_parse.go の parseAuthEvent を参照。
const authEventIDPredicate = "EventID=4624 or EventID=4625 or EventID=4634 or EventID=4672 or " +
	"EventID=4765 or EventID=4766 or EventID=4769"

// buildAuthQuery は「直近 windowMillis ミリ秒以内」の認証イベントを選ぶ XPath を返す。
//
// 重要: Windows イベントログの XPath は XPath 1.0 の**部分集合**しか実装しておらず、
// 時刻比較に使えるのは timediff() 関数だけである。`@SystemTime>='2026-07-26T15:37:00Z'`
// のようなリテラル比較は構文上は自然に見えるが Windows は受け付けず、EvtQuery が
// ERROR_EVT_INVALID_QUERY で失敗する。実機ではこの誤ったクエリのせいで
// queryAuthEvents が毎回エラーを返し、しかも呼び出し側がエラーを無言で握り潰していた
// ため、認証イベントが恒久的に0件のまま気付かれなかった(T1110 ブルートフォース検知が
// 入力欠如で原理的に発火しない状態)。
func buildAuthQuery(windowMillis int64) string {
	if windowMillis < 1 {
		windowMillis = 1
	}
	return fmt.Sprintf(
		`*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]`,
		authEventIDPredicate, windowMillis,
	)
}

// buildAuthSubscribeQuery は EvtSubscribe 用。購読は将来のイベントのみを配送するため
// 時刻述語を持たない。
func buildAuthSubscribeQuery() string {
	return fmt.Sprintf(`*[System[(%s)]]`, authEventIDPredicate)
}
