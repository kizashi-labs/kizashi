package scheduler

import "strings"

// 外向き通信を伴う機能のオン/オフ。
//
// README の外部通信表と 1:1 で対応する。表に「止め方」を書く以上、実際に
// 止められる口が要る、というのがこのファイルの存在理由。
//
// 既定値の考え方は 2 通りある。
//
//   - **オプトイン**（DarkWebEnabled）— 明示的に有効化したときだけ動く。
//     機能そのものが外部サービスの参照でできており、無効でも他の検知が
//     劣化しないもの。
//   - **オプトアウト**（ThreatFeedSyncEnabled / NVDLookupEnabled）— 既定で
//     動き、明示的に "false" を置いたときだけ止まる。検知の母数に直結し、
//     黙って止めると「入れたのに検知しない」に化けるもの。
//
// どちらも README の表に既定値ごと明記してある。値の解釈は両方向とも
// 厳密で、"true"/"false" 以外は既定値に倒す（"yes" や "0" のような
// それらしい綴りを黙って解釈しない）。

// ThreatFeedSyncEnabled は公開 IOC ブロックリストの定期取得を行うかを返す。
//
// 既定は**有効**。abuse.ch / AlienVault / CINS / blocklist.de / IPsum の
// 8 本が migration 275・287・303 で is_active=TRUE としてシードされており、
// IOC 照合の母数そのものになっている。ここを既定で止めると、初期状態の
// 検知力が大きく落ちたまま気づかれない。
//
// 送っているのは取得要求だけで、自組織のテレメトリは送らない。それでも
// 許容できない環境のために THREAT_FEED_SYNC_ENABLED=false で全停止できる。
// 個別に止めたいだけなら threat_feeds.is_active を落とす。
func ThreatFeedSyncEnabled(v string) bool {
	return !strings.EqualFold(strings.TrimSpace(v), "false")
}

// NVDLookupEnabled は NVD CVE API への照会を行うかを返す。
//
// 既定は**有効**。無効化すると内蔵の小さな CVE 表にフォールバックする
// （7 エントリしかないので、脆弱性の検出数は大きく落ちる）。
//
// 送るのはソフトウェア名（例: "openssl"）だけで、ホスト名・バージョン・
// 資産の識別子は送らない。
func NVDLookupEnabled(v string) bool {
	return !strings.EqualFold(strings.TrimSpace(v), "false")
}
