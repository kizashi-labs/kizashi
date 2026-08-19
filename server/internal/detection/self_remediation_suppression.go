package detection

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// self_remediation_suppression.go — 自分の封じ込め操作を自分で検知しないようにする。
//
// 2026-08-05 の実測（WIN-ENDPOINT-01）:
//
//	14:09:36  [PROC-CORRELATION] sev 10 → 自動隔離
//	14:09:37  netsh advfirewall firewall add rule name=EDR-ISOLATE-BLOCK-RANGE-0-IN …
//	14:09:42  [SIGMA] New Firewall Rule Added Via Netsh.EXE     ← 自分の隔離を検知
//	15:18:11  [SIGMA] Firewall Rule Deleted Via Netsh.EXE       ← 自分の解除を検知
//
// Windows の隔離は netsh advfirewall でブロックルールを足すので、ファイアウォール改変を
// 見る Sigma ルールが必ず当たる。隔離のたびにアラートが増え、そのアラートがまた相関の
// 材料になる。SOC から見ると、封じ込めた端末ほど「怪しい」ように見える。
//
// # なぜコマンドラインで判定しないのか
//
// 素直な実装は「コマンドラインに EDR-ISOLATE- を含むなら抑止」だが、これは検知回避の穴に
// なる。攻撃者がファイアウォールルールをその名前で作るだけで、netsh ルール全体を回避
// できてしまう。プロセスイベントは親プロセス情報を持たない（internal/ingestion/handler.go）
// ため、サーバ側では自分の netsh と攻撃者の netsh を名前以外で区別できない。
//
// # 代わりに使う条件
//
// 「サーバが実際にこの端末へ封じ込めコマンドを送出した直後か」を条件にする。これは
// 攻撃者が仕込めない。仕込むには当のプラットフォームに隔離を発行させる必要があり、
// それには severity 10 の検知を踏むことになるので、回避の手段として成立しない。
// 窓の外では通常どおり検知するし、窓の中で見逃す可能性がある netsh 操作についても、
// その時点で端末は隔離済みなので攻撃者が得られるものは乏しい。
//
// 判定順は「アラート種別（メモリ内・安価）→ 送出履歴（DB照会）」。ファイアウォール改変
// アラート自体が稀なので、DB を引くのはその稀な場合だけになる。
//
// #757 が隔離の実行経路を internal/isolation.Gatekeeper に集約し、6 経路すべてが
// response_actions に記録されるようになったので、この判定が成立する。集約前は
// rem-001-critical-isolate が記録を残さずに隔離していたため、「送出した事実」を
// 問い合わせる先が存在しなかった。

// ContainmentLookup answers whether we recently acted on this endpoint ourselves.
// store.ResponseActionStore がこれを満たす。
type ContainmentLookup interface {
	RecentContainment(ctx context.Context, agentID string, within time.Duration) (bool, error)
}

// selfRemediationWindow は封じ込めコマンドの送出から、端末上でその副作用が観測されて
// アラートになるまでの猶予。実測では隔離から netsh 由来のアラートまで 6 秒だったが、
// 検知エンジンのラグ（P4-6）と解除時の往復を吸収できる長さにしてある。長くするほど
// 見逃しの窓が広がるので、実測値に対する余裕以上には伸ばさない。
const selfRemediationWindow = 90 * time.Second

// firewallChangeMarkers は「ホストのファイアウォール設定が変わった」ことを述べている
// アラートを見分けるための語。ルール名・タイトルの部分一致で判定する。
//
// タイトル一致という弱い手掛かりを使うのは、この条件が単独では何も抑止しないため。
// 抑止が起きるには「サーバが直前に封じ込めを送出した」ことが別途必要で、安全性は
// そちら側が担保している。ここは DB 照会を減らすための足切りに近い。
//
// rules テーブルは SigmaHQ から同期されるのでタイトルは変わりうる。取りこぼしても
// 「自分の隔離を検知してしまう」元の状態に戻るだけで、検知が甘くなる方向には倒れない。
var firewallChangeMarkers = []string{
	"firewall rule added",
	"firewall rule deleted",
	"firewall rule modified",
	"advfirewall",
	"netsh",
	"ファイアウォール",
}

// SelfRemediationSuppressor drops alerts that our own containment produced.
type SelfRemediationSuppressor struct {
	lookup ContainmentLookup
	window time.Duration
}

// NewSelfRemediationSuppressor returns nil when lookup is nil, so a caller that
// has no store simply gets no suppression rather than a silent no-op object.
func NewSelfRemediationSuppressor(lookup ContainmentLookup) *SelfRemediationSuppressor {
	if lookup == nil {
		return nil
	}
	return &SelfRemediationSuppressor{lookup: lookup, window: selfRemediationWindow}
}

// IsSelfInflicted reports whether this alert is our own containment being
// observed on the endpoint we just contained.
//
// 照会に失敗した場合は false を返す（＝抑止しない）。DB が答えられないときに
// アラートを消すのは、検知を止める方向の失敗になるため。
func (s *SelfRemediationSuppressor) IsSelfInflicted(ctx context.Context, alert *StoredAlert) bool {
	if s == nil || alert == nil || alert.AgentID == "" {
		return false
	}
	if !describesFirewallChange(alert) {
		return false
	}
	recent, err := s.lookup.RecentContainment(ctx, alert.AgentID, s.window)
	if err != nil {
		slog.Warn("直近の封じ込め操作を照会できませんでした。抑止せずに続行します",
			"agent", alert.AgentID, "alert", alert.Title, "error", err)
		return false
	}
	if !recent {
		return false
	}
	slog.Info("自分の封じ込め操作に由来するアラートを抑止しました",
		"agent", alert.AgentID, "alert", alert.Title, "window", s.window)
	return true
}

func describesFirewallChange(alert *StoredAlert) bool {
	hay := strings.ToLower(alert.RuleName + " " + alert.Title)
	for _, m := range firewallChangeMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}
