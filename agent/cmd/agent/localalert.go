package main

// ローカルアラート — サーバの判定を待たずにエンドポイント単独で発報する経路。
//
// scanner.LocalAnomalyDetector のスコアが localAlertThreshold (0.85) 以上に
// 達したイベントは、次のバッチ間隔を待たずに送る。バッチ間隔は既定で
// 数秒あり、ランサムウェアの暗号化開始やマスカレードした svchost.exe の起動を
// その分だけ遅らせてしまう。閾値を超えるのはエンドポイント単独で「怪しい」と
// 言い切れる水準 (例: システムプロセスが想定外パスから起動 0.6 + 一時ディレクトリ
// 0.3) なので、送信を待つ理由が無い。
//
// ここで行うのは「WARN ログ」と「即時送信」までで、遮断や隔離は行わない。
// ヒューリスティックのスコアだけで自動遮断すると誤検知の影響が大きすぎるため、
// 遮断の判断はサーバ側 (およびポリシー) に委ねる。

import (
	"log/slog"
	"time"

	"github.com/edr-platform/agent/internal/scanner"
)

// localAlertFlushGap は即時送信の最小間隔。
//
// 攻撃中は閾値超えが連続することがあり、1 件ごとに送ると 1 イベントだけの
// RPC が並んでスループットを落とす。この間隔で間引いても、遅延は最大でも
// この長さで、バッチ間隔を待つより短い。
const localAlertFlushGap = time.Second

// localAlertGate は即時送信の発火を間引く。並行アクセスは想定していない
// (イベント集約ループの単一 goroutine からのみ使う)。
type localAlertGate struct {
	minGap time.Duration
	last   time.Time
}

func newLocalAlertGate(minGap time.Duration) *localAlertGate {
	return &localAlertGate{minGap: minGap}
}

// allow は now 時点で即時送信してよいかを返す。許可したときだけ時刻を記録する
// ので、拒否が続いても「最後に送った時刻」からの経過で判定される。
func (g *localAlertGate) allow(now time.Time) bool {
	if !g.last.IsZero() && now.Sub(g.last) < g.minGap {
		return false
	}
	g.last = now
	return true
}

// noteAnomaly はスコアを記録し、即時送信が必要かどうかを返す。
//
// 閾値未満のスコアは従来どおり Debug に落とす (0 は出さない)。閾値以上は
// WARN で理由付きで残す — エンドポイントのログだけを見ている運用者に、
// サーバへ届く前の時点で気付けるようにするのがローカルアラートの主目的。
func noteAnomaly(gate *localAlertGate, now time.Time, kind string, score scanner.AnomalyScore, attrs ...any) bool {
	if !score.LocalAlert {
		if score.Score > 0 {
			slog.Debug("異常スコア", append([]any{"kind", kind, "score", score.Score, "reasons", score.Reasons}, attrs...)...)
		}
		return false
	}

	slog.Warn("ローカルアラート: 異常スコアが閾値を超えました",
		append([]any{"kind", kind, "score", score.Score, "reasons", score.Reasons}, attrs...)...)
	return gate.allow(now)
}
