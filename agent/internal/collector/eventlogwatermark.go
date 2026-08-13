// eventlogwatermark.go — Windows イベントログのポーリング収集で「同じイベントを
// 何度も報告しない」ための透かし。
//
// なぜ共通化するか。System 7045(サービスインストール) と Security 1102 / System 104
// (イベントログ消去) の2つのコレクタが、同じ形の欠陥を独立に持っていた:
//
//	timeStr := lastSeen.Format(...)
//	query   := `…TimeCreated[@SystemTime>='` + timeStr + `']`   // ← 「以上」
//	for _, ev := range results {
//	    if ev.when.After(lastSeen) { lastSeen = ev.when }        // ← 更新するだけ
//	    emit(ev)                                                 // ← 無条件に送出
//	}
//
// クエリの下限が「以上」なので、境界にある最新イベントは毎回のポーリングで再びヒットする。
// そして送出はそれを弾かない——`After` の判定は透かしを進めるだけで、送るかどうかを
// 決めていない。結果、7045 が1件あるだけで 15 秒ごとに再送され続ける。
//
// 実測(検証EC2, 2026-08-10): service_installed が 24 時間で 5,761 件、その全てが同一の
// "Microsoft Defender Core Service"(同じ ImagePath / 同じ account)。1 度きりの
// インストールが 1 日 5,761 件のイベントと、5 分ごとの [PERSIST] アラートになっていた。
// eventlog_cleared 側は「誰もログを消していない」ために表面化していなかっただけで、
// 一度でも消去が起きれば同じ無限再送になる——痕跡消去(T1070.001)は攻撃の終盤に出る
// 高価値シグナルなので、そこがアラート洪水になるのは最悪の壊れ方である。
//
// クエリの下限は「以上」のまま残す。ミリ秒精度に丸めた境界を「より大きい」にすると、
// 同じミリ秒に発生したイベントを取りこぼしうるため。取りこぼさずに二重送出だけを消すには、
// 「取得は広く、送出は厳密に」を分ける必要がある。それがこの型の役割。
package collector

import "time"

// EventLogWatermark tracks the newest event already emitted by a Windows
// event-log poller, so a re-matched boundary event is fetched but not resent.
//
// Not safe for concurrent use: each collector owns one and polls from a single
// goroutine.
type EventLogWatermark struct {
	emitted time.Time
}

// NewEventLogWatermark starts a watermark at t. Callers typically pass a moment
// slightly in the past so the first poll picks up an event that landed during
// agent startup.
func NewEventLogWatermark(t time.Time) *EventLogWatermark {
	return &EventLogWatermark{emitted: t}
}

// QueryFrom is the inclusive lower bound for the poll's XPath filter. Inclusive
// on purpose: excluding it at millisecond resolution could skip an event sharing
// the boundary millisecond. Over-fetching is corrected by ShouldEmit.
func (w *EventLogWatermark) QueryFrom() time.Time { return w.emitted }

// BeginRound snapshots the watermark for one polling round. Pass the result to
// every ShouldEmit call in that round: comparing against a watermark that moves
// mid-round would drop later events whose timestamps precede an earlier one,
// and the API gives no ordering guarantee.
func (w *EventLogWatermark) BeginRound() time.Time { return w.emitted }

// ShouldEmit reports whether an event stamped ts is new relative to the round's
// snapshot. Equal timestamps are NOT new — that is precisely the re-matched
// boundary event.
func (w *EventLogWatermark) ShouldEmit(round, ts time.Time) bool { return ts.After(round) }

// Commit advances the watermark to the newest timestamp seen in the round.
// Ignores zero and non-advancing values, so a parse failure or an out-of-order
// batch can never move it backwards and cause a re-send.
func (w *EventLogWatermark) Commit(newest time.Time) {
	if newest.IsZero() || !newest.After(w.emitted) {
		return
	}
	w.emitted = newest
}
