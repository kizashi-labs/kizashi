// emit.go — センサーからコレクタチャネルへの送出。取りこぼしを黙って起こさないための共通処理。
//
// Linux(inotify) と Windows(ReadDirectoryChangesW) のファイルコレクタは、送信を
//
//	select { case out <- evt: ; case <-ctx.Done(): return ; default: }
//
// と書いていた。`default:` はチャネルが一瞬でも満杯なら**そのイベントを捨てる**。
// バッファは1000だが、取りこぼしが起きるのは「短時間に大量のファイル操作が走った
// とき」であり、それはランサムウェアの暗号化フェーズそのものである。つまり
// レートベースの検知器(T1486)が最も必要とするデータを、最も必要な瞬間に失う実装に
// なっていた。しかもログが一切出ないため、検知漏れの原因として浮上しようがない。
//
// ここでは (1) まず非ブロッキングで送る、(2) 満杯なら短時間だけ待つ、(3) それでも
// 送れなければ**取りこぼしを数えて警告する**、という三段構えにする。無制限に
// ブロックしないのは、消費側が停止したときにカーネル側のイベントキューを溢れさせて
// より広範な欠落を招かないため。
package collector

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// emitBlockFor is how long a send waits for a momentarily-full channel before
// giving up and counting a drop. Long enough to ride out a normal consumer
// hiccup, short enough that the sensor never stalls behind a wedged consumer.
const emitBlockFor = 250 * time.Millisecond

// EmitFile delivers a file event to out. Returns true when delivered. A drop is
// counted in dropped and surfaced in the log (first occurrence, then every
// 1000th) so silent telemetry loss cannot hide. Passing a nil counter is fine.
func EmitFile(ctx context.Context, out chan<- FileEvent, evt FileEvent, dropped *atomic.Uint64) bool {
	select {
	case out <- evt:
		return true
	case <-ctx.Done():
		return false
	default:
	}

	t := time.NewTimer(emitBlockFor)
	defer t.Stop()
	select {
	case out <- evt:
		return true
	case <-ctx.Done():
		return false
	case <-t.C:
		if dropped == nil {
			return false
		}
		n := dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			slog.Warn("ファイルイベントを取りこぼしました(送信キュー飽和)。"+
				"ファイル操作バースト検知(T1486)の入力が欠落します",
				"累計取りこぼし", n, "path", evt.Path, "action", evt.Action)
		}
		return false
	}
}
