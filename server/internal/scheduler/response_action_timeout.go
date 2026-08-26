package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// 期限の下限と既定値。
//
// 短すぎると、単に遅いだけのコマンドを timeout として畳んでしまう。実行結果が
// 返る前に期限切れにすると、あとから成功が返ってきても行は timeout のままで、
// かえって記録が不正確になる。エージェントは断続的に切れる前提なので、
// 分単位で余裕を持たせる。
const (
	minResponseActionTimeout     = 2 * time.Minute
	defaultResponseActionTimeout = 15 * time.Minute
	timeoutSweepInterval         = time.Minute
)

// ResponseActionTimeoutWorker marks response actions that never reached a
// terminal state as timed out.
//
// これが無いと、送ったまま結果が返らなかったコマンドは dispatched のまま
// 永久に残る。UI では「実行中」に見えるため、操作者は隔離が効いていると
// 思い込む。対応の記録は誰かが実行しようとするまで沈黙するので、
// 放置された行を能動的に畳む担当が要る。
//
// エージェントからの結果通知が実装された後も、この掃除役は残す。通知が
// 届かない経路（エージェントの死亡、NATS の滞留）は常に存在する。
type ResponseActionTimeoutWorker struct {
	actions  *store.ResponseActionStore
	timeout  time.Duration
	interval time.Duration
}

// NewResponseActionTimeoutWorker creates the worker.
//
// timeout が下限を下回る場合は下限に丸める。設定ミスで「送った直後に
// timeout」になるほうが、期限が長すぎるより有害なため。
func NewResponseActionTimeoutWorker(actions *store.ResponseActionStore, timeout time.Duration) *ResponseActionTimeoutWorker {
	if timeout <= 0 {
		timeout = defaultResponseActionTimeout
	}
	if timeout < minResponseActionTimeout {
		slog.Warn("対応アクションの期限が短すぎます。下限に丸めます",
			"指定", timeout, "下限", minResponseActionTimeout)
		timeout = minResponseActionTimeout
	}
	return &ResponseActionTimeoutWorker{
		actions:  actions,
		timeout:  timeout,
		interval: timeoutSweepInterval,
	}
}

// Run starts the sweep loop and blocks until ctx is cancelled.
func (w *ResponseActionTimeoutWorker) Run(ctx context.Context) {
	slog.Info("対応アクションの期限切れ監視を開始しました",
		"期限", w.timeout, "間隔", w.interval)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "response_action_timeout", w.sweep)
		}
	}
}

func (w *ResponseActionTimeoutWorker) sweep(ctx context.Context) {
	n, err := w.actions.ExpireStale(ctx, w.timeout)
	if err != nil {
		// 畳めなかった回。ログだけでは「期限切れが 0 件だった」と
		// 見分けが付かず、dispatched のまま残った記録に誰も気付けない。
		fail(ctx, err, "対応アクションの期限切れ処理に失敗しました")
		return
	}
	if n > 0 {
		// 沈黙させない。ここが継続的に鳴るなら、コマンドが届いていないか
		// エージェントが結果を返せていない。件数の推移そのものが配送経路の
		// 健全性を示す指標になる。
		slog.Warn("結果が返らなかった対応アクションを期限切れにしました",
			"件数", n, "期限", w.timeout)
	}
}
