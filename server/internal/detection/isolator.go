package detection

import (
	"context"

	"github.com/edr-platform/server/internal/isolation"
)

// Isolator is the subset of isolation.Gatekeeper that this package needs.
//
// detection は隔離を「決める」側で、「行う」側ではない。行うのは Gatekeeper
// だけで、安全弁（冷却期間・時間あたり上限・ドライラン）と response_actions への
// 記録はそちらに寄せてある。ここに判断を足すと、また経路ごとに規則が分かれる。
//
// インターフェースで受けるのは、Engine / PlaybookRunner / AIAgent のテストで
// Gatekeeper 一式（NATS・DB）を組み立てずに済ませるため。実体は常に
// *isolation.Gatekeeper。
type Isolator interface {
	Isolate(ctx context.Context, req isolation.Request) (isolation.Result, error)
}
