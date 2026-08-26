// engine_stateful.go — 公開版スタブ。
//
// 本流の同名ファイルは状態保持型（レート・相関）検知器の束を Engine にぶら下げる
// 継ぎ目で、公開版はそれらの検知器を同梱しない。engine.go 側との接点
// （statefulDetectors 型と 2 メソッド）だけを no-op で満たす。
package detection

import (
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// statefulDetectors はこの版では空。個々の検知器は同梱していない。
type statefulDetectors struct{}

func newStatefulDetectors(_ EngineConfig) statefulDetectors { return statefulDetectors{} }

// enrichCountryCode はこの版では何もしない（country_code の付与は同梱していない）。
func (e *Engine) enrichCountryCode(_ string, _ map[string]interface{}) {}

// observeStatefulDetectors はこの版では受け取った matches をそのまま返す。
func (e *Engine) observeStatefulDetectors(_ *EventEnvelope, _ map[string]interface{}, _ time.Time, matches []*detectionrules.RuleMatch) []*detectionrules.RuleMatch {
	return matches
}
