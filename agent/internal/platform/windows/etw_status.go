//go:build windows

package windows

import (
	"log/slog"

	"github.com/edr-platform/agent/internal/telemetry"
)

// ETW センサーの起動結果を、サーバに届く形で記録します。
//
// 7本の ETW センサー（レジストリ / WMI / 名前付きパイプ / スクリプトブロック /
// リモートスレッド / イメージロード / PowerShell モジュール）は、登録に
// 失敗しても `slog.Warn` を1行書いて `return nil` していました。
//
// **サーバから見ると、その端末は何も起きていない端末とまったく同じ姿を
// します。** イベントが来ないので一覧は短くならず、アラートも出ず、
// ハートビートは届き続け、画面は緑のまま。**攻撃されていないことと、
// 見えていないことの区別がつきません。** living-off-the-land の検知が
// 寄りかかっている面が、丸ごと落ちていても分かりません。
//
// **7本とも既定では動きません。** `etwEnabled()` は `EDR_AGENT_ETW=1` を
// 見る opt-in で、運用者が Windows サービスの環境変数に足して再起動する
// 手順です（`agent/scripts/README.md`）。つまりこの黙りが効くのは、
// **ETW をわざわざ有効にした端末**だけです —— その可視性を明示的に
// 求めた相手に対して黙るので、既定の端末より悪い形です。
//
// 無効にしてある（`!etwEnabled()`）ときは何も登録しません。登録すると
// Windows の端末が軒並み `telemetry_mode=off` を報告し始め、ポーリング
// 系のセンサーが健全に動いていても「何も集めていない」と読めます ——
// Aggregate のコメントが警告しているとおりの誤報です。**増やすのは
// 「動いていない」という事実だけにします。**
//
// `Start` の戻り値は変えていません。エラーを返すと、ETW が使えない端末
// （権限不足、セッション上限、プロバイダ不在）でエージェント自体が
// 起動しなくなる可能性があり、それは運用の判断だからです
// （docs/判断待ちの一覧.md）。**変えたのは、黙っていた点だけです。**
//
// 届け先は `internal/telemetry` です。ハートビートの `telemetry_mode` に
// 載り、サーバの `UpdateTelemetryMode` が `agents.telemetry_mode` に
// 書きます。**既に動いている経路で、Linux のセンサーが使っています。**
//
// （`internal/health.Reporter.SetCollectorStatus` の方が名前は近いのですが、
// あちらは本番から一度も呼ばれておらず、パッケージごとどこからも
// import されていません。送る先も受ける側もありません。）

// etwSensorFailed records that a sensor was meant to run and could not start.
//
// **ModeOff ではなく ModeFailed です。** off は「無効にしてある」で、
// 設定の選択なので Aggregate は数えません。failed は「望んだのに届かな
// かった」で、数えないと元の姿に戻ります。
func etwSensorFailed(sensor string, err error) {
	slog.Warn("ETW センサーを開始できませんでした。"+
		"この面は監視されていません", "sensor", sensor, "error", err)
	telemetry.Set(sensor, telemetry.ModeFailed, err.Error())
}

// ETW センサーの名前。ハートビート経由でサーバに届くので、
// 増やすときは表示側と揃えてください。
const (
	sensorETWRegistry  = "etw_registry"
	sensorETWWMI       = "etw_wmi"
	sensorETWPipe      = "etw_pipe"
	sensorETWScript    = "etw_script"
	sensorETWThread    = "etw_remote_thread"
	sensorETWImageLoad = "etw_image_load"
	sensorETWPSModule  = "etw_ps_module"
)
