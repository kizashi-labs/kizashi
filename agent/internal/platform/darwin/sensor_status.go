//go:build darwin

package darwin

import (
	"log/slog"

	"github.com/edr-platform/agent/internal/telemetry"
)

// macOS のセンサーが動いていないことを、サーバに届く形で記録します。
//
// **Windows の ETW 7本とまったく同じ形でした。** 認証コレクタは
// `log` コマンドが無ければ `slog.Info` を1行書いて `return nil`、
// DNS コレクタは `tcpdump` を起動できなければ `slog.Warn` を1行書いて
// `return`。どちらもエージェントは動き続け、**サーバから見た端末は
// 何も起きていない端末とまったく同じ姿**になります。
//
// 届け先は `internal/telemetry` —— ハートビートの `telemetry_mode` に
// 載り、サーバの `agents.telemetry_mode` に入ります。ETW と同じ経路です。

// sensorUnavailable records that a sensor was meant to run and could not.
//
// **ModeOff ではなく ModeFailed です。** off は「無効にしてある」で、
// 設定の選択なので Aggregate は数えません。failed は「望んだのに
// 届かなかった」です。
func sensorUnavailable(sensor, why string, err error) {
	slog.Warn("センサーを開始できませんでした。この面は監視されていません",
		"sensor", sensor, "reason", why, "error", err)
	telemetry.Set(sensor, telemetry.ModeFailed, why)
}

// macOS センサーの名前。ハートビート経由でサーバに届きます。
const (
	sensorAuth = "macos_auth"
	sensorDNS  = "macos_dns"
)
