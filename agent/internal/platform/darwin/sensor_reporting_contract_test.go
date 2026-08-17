// build tag を付けていないのは意図です。付けると Linux では対象が
// 1件も見えず、検査は永久に緑になります。

package darwin_test

import (
	"os"
	"strings"
	"testing"
)

// macOS のセンサーが動いていないことが、黙って捨てられていないこと。
//
// **Windows の ETW 7本とまったく同じ形でした。** 認証コレクタは
// `log` コマンドが無ければ1行書いて `return nil`、DNS コレクタは
// `tcpdump` を起動できなければ1行書いて `return`。エージェントは
// 動き続け、**サーバから見た端末は何も起きていない端末と同じ姿**です。
//
// いまは telemetry に ModeFailed で登録します。

func TestMacSensorFailuresAreReported(t *testing.T) {
	for file, sensor := range map[string]string{
		"auth_collector.go": "sensorAuth",
		"dns_collector.go":  "sensorDNS",
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s を読めません: %v", file, err)
			continue
		}
		src := string(b)
		if !strings.Contains(src, "sensorUnavailable("+sensor) {
			t.Errorf("%s が起動失敗を報告していません。"+
				"その面は監視されていないのに、画面は緑のままです", file)
		}
		// 元の形に戻っていないこと。
		if strings.Contains(src, `slog.Warn("DNS 監視を開始できませんでした`) ||
			strings.Contains(src, `slog.Info("macOS の log コマンドが見つかりません`) {
			t.Errorf("%s がログだけに戻っています", file)
		}
	}
}

// 記録が ModeFailed であること。**ModeOff だと Aggregate に無視され、
// 報告した気になるだけです。**
func TestTheMacDegradationIsFailedNotOff(t *testing.T) {
	b, err := os.ReadFile("sensor_status.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "telemetry.ModeFailed") {
		t.Error("ModeFailed で登録していません")
	}
	if strings.Contains(s, "telemetry.ModeOff") {
		t.Error("ModeOff で登録しています。Aggregate に無視されるので、" +
			"報告した気になるだけです")
	}
}
