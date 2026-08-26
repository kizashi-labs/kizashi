// build tag を付けていないのは意図です。付けると Linux では対象が
// 1件も見えず、検査は永久に緑になります。

package collector

import (
	"os"
	"strings"
	"testing"
)

// 「数えられなかった」を、空の一覧で表さないこと。
//
// macOS の2つが最後まで残っていました:
//
//	processListImpl   /proc が無ければ (nil, nil)
//	listDevices       system_profiler が無ければ (nil, nil)
//
// **どちらも呼び出し側は「0件」として扱います。** 稼働中の Mac で
// 「動いているプロセスは無い」、USB の抜き差しを見る収集で
// 「何も繋がっていない」—— 後者は持ち出しの経路です。
//
// `processListImpl` は特に鋭い形でした。**このファイルには /proc 以外の
// 経路がなく、macOS の実機に /proc はありません。** つまり常に0件を
// 成功として返していました。

func TestDarwinListsDoNotReturnEmptySuccess(t *testing.T) {
	for file, fn := range map[string]string{
		"process_monitor_darwin.go":  "processListImpl",
		"device_collector_darwin.go": "listDevices",
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s を読めません: %v", file, err)
			continue
		}
		src := string(b)

		if strings.Contains(src, "return nil, nil") {
			t.Errorf("%s (%s) がまだ (nil, nil) を返しています。"+
				"**呼び出し側には「0件」として届きます**", file, fn)
		}
		if !strings.Contains(src, "telemetry.ModeFailed") {
			t.Errorf("%s が telemetry に失敗を記録していません。"+
				"エラーは呼び出し側で止まり、サーバには届きません", file)
		}
		if !strings.Contains(src, "fmt.Errorf") {
			t.Errorf("%s がエラーを返していません", file)
		}
	}
}
