package detection

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The process-execution anomaly detector counts rows in `events` keyed on
// raw_data->>'process_name'. That field is NOT exclusive to process events:
// image_load, registry, file and network events all carry it. Without an
// event_type filter the detector does not measure "how often this process ran",
// it measures "how many events of any kind mention this name".
//
// On the validation host (2026-08-05) that surfaced as a stream of
//
//	異常なプロセス実行パターン: kernel32.dll
//	異常なプロセス実行パターン: crypt32.dll
//
// one alert per DLL — image_load events being counted as process executions.
// (The agent compounded it by putting the loaded module's own base name in
// ProcessName; fixed separately. Even with that corrected, an unfiltered query
// would still count every DLL load against the loading process's execution
// count.)
//
// Both queries must carry the filter, and they must AGREE: the detector INNER
// JOINs its result against process_baselines, so filtering only one side makes
// the join miss and the detector goes quiet — a silent loss of detection rather
// than a visible error.
//
// A string check on the SQL is coarse, but the alternative is a live DB and this
// is the property that actually broke. It fails loudly if either query is edited
// to drop the scope.
func TestAnomalyQueriesAreScopedToProcessEvents(t *testing.T) {
	src, err := os.ReadFile("anomaly.go")
	if err != nil {
		t.Fatalf("anomaly.go を読めません: %v", err)
	}
	body := string(src)

	for _, fn := range []string{"DetectAnomalies", "UpdateBaselines"} {
		q := functionBody(t, body, fn)
		if !strings.Contains(q, "process_name") {
			t.Fatalf("%s が process_name を参照していません。テストの前提が壊れています", fn)
		}
		if !regexp.MustCompile(`event_type\s*=\s*'process'`).MatchString(q) {
			t.Errorf("%s のクエリに event_type = 'process' がありません。"+
				"process_name は image_load / registry / file / network も持つため、"+
				"絞らないと DLL ロード等がプロセス実行として数えられます", fn)
		}
	}
}

// functionBody returns the source of the named top-level func.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, ") "+name+"(")
	if start < 0 {
		start = strings.Index(src, "func "+name+"(")
	}
	if start < 0 {
		t.Fatalf("関数 %s が見つかりません", name)
	}
	// Up to the next top-level func, or end of file.
	rest := src[start:]
	if i := strings.Index(rest[1:], "\nfunc "); i >= 0 {
		rest = rest[:i+1]
	}
	return rest
}
