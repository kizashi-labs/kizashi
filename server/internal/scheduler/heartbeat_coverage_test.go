package scheduler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every background worker must leave a trace that it ran.
//
// Forty workers run on tickers in this package. Three emitted any metric, and
// there was no run-record table, so from outside a running process "woke up and
// had nothing to do" and "has never run once" were the same observation:
// nothing at all.
//
// hunt_scheduler is what that costs. It wakes every fifteen minutes, finds that
// saved_hunt_queries has no `scheduled` column, and returns. Zero hunts on
// every deployment that has ever existed, and the only way anyone found out was
// by reading the code.
//
// schema_gate_test.go catches that particular shape statically. This catches
// the general one at the only place it can be caught — the code — by requiring
// that each Run loop routes its work through trackRun, which increments
// edr_scheduler_runs_total and moves edr_scheduler_last_run_timestamp_seconds.
// A worker whose counter is not climbing is not running, and that is now a
// question with an answer.
//
// This is a coverage rule, not a style rule. It does not check that the metric
// is useful; it checks that the worker is not invisible.
//
// **これはファイル単位の検査です。** 「そのファイルのどこかに trackRun が
// あるか」しか見ません。実測 (2026-08-12): dead_agent_cleanup.go は 5 分の
// タイマーと 24 時間の ticker の2つの枝を持っていて、**24 時間の枝
// （日次の掃除そのもの）から trackRun を外しても、この検査は緑のまま**
// でした。片方の枝が残っていれば通ります。
//
// 枝ごとの検査は `internal/tick/tracked_workers_test.go` にあります
// （`TestEveryPeriodicWorkerRecordsThatItRan`）。あちらは
// `server/internal` 全体を1つの走査で見るので、この package だけ別の
// 規則、ということがありません。**ここに残しているのは、あちらが見て
// いない「記録の名前がファイル名と揃っていること」のためです。**

var runMethod = regexp.MustCompile(`func \([a-z] \*(\w+)\) Run\(ctx context\.Context\)`)

// schedulerFile is one worker's source.
type schedulerFile struct {
	name     string // file base name, which is also the metric label
	types    []string
	tracked  []string // labels passed to trackRun
	hasTrack bool
}

func readSchedulers(t *testing.T, dir string) []schedulerFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []schedulerFile
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") ||
			strings.HasSuffix(n, "_test.go") || n == "heartbeat.go" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, n))
		if rerr != nil {
			continue
		}
		src := string(b)
		types := []string{}
		for _, m := range runMethod.FindAllStringSubmatch(stripLineComments(src), -1) {
			types = append(types, m[1])
		}
		if len(types) == 0 {
			continue
		}
		labels := trackLabelsIn(src)
		out = append(out, schedulerFile{
			name:     strings.TrimSuffix(n, ".go"),
			types:    types,
			tracked:  labels,
			hasTrack: len(labels) > 0,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// untracked and mislabelled are separated out because on the passing path
// every worker is tracked with its own name, so neither loop below pushes —
// and a rule that never fires reads the same as one that was deleted.
func heartbeatProblems(files []schedulerFile) []string {
	var problems []string
	for _, f := range files {
		if !f.hasTrack {
			problems = append(problems, fmt.Sprintf(
				"%s.go は Run() を持っていますが trackRun を通していません。\n"+
					"  外からは「動いて何もすることが無かった」と「一度も動いていない」が\n"+
					"  区別できません。hunt_scheduler はその状態で0件のまま動き続けました。",
				f.name))
			continue
		}
		for _, label := range f.tracked {
			if label != f.name {
				problems = append(problems, fmt.Sprintf(
					"%s.go が %q という名前で記録しています。ファイル名と揃えてください。"+
						"揃っていないと、メトリクスから探す人がソースに辿り着けません。",
					f.name, label))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// The headline.
func TestEverySchedulerRecordsThatItRan(t *testing.T) {
	files := readSchedulers(t, schedulerDir)
	if len(files) < 35 {
		t.Fatalf("Run() を持つファイルが %d 個しか見つかりません。走査が届いていません", len(files))
	}
	for _, p := range heartbeatProblems(files) {
		t.Error(p)
	}
}

func TestTheHeartbeatRuleActuallyFires(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []schedulerFile
		want  int
	}{
		{"記録している", []schedulerFile{{name: "a", types: []string{"A"}, tracked: []string{"a"}, hasTrack: true}}, 0},
		{"記録していない", []schedulerFile{{name: "a", types: []string{"A"}}}, 1},
		{"名前がファイルと違う", []schedulerFile{{name: "a", types: []string{"A"}, tracked: []string{"b"}, hasTrack: true}}, 1},
		{"複数の記録が全部正しい", []schedulerFile{{name: "a", types: []string{"A"}, tracked: []string{"a", "a"}, hasTrack: true}}, 0},
		{"複数のうち1つが違う", []schedulerFile{{name: "a", types: []string{"A"}, tracked: []string{"a", "z"}, hasTrack: true}}, 1},
		{"2ファイルとも未記録", []schedulerFile{
			{name: "a", types: []string{"A"}}, {name: "b", types: []string{"B"}}}, 2},
		{"ワーカーが無い", nil, 0},
	} {
		if got := heartbeatProblems(tc.files); len(got) != tc.want {
			t.Errorf("%s: %d件 (want %d): %v", tc.name, len(got), tc.want, got)
		}
	}
}

// The scanner has to find the real workers and the real calls, or the contract
// above is satisfied by finding nothing on either side.
func TestTheSchedulerScannerReadsRealSources(t *testing.T) {
	files := readSchedulers(t, schedulerDir)

	byName := map[string]schedulerFile{}
	for _, f := range files {
		byName[f.name] = f
	}
	// A few that exist for certain, including the two whose tick body is not a
	// bare call and had to be given one.
	for _, want := range []string{
		"hunt_scheduler", "dead_agent_cleanup", "darkweb_scheduler",
		"daily_briefing_scheduler", "ioc_expiry_sweeper",
	} {
		f, ok := byName[want]
		if !ok {
			t.Errorf("%s を見つけられていません", want)
			continue
		}
		if !f.hasTrack {
			t.Errorf("%s の trackRun を読めていません", want)
		}
	}

	// heartbeat.go defines trackRun and is not itself a worker.
	if _, ok := byName["heartbeat"]; ok {
		t.Error("heartbeat.go をワーカーとして数えています")
	}

	// And a comment mentioning trackRun must not count as a call, or a file
	// could satisfy the rule by talking about it.
	if got := trackLabelsIn(`// trackRun(ctx, "ghost", x)` + "\nfunc f() {}\n"); len(got) != 0 {
		t.Errorf("コメント内の trackRun を呼び出しとして数えています: %v", got)
	}
	if got := trackLabelsIn(`	trackRun(ctx, "real", s.tick)` + "\n"); len(got) != 1 || got[0] != "real" {
		t.Errorf("本物の trackRun を読めていません: %v", got)
	}
	// alert_digest_sender has its own s.recordRun method; a method call on a
	// receiver must not be mistaken for the package function. The label here
	// has to be a legal one — an earlier version used "not-ours", and the
	// hyphen alone made the case pass whether the guard was there or not.
	if got := trackLabelsIn(`	s.trackRun(ctx, "not_ours", x)` + "\n"); len(got) != 0 {
		t.Errorf("レシーバ付きの呼び出しを数えています: %v", got)
	}
	if got := trackLabelsIn(`	x.y.trackRun(ctx, "nested", z)` + "\n"); len(got) != 0 {
		t.Errorf("入れ子のレシーバ付き呼び出しを数えています: %v", got)
	}
}

// trackLabelsIn pulls the labels out of one file's trackRun calls.
//
// This is the extraction readSchedulers uses, not a copy of it. It was a copy
// for one round, and the mutations that broke comment stripping and the
// receiver guard both survived — the tests were exercising a duplicate while
// the scan used the original. Testing a copy of the rule is the same shape as
// a rule nothing exercises.
//
// The `[^.\w]` guard keeps `s.trackRun(...)` out: alert_digest_sender has its
// own recordRun method on the receiver, and a package function and a method
// with similar names is exactly the confusion this would fall into.
var trackCall = regexp.MustCompile(`(?:^|[^.\w])trackRun\(ctx, "([a-z_0-9]+)"`)

func trackLabelsIn(src string) []string {
	var out []string
	for _, m := range trackCall.FindAllStringSubmatch(stripLineComments(src), -1) {
		out = append(out, m[1])
	}
	return out
}
