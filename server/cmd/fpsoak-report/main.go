// Command fpsoak-report scores a false-positive soak.
//
// It reads the run manifest written by agent/cmd/fleet-sim, pulls every alert
// those simulated agents produced, and turns them into a per-rule scorecard in
// the unit commercial EDR is judged by: false positives per 1000 hosts per day.
//
// The ground truth is structural, not statistical. fleet-sim emits only benign
// telemetry, so every alert attributed to a manifest agent is a false positive
// by construction. That is what makes unattended labelling possible at all —
// the platform's existing FP metrics (detectionmetrics.Tracker, the
// /api/v1/metrics/detection-stats handler) both count `status='false_positive'`,
// which only an analyst can set, so they read a flat zero on an unattended run.
// With -label this tool writes that status back, so the existing dashboards and
// KPI jobs light up from the soak with no further wiring.
//
// Usage
//
//	go run ./cmd/fpsoak-report -db "$DATABASE_URL" \
//	  -manifest /tmp/soak-manifest.json \
//	  -out docs/results/fpsoak-latest.csv -md docs/results/fpsoak-latest.md \
//	  -baseline docs/results/baseline_fp_soak.csv -baseline-tol 5
//
// Exit codes: 0 = within budget and baseline; 3 = regression or budget
// exceeded; 1 = the run could not be scored at all.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Manifest mirrors the JSON written by agent/cmd/fleet-sim. Only the fields this
// tool needs are declared; unknown fields are ignored so a newer simulator can
// add data without breaking scoring.
type Manifest struct {
	SchemaVersion     int              `json:"schema_version"`
	StartedAt         time.Time        `json:"started_at"`
	EndedAt           time.Time        `json:"ended_at"`
	HostnamePrefix    string           `json:"hostname_prefix"`
	Seed              uint64           `json:"seed"`
	Speed             float64          `json:"speed"`
	SimulatedHostDays float64          `json:"simulated_host_days"`
	AgentCount        int              `json:"agent_count"`
	Profiles          map[string]int   `json:"profiles"`
	Agents            []ManifestAgent  `json:"agents"`
	EventsByType      map[string]int64 `json:"events_by_type"`
	EventsTotal       int64            `json:"events_total"`
	SendErrors        int64            `json:"send_errors"`
}

// ManifestAgent is one simulated host.
type ManifestAgent struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Profile  string `json:"profile"`
}

const (
	exitRegression = 3
)

func main() {
	var (
		dbURL        = flag.String("db", os.Getenv("DATABASE_URL"), "PostgreSQL接続URL (既定: $DATABASE_URL)")
		manifestPath = flag.String("manifest", "", "fleet-sim が出力した実行マニフェスト (必須)")
		outCSV       = flag.String("out", "", "スコアカードCSVの出力先")
		outMD        = flag.String("md", "", "Markdownサマリの出力先")
		window       = flag.Duration("window", 15*time.Minute, "ソーク終了後、この時間内に発生したアラートを集計対象とする")
		quiesce      = flag.Duration("quiesce", 90*time.Second, "窓の終端で、この期間の増加が残っていれば遅延として警告する (0で無効)")
		strict       = flag.Bool("strict", false, "窓の終端でまだ検知が遅延している場合に失敗する")
		label        = flag.Bool("label", false, "対象アラートを status='false_positive' でDBに書き戻す")
		baselinePath = flag.String("baseline", "", "比較するベースラインCSV")
		baselineTol  = flag.Float64("baseline-tol", 0, "全体の誤検知率に対する許容増分 (件/1000ホスト/日)")
		ruleTol      = flag.Float64("rule-tol", 0, "個別ルールに対する許容増分。総量より小さく取る (0 = -baseline-tol と同じ)")
		newRuleFloor = flag.Float64("new-rule-floor", 0, "この値未満のルールはゲート判定から除外する")
		budget       = flag.Float64("budget", 0, "全体誤検知率の上限 (0 = 無効)")
		maxEventLoss = flag.Float64("max-event-loss", 0,
			"送信したイベントのうちDBに着信しなかった割合の上限 (%)。超えたら失敗する (0 = 無効)")
		eventSettle = flag.Duration("event-settle", 0,
			"着信数を数えた後この時間待って数え直し、遅れて着いた分を切り分ける (0 = 無効)")
	)
	flag.Parse()

	if *manifestPath == "" {
		log.Fatal("-manifest は必須です")
	}
	if *dbURL == "" {
		log.Fatal("-db または DATABASE_URL が必要です")
	}

	manifest, err := loadManifest(*manifestPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("マニフェスト: %d 台 / %.3f ホスト日 / 送信 %d イベント (seed=%d speed=%g)",
		manifest.AgentCount, manifest.SimulatedHostDays, manifest.EventsTotal,
		manifest.Seed, manifest.Speed)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		log.Fatalf("DB接続に失敗しました: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("DBに疎通できません: %v", err)
	}

	agentIDs, agentProfile := indexAgents(manifest)
	if len(agentIDs) == 0 {
		log.Fatal("マニフェストに登録済みエージェントがありません — ソークは実行されていません")
	}

	win := scoringWindow(manifest, *window)
	waitForWindowClose(win)

	// Reachability check before scoring. A soak whose telemetry never reached
	// the database produces zero alerts and would otherwise be reported as a
	// perfect FP rate — the same silent-success failure mode the detection
	// reachability work (#480/#491/#492) was built to eliminate. Refuse to score
	// instead of publishing a flattering zero.
	events, err := countEvents(ctx, pool, agentIDs, win)
	if err != nil {
		log.Fatalf("イベント数の照会に失敗しました: %v", err)
	}
	// #nosec G706 -- both arguments are ints (a COUNT(*) and a manifest counter);
	// there is no string that could inject log lines.
	log.Printf("DBに着信したイベント: %d 件 (送信 %d 件)", events, manifest.EventsTotal)
	if manifest.EventsTotal > 0 && events == 0 {
		log.Fatalf("送信 %d 件に対しDBのイベントが0件です — 取り込み経路が壊れており、"+
			"このソークは採点できません", manifest.EventsTotal)
	}
	events = settleEventCount(ctx, pool, agentIDs, win, events, *eventSettle)
	eventLossPct := eventLossRate(manifest.EventsTotal, events)
	eventLossFailed := reportEventLoss(manifest.EventsTotal, events, eventLossPct, *maxEventLoss)

	lagging, err := detectionStillLagging(ctx, pool, agentIDs, win, *quiesce)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if lagging {
		msg := "窓の終端でもアラートが増え続けています — 検知エンジンが遅延しており、" +
			"この結果は過小評価 (下限) です"
		if *strict {
			log.Fatalf("%s。-strict のため採点を中止します", msg)
		}
		log.Printf("⚠️  %s", msg)
	}

	rows, err := fetchAlerts(ctx, pool, agentIDs, win)
	if err != nil {
		log.Fatalf("アラートの照会に失敗しました: %v", err)
	}
	sc := Aggregate(rows, manifest.SimulatedHostDays, agentProfile, manifest.AgentCount)

	log.Printf("誤検知: %d 件 = %.1f 件/1000ホスト/日 (%d ルール)",
		sc.TotalAlerts, sc.Rate, len(sc.Rules))
	if sc.HarnessAlerts > 0 {
		// The run total is never adjusted, but the two halves mean different things:
		// the harness share is a fixed per-host toll of ending the soak, so quoting
		// the whole figure as "detection noise" overstates it and makes it move with
		// fleet size for reasons that have nothing to do with detection content.
		log.Printf("  ├ 検知コンテンツ由来: %d 件 = %.1f 件/1000ホスト/日",
			sc.DetectionAlerts, sc.DetectionRate)
		log.Printf("  └ 測定ハーネス由来: %d 件 (ソーク終了に伴う死活監視アラート)",
			sc.HarnessAlerts)
	}

	if *label {
		n, err := labelFalsePositives(ctx, pool, rows)
		if err != nil {
			log.Fatalf("誤検知ラベルの書き戻しに失敗しました: %v", err)
		}
		// #nosec G706 -- n is the int64 row count from the UPDATE, not a string.
		log.Printf("status='false_positive' を %d 件に書き戻しました", n)
	}

	if err := emit(sc, manifest, events, eventLossPct, *outCSV, *outMD); err != nil {
		log.Fatalf("%v", err)
	}

	// -rule-tol を省いた呼び出しは従来どおり単一許容値として振る舞う。
	rt := *ruleTol
	if rt == 0 {
		rt = *baselineTol
	}
	code := gate(sc, *baselinePath, *baselineTol, rt, *newRuleFloor, *budget)
	// An ingest shortfall fails on its own, even when the FP gate is clean. The
	// two answer different questions and a passing FP rate measured on telemetry
	// that never arrived is the more misleading of the two.
	if eventLossFailed && code == 0 {
		code = exitRegression
	}
	os.Exit(code)
}

// settleEventCount re-counts arrivals after a pause and returns the larger figure.
//
// This is the experiment P2-7 asks for. The soak counts arrivals the moment the
// scoring window closes, and telemetry sent near the end of the window may still
// be in flight — the row's `time` is inside the window, so a later count picks it
// up. That mechanism would produce exactly the shape observed on 2026-08-04:
// 0, 0, 16, 16, 34, 81, 328, 405 events "lost" across eight runs of the same
// manifest, small most of the time and occasionally a long tail.
//
// The alternative is that the ingestion path really drops events. The two demand
// different fixes — one is a measurement artifact, the other a defect — and the
// numbers alone cannot tell them apart. Waiting and re-counting can: if the
// shortfall closes, it was the boundary; if it persists, the events are gone.
//
// The delta is logged either way, so each run contributes evidence instead of
// just a number. The larger count is returned because a row that arrives during
// the pause was never lost, only late.
func settleEventCount(ctx context.Context, pool *pgxpool.Pool, agentIDs []string,
	w window, first int64, settle time.Duration) int64 {
	if settle <= 0 {
		return first
	}
	log.Printf("着信数の確定待ち: %s", settle)
	select {
	case <-ctx.Done():
		return first
	case <-time.After(settle):
	}
	second, err := countEvents(ctx, pool, agentIDs, w)
	if err != nil {
		log.Printf("⚠️  着信数の数え直しに失敗しました（最初の値を使います）: %v", err)
		return first
	}
	late := second - first
	switch {
	case late > 0:
		// #nosec G706 -- all arguments are int64 counters from COUNT(*).
		log.Printf("遅れて着信: %d 件 (%d → %d)。窓を閉じた時点の欠損はこの分だけ"+
			"「実欠損ではなく測り方」だったことになる", late, first, second)
	case late < 0:
		// #nosec G706 -- both arguments are int64 COUNT(*) results.
		log.Printf("⚠️  数え直しで件数が減りました (%d → %d)。窓内の行が消えているので、"+
			"保持期間の削除など別の要因を疑うこと", first, second)
		return first
	default:
		log.Printf("遅れて着信: 0 件。窓を閉じた時点で着信は確定していた")
	}
	return second
}

// eventLossRate returns the percentage of sent events that never reached the DB.
// A negative difference (more rows than sent) reads as 0 rather than a negative
// rate: leftover rows from an earlier run are a separate problem, not a loss.
func eventLossRate(sent, arrived int64) float64 {
	if sent <= 0 {
		return 0
	}
	lost := sent - arrived
	if lost <= 0 {
		return 0
	}
	return float64(lost) / float64(sent) * 100
}

// reportEventLoss logs the ingest shortfall and reports whether it breaches maxPct.
//
// The soak has always printed both numbers and never compared them, so telemetry
// could go missing between the simulated agents and the events table without
// anything failing. Measured across six 2026-08-04 runs of the same manifest: 0,
// 16, 34, 81, 328 and 405 events lost (0%–0.27%). One run lost nothing, so the
// pipeline can deliver the full set inside the window — this is jitter or real
// loss, not a structural boundary artifact.
//
// It matters because a lost event is a missed detection that leaves no trace. A
// technique that fires once has a ~0.27% chance of simply not being there, and
// ATT&CK detection-rate measurements cannot distinguish "the rule failed" from
// "the event never arrived". The gate exists so that number cannot grow silently:
// nothing in this harness would have objected at 50%.
//
// Reported even when the gate is off, because the figure is the input to deciding
// whether a detection-rate miss was a detection problem at all.
func reportEventLoss(sent, arrived int64, lossPct, maxPct float64) bool {
	lost := sent - arrived
	if lost <= 0 {
		// #nosec G706 -- sent is an int64 manifest counter; no string reaches the log.
		log.Printf("イベント欠損: 0 件 (送信 %d 件すべて着信)", sent)
		return false
	}
	// #nosec G706 -- every argument is numeric (int64 counters and a computed
	// float64 rate); there is no string that could inject log lines.
	log.Printf("イベント欠損: %d 件 = %.3f%% (送信 %d / 着信 %d)", lost, lossPct, sent, arrived)
	if maxPct <= 0 || lossPct <= maxPct {
		return false
	}
	annotate("送信イベントの %.3f%% (%d 件) がDBに届いていません — 上限 %.3f%%。"+
		"失われたイベントは痕跡の残らない検知漏れであり、検知率の測定では"+
		"「ルールが鳴らなかった」のか「イベントが来なかった」のか区別できません",
		lossPct, lost, maxPct)
	return true
}

// annotate prints a GitHub Actions error annotation alongside the log line.
//
// The gate's verdict is the one thing a reader needs from a 40-minute job, and
// it sits near the end of a log the runner then buries under its dump of the
// postgres service container. An ::error:: line is surfaced by GitHub as a check
// annotation on the PR, so the reason a soak went red is visible without opening
// the log at all.
func annotate(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("❌ %s", msg)
	// Annotations are single-line; a newline would truncate the rest.
	fmt.Printf("::error title=FPソーク退行::%s\n", strings.ReplaceAll(msg, "\n", " "))
}

// gate applies the budget and baseline checks, returning the process exit code.
func gate(sc Scorecard, baselinePath string, totalTol, ruleTol, floor, budget float64) int {
	failed := false

	if budget > 0 && sc.Rate > budget {
		annotate("予算超過: %.2f > %.2f 件/1000ホスト/日", sc.Rate, budget)
		failed = true
	}

	if baselinePath != "" {
		baseline, err := readBaselineFile(baselinePath)
		if err != nil {
			log.Fatalf("%v", err)
		}
		regressions := CompareBaseline(sc, baseline, totalTol, ruleTol, floor)
		if len(regressions) == 0 {
			log.Printf("✅ ベースライン比較: 退行なし (baseline %.2f → 今回 %.2f)",
				baseline.Rate, sc.Rate)
		} else {
			// Lead with the headline so the first annotation carries the totals
			// even when a long tail of per-rule regressions follows.
			annotate("誤検知 %d件 = %.2f 件/1000ホスト/日 (%d ルール) — baseline %.2f から退行",
				sc.TotalAlerts, sc.Rate, len(sc.Rules), baseline.Rate)
			for _, r := range regressions {
				annotate("%s", r.Message)
			}
			failed = true
		}
	}

	if failed {
		return exitRegression
	}
	return 0
}

func emit(sc Scorecard, m *Manifest, stored int64, lossPct float64, outCSV, outMD string) error {
	if outCSV != "" {
		if err := writeToFile(outCSV, func(w io.Writer) error { return WriteCSV(w, sc) }); err != nil {
			return fmt.Errorf("CSVの書き出しに失敗しました: %w", err)
		}
		log.Printf("スコアカードCSV: %s", outCSV)
	}
	if outMD != "" {
		meta := MarkdownMeta{
			RunLabel:     m.StartedAt.Format("2006-01-02 15:04 MST"),
			EventsTotal:  m.EventsTotal,
			EventsStored: stored,
			EventLossPct: lossPct,
		}
		if err := writeToFile(outMD, func(w io.Writer) error { return WriteMarkdown(w, sc, meta) }); err != nil {
			return fmt.Errorf("サマリ用Markdownファイルの書き出しに失敗しました: %w", err)
		}
		log.Printf("Markdownサマリ: %s", outMD)
	}
	if outCSV == "" && outMD == "" {
		return WriteCSV(os.Stdout, sc)
	}
	return nil
}

// writeToFile creates path, hands the file to write, and reports the first of
// the write error and the close error. Close is checked deliberately rather than
// deferred away: the CSV this produces is what the next run's regression gate
// reads back, and a flush failure surfacing only at Close would otherwise leave
// a silently truncated scorecard that compares as a clean, improved run.
func writeToFile(path string, write func(io.Writer) error) (err error) {
	// #nosec G304 -- path comes from the operator's own -out/-md flags on a local
	// reporting CLI; no untrusted input reaches this process.
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("ファイルの作成に失敗しました: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("ファイルのクローズに失敗しました: %w", cerr)
		}
	}()
	return write(f)
}

// ─── manifest ─────────────────────────────────────────────────

func loadManifest(path string) (*Manifest, error) {
	// #nosec G304 -- path comes from the operator's own -manifest flag on a local
	// reporting CLI; no untrusted input reaches this process.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("マニフェストの読み込みに失敗しました: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("マニフェストのパースに失敗しました: %w", err)
	}
	if m.SimulatedHostDays <= 0 {
		return nil, fmt.Errorf("マニフェストの simulated_host_days が %v です — 正規化できません",
			m.SimulatedHostDays)
	}
	if m.EndedAt.Before(m.StartedAt) {
		return nil, fmt.Errorf("マニフェストの期間が不正です: %s → %s", m.StartedAt, m.EndedAt)
	}
	return &m, nil
}

func indexAgents(m *Manifest) ([]string, map[string]string) {
	ids := make([]string, 0, len(m.Agents))
	byID := make(map[string]string, len(m.Agents))
	for _, a := range m.Agents {
		if a.AgentID == "" {
			continue
		}
		ids = append(ids, a.AgentID)
		byID[a.AgentID] = a.Profile
	}
	return ids, byID
}

type window struct {
	from time.Time
	to   time.Time
}

// scoringWindow bounds which alerts belong to this run.
//
// The lower bound is slightly before the run starts to absorb clock skew between
// the simulator and the database. The upper bound extends past the end by the
// settle period because detection is asynchronous — the stateful burst detectors
// in particular only fire once their sliding window closes, so alerts caused by
// the run keep arriving after the last event was sent. Cutting the window at
// EndedAt would systematically undercount exactly the detectors most likely to
// produce false positives.
// scoringWindow bounds which alerts belong to this run.
//
// The lower bound sits slightly before the run starts to absorb clock skew. The
// upper bound is a FIXED offset past the run's end — not "however long it took to
// go quiet" — because detection is asynchronous and never fully stops: periodic
// batch producers keep adding alerts long after the event backlog is consumed.
// Scoring whenever the count happened to look stable made the result a function
// of when the tool was run rather than of the detection content, which is fatal
// for a baseline. A fixed window makes two runs of the same configuration
// directly comparable.
//
// A generous upper bound is safe because the window is already scoped to this
// run's agent IDs, which are freshly enrolled per run. The one case to watch is
// `fleet-sim -state` reuse: two soaks sharing the same agents must be separated
// by more than this window, or the later run's alerts bleed into the earlier
// run's score.
func scoringWindow(m *Manifest, after time.Duration) window {
	return window{
		from: m.StartedAt.Add(-2 * time.Minute),
		to:   m.EndedAt.Add(after),
	}
}

// waitForWindowClose blocks until wall-clock passes the end of the scoring
// window, so a run is scored over exactly the same period no matter when the
// tool is launched.
func waitForWindowClose(w window) {
	remaining := time.Until(w.to)
	if remaining <= 0 {
		return
	}
	log.Printf("集計窓が閉じるまで待機します: %s (窓の終端 %s)",
		remaining.Round(time.Second), w.to.UTC().Format(time.RFC3339))
	time.Sleep(remaining)
}

// detectionStillLagging reports whether alerts were still arriving in bulk as
// the scoring window closed, which means the engine had not finished with the
// run's events and the score is a floor rather than the real figure.
//
// This is a diagnostic, not a rule for when to score. Scoring waits for a fixed
// window rather than for the alert count to go flat, because the count never
// does: the detection service runs periodic batch producers (the correlation
// engine, the retro rule hunter, the insider-threat and network-anomaly
// schedulers) that keep adding a slow trickle indefinitely. Waiting for quiet
// made the result depend on *when* scoring started — the same run scored 370
// alerts at one moment and 391 a few minutes later, so no two runs were
// comparable and a baseline meant nothing. A fixed window makes the measurement
// reproducible; this check keeps the one thing the quiet-wait was genuinely
// protecting against — a lagging engine being mistaken for a quiet one — by
// reporting it explicitly instead of silently returning a small number.
func detectionStillLagging(ctx context.Context, pool *pgxpool.Pool, agentIDs []string,
	w window, quiesce time.Duration) (bool, error) {
	if quiesce <= 0 {
		return false, nil
	}
	total, err := countAlertsBetween(ctx, pool, agentIDs, w.from, w.to)
	if err != nil {
		return false, fmt.Errorf("アラート数の照会に失敗しました: %w", err)
	}
	tail, err := countAlertsBetween(ctx, pool, agentIDs, w.to.Add(-quiesce), w.to)
	if err != nil {
		return false, fmt.Errorf("アラート数の照会に失敗しました: %w", err)
	}
	// ここは「到着した生の件数」で数える。採点側 (fetchAlerts) は dedup が
	// 統合済みの写しを除くが、この検査の目的は「エンジンが追いつききったか」で
	// あって誤検知率ではない。統合されて減った分を「落ち着いた」と読むと、
	// まだ流れ込んでいる最中に採点してしまう。数え方が違うので、採点対象では
	// なく到着数だと分かる文言にしておく。
	//
	// #nosec G706 -- the arguments are two ints and a time.Duration parsed from a
	// CLI flag; none can carry a newline into the log.
	log.Printf("到着アラート: %d 件 (うち窓の最後 %s に %d 件)", total, quiesce, tail)
	return tail > residualTolerance(total), nil
}

// residualTolerance is the alert count in the final quiescence slice that still
// counts as settled: 5% of the run total, with a floor of 2 so a small run is
// not flagged by a single late alert. A backlog still draining lands far more
// than this, because it arrives at the full ingest rate.
func residualTolerance(count int) int {
	tol := count / 20
	if tol < 2 {
		tol = 2
	}
	return tol
}

func countAlertsBetween(ctx context.Context, pool *pgxpool.Pool, agentIDs []string,
	from, to time.Time) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM alerts
		WHERE agent_id = ANY($1::uuid[]) AND created_at >= $2 AND created_at <= $3
	`, agentIDs, from, to).Scan(&n)
	return n, err
}

func countEvents(ctx context.Context, pool *pgxpool.Pool, agentIDs []string, w window) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM events
		WHERE agent_id = ANY($1::uuid[]) AND time >= $2 AND time <= $3
	`, agentIDs, w.from, w.to).Scan(&n)
	return n, err
}

// notMergedDuplicate は「dedup が別のアラートへ統合した写し」を除く条件。
//
// 検知は 2 プロセスに分かれており、PR #647 で rules テーブルが api 経路にも
// 繋がった結果、DB ルールは server-detect と server-api の両方が評価する。
// 1 つの検知が 2 行になる:
//
//	[SIGMA] X   (server-detect)
//	[Sigma] X   (server-api)
//
// dedup.AlertDeduplicator はこれを統合するが、行は消さない — 生存側に
// dedup_key を立て、統合された側を status='resolved' にして注記を足すだけ。
// 一方このレポートは status を見ずに数えていたため、統合済みの写しまで
// 誤検知として計上していた。集計キー (ruleKey → foldEnginePrefix) が
// [SIGMA] と [Sigma] を畳むので、両方の写しが 1 行に合算されて件数が倍になる。
//
// 実測 (CI run 2026-08-12): "RDP Lateral Movement via xfreerdp or mstsc" が
// 6 → 12 件。baseline (2026-08-02、#647 より前) には server-detect の 6 件しか
// 無かった。運用者が画面で向き合う件数は統合後の 6 件なので、12 は計測の側の
// 数え間違いであって誤検知の増加ではない。
//
// 誤検知率は「運用者が実際に向き合う件数」でなければ意味がないので、統合済みの
// 写しは数えない。生存側にも dedup_key は付くため dedup_key IS NULL では生存側
// まで落ちる。status との組み合わせで判定する。解析者が手で resolved にした
// アラートは dedup_key を持たないので残る。
const notMergedDuplicate = `AND NOT (status = 'resolved' AND dedup_key IS NOT NULL)`

func fetchAlerts(ctx context.Context, pool *pgxpool.Pool, agentIDs []string, w window) ([]AlertRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text,
		       COALESCE(rule_id::text, ''),
		       title,
		       severity,
		       agent_id::text,
		       COALESCE(mitre_technique, ''),
		       created_at
		FROM alerts
		WHERE agent_id = ANY($1::uuid[]) AND created_at >= $2 AND created_at <= $3
		  `+notMergedDuplicate+`
		ORDER BY created_at
	`, agentIDs, w.from, w.to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Title, &a.Severity,
			&a.AgentID, &a.Technique, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// labelFalsePositives writes the soak's ground truth back into the alerts table
// so the platform's existing FP metrics reflect it without any manual triage.
func labelFalsePositives(ctx context.Context, pool *pgxpool.Pool, rows []AlertRow) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	tag, err := pool.Exec(ctx, `
		UPDATE alerts
		   SET status = 'false_positive', updated_at = NOW()
		 WHERE id = ANY($1::uuid[]) AND status <> 'false_positive'
	`, ids)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func readBaselineFile(path string) (Scorecard, error) {
	// #nosec G304 -- path comes from the operator's own -baseline flag on a local
	// reporting CLI; no untrusted input reaches this process.
	f, err := os.Open(path)
	if err != nil {
		return Scorecard{}, fmt.Errorf("ベースラインの読み込みに失敗しました: %w", err)
	}
	// Read-only: nothing is lost if Close fails, so the error is dropped
	// explicitly rather than left unchecked.
	defer func() { _ = f.Close() }()
	sc, err := ReadCSV(f)
	if err != nil {
		return Scorecard{}, fmt.Errorf("ベースライン %s: %w", path, err)
	}
	return sc, nil
}
