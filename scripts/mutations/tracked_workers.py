#!/usr/bin/env python3
"""周期的に回る仕事が、回ったことを残すこと。

対象:
  server/internal/tick/tick.go
  server/internal/tick/tracked_workers_test.go
  server/internal/scheduler/heartbeat.go
  server/internal/scheduler/fail_reaches_someone_test.go
  server/internal/detection/correlation.go
  server/internal/cloud/poller.go
  server/internal/store/rows_err_returnable_test.go
  server/internal/compliance/scheduler.go
  server/internal/scheduler/dead_agent_cleanup.go

実測 (2026-08-12): `server/internal` に ticker を持つ箇所は 73。うち
`internal/scheduler` が 36、**その外が 37 で、1つも run を記録していません
でした。** 外の 34 関数のうち 20 を包み、14 は理由を書いて外しました
（接続ごと 7・メモリの掃除 5・周期の仕事でないもの 2）。

**そのあと、走査の側に同じ欠陥が3つ見つかりました。**「狭く探して、
無かったことにする」—— このキャンペーンで何度も直してきた形が、
検査自身にありました:

  1. 合図を `time.NewTicker` だけで探していた。**毎日 02:00 に回る
     `internal/compliance/scheduler.go` が丸ごと外れていました**
     （`time.After(time.Until(next))` の形）。→ 包みました。
  2. 枝を `select` だけで探していた。`for range ticker.C {` の形が4つ
     あり、**理由は一度も参照されていませんでした** —— 「理由があるから
     通っている」ではなく「見ていないから通っている」でした。
  3. 仕事を枝の中だけで探していた。**待つのが枝で、仕事が本体にある形**
     （work-then-wait）が3つあり、枝が空だという理由だけで黙って
     通っていました。→ 理由を書かせる形にしました。

走査を広げたあと: 対象 37、理由つきで外したもの 16。**理由が本当に何かを
留めているかも、逆から確かめます**（理由を取り上げたら違反として挙がる
こと）。

**4つめは、`internal/scheduler` を丸ごと対象外にしていたことでした。**
「あちらは `heartbeat_coverage_test.go` が見ている」——**あちらが見て
いるのはファイル単位です**（そのファイルのどこかに `trackRun` があるか）。
実測: `dead_agent_cleanup.go` の 24 時間の枝（日次の掃除そのもの）から
`trackRun` を外しても、あちらは緑のままでした。5 分のタイマーの枝が
残っているからです。

走査を `server/internal` 全体に広げました。対象 76（`internal/scheduler`
の 39 を含む）、包んでいない枝 0、`tick.Run`/`trackRun` に渡している
仕事 39。**`trackRun` は `tick.Run` への1行の委譲で、その定義が1つだけ
であることも見ています** —— 自前の `trackRun` を書けば、包まずに
通せてしまうからです。

`internal/scheduler` には既にこの仕組みがありました —— 「40 のワーカーの
うち、計測を出していたのは3つ」という実測から作られたものです。
**その仕事は package の中で止まっていました。** 外のワーカーは、動いて
いるのか一度も動いていないのかを、外から区別できません。

もう1つ、前回の続きがあります。`fail` は `internal/scheduler` の中でしか
使えませんでした（`tickState` が package 内）。外の 16 か所は `slog.Error`
止まりで、**「回っているが何もできていない」が計測に出ませんでした。**

`internal/tick` に出して、両側が同じ形で報告できるようにしました。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  接続ごと・要求ごとの ticker（7個）とメモリの掃除（5個）への変異も
  置いていません。**包む対象ではないからです** —— 理由を一覧に書いて
  あります。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

K = 'server/internal/tick/tick.go'
T = 'server/internal/tick/tracked_workers_test.go'
H = 'server/internal/scheduler/heartbeat.go'
F = 'server/internal/scheduler/fail_reaches_someone_test.go'
CO = 'server/internal/detection/correlation.go'
CP = 'server/internal/cloud/poller.go'
R = 'server/internal/store/rows_err_returnable_test.go'

CASES = [
    # ── 仕組みそのもの ───────────────────────────────────────────────────
    (K, '\tif n := st.count(); n > 0 {\n\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))\n\t\treturn\n\t}\n',
        '',
     '諦めた回でも成功として刻む（**毎回失敗しているワーカーが、健全な'
     'ワーカーと同じ形になります**）'),
    (K, '\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))\n\t\treturn\n',
        '\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))\n',
     '失敗を記録したあとに戻らない（成功時刻も一緒に動きます）'),
    (K, '\tif st, ok := ctx.Value(stateKey{}).(*state); ok {\n\t\tst.add()\n\t}\n', '',
     '`Fail` がログだけになる（**`slog.Warn` のままと変わりません**）'),
    (K, '\tst := &state{}\n\tstart := time.Now()', '\tvar st *state\n\tstart := time.Now()',
     '回ごとの記録を渡さなくなる'),
    (K, '\tslog.Error(msg, append(args, "error", err)...)\n',
        '\tslog.Warn(msg, append(args, "error", err)...)\n',
     '`Fail` が、切られる段に落ちる'),

    # ── ワーカーが包まれていること ───────────────────────────────────────
    (CO, '\t\t\ttick.Run(ctx, "correlation_engine", ce.runOnce)\n',
         '\t\t\tce.runOnce(ctx)\n',
     '相関エンジンが、**毎回の枝だけ**素通しに戻る（起動時の1回は包んだ'
     'まま —— 記録されるのは起動だけになります）'),
    (CP, '\t\t\ttick.Run(ctx, "cloud_poller", p.poll)\n',
         '\t\t\tp.poll(ctx)\n',
     'クラウドの取り込みが、回ったことを残さなくなる（**元の実装**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, '\tif usesTimeFunc(body, "NewTicker", "Tick") {',
        '\tif usesTimeFunc(body, "NewTickerXXX", "TickXXX") {',
     '`time.NewTicker` を1つも見つけなくなる（**0件を検査して緑**）'),
    (T, '\t\tif pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "tick" && sel.Sel.Name == "Run" {\n\t\t\tfound = true\n\t\t}',
        '\t\tif pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "tick" {\n\t\t\tfound = true\n\t\t}',
     '`tick` の別の関数も「記録している」に数える'),
    (T, 'const minUntrackedCandidates = 60', 'const minUntrackedCandidates = 0',
     '走査の床を 0 に落とす'),
    (T, '\treturn reasons[file+":"+fn] == ""', '\treturn false',
     '違反を1件も挙げなくなる'),
    (T, '\tif tracked(body) {\n\t\treturn false\n\t}', '\tif !tracked(body) {\n\t\treturn false\n\t}',
     '包んだ方を違反にする'),
    (T, '\t\t\tif !branchDoesWork(v.Body) {\n\t\t\t\treturn true\n\t\t\t}',
        '\t\t\tif branchDoesWork(v.Body) {\n\t\t\t\treturn true\n\t\t\t}',
     '仕事をする枝の方を数えない（**包んでいないワーカーが全部通ります**）'),
    (T, '\t\tif fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {\n\t\t\treturn fn\n\t\t}',
        '\t\tif fn, ok := decl.(*ast.FuncDecl); ok {\n\t\t\treturn fn\n\t\t}',
     '理由の宛先が消えても気づかなくなる'),

    # ── 委譲がほどけていないこと ─────────────────────────────────────────
    (H, '\ttick.Fail(ctx, err, msg, args...)\n', '\t_ = tick.Failing(ctx)\n',
     'scheduler の `fail` が、何も報告しなくなる'),
    (F, 'const tickSourcePath = "../tick/tick.go"', 'const tickSourcePath = "heartbeat.go"',
     '委譲した先ではなく、1行の委譲そのものを読みに行く（**「探したが'
     '無かった」を「移した」と読み違えます**）'),

    # ── 届き先の綴りが2つあること ────────────────────────────────────────
    (R, '\t\t\t\tif pkg.Name == "tick" && sel.Sel.Name == "Fail" {\n\t\t\t\t\tfound = true\n\t\t\t\t}\n',
        '',
     '`tick.Fail` を報告と認めなくなる（**scheduler の外で書かれた報告が'
     '「届いていない」に数えられます**）'),
]

RSC = 'server/internal/reports/scheduler.go'
TIF = 'server/internal/threatintel/feed.go'
CS = 'server/internal/compliance/scheduler.go'
DAC = 'server/internal/scheduler/dead_agent_cleanup.go'

CASES += [
    (RSC, '\t\t\ttick.Run(ctx, "report_scheduler", func(ctx context.Context) { s.checkAndRun(ctx, now) })\n',
          '\t\t\ts.checkAndRun(ctx, now)\n',
     'レポートの予定実行が、回ったことを残さなくなる（**`case now := <-ticker.C:`'
     'の形で、走査から外れていました**）'),
    (TIF, '\t\t\ttick.Run(ctx, "threatintel_periodic_sync", m.syncDueFeeds)\n',
          '\t\t\tm.syncDueFeeds(ctx)\n',
     '脅威フィードの定期取り込みが、回ったことを残さなくなる'),
    (T, '\tcase *ast.AssignStmt:\n\t\tif len(v.Rhs) != 1 {\n\t\t\treturn false\n\t\t}\n\t\tx = v.Rhs[0]\n',
        '',
     '`case now := <-ticker.C:` の形を見なくなる（**その形のワーカーが'
     '丸ごと走査から外れます**）'),

    # ── 合図の形（`time.NewTicker` だけではありません） ──────────────────
    (CS, '\t\t\ttick.Run(ctx, "compliance_scheduler", s.runEvaluation)\n',
         '\t\t\ts.runEvaluation(ctx)\n',
     'コンプライアンスの日次評価が、回ったことを残さなくなる（**元の実装。'
     '`time.NewTicker` を見ていなかったので、走査から丸ごと外れていました**）'),
    (CS, '\t\t\ttick.FailComponent(ctx, "compliance_scheduler", err,',
         '\t\t\tmetrics.BackgroundFailed("compliance_scheduler", err,',
     '日次評価の失敗が、部品の件数だけになる（**その回は成功として'
     '刻まれます**）'),
    (T, '\tif usesTimeFunc(body, "NewTicker", "Tick") {\n\t\treturn true\n\t}\n\tfound := false',
        '\treturn usesTimeFunc(body, "NewTicker", "Tick")\n\tfound := false',
     '`for` の中の `time.After` を周期の合図と見なくなる（**毎日 02:00 に'
     '回るワーカーが丸ごと走査から外れます**）'),
    (T, '\t\tif _, ok := m.(*ast.FuncLit); ok && skipFuncLit {\n\t\t\treturn false\n\t\t}\n',
        '',
     '`go func(){ <-time.After(d) }()` の一度きりの遅延実行まで周期の仕事に'
     '数える（**包む先の無いものを違反にします**）'),
    (T, '\t\t\tif !rangesOverTicker(v.X) || !branchDoesWork(v.Body.List) {\n\t\t\t\treturn true\n\t\t\t}\n',
        '\t\t\treturn true\n',
     '`for range ticker.C {` の形を見なくなる（**理由が一度も参照されない'
     '状態に戻ります** —— 実測でその形が4つありました）'),
    (T, '\tsel, ok := x.(*ast.SelectorExpr)\n\treturn ok && sel.Sel.Name == "C"\n}',
        '\t_, ok := x.(*ast.SelectorExpr)\n\treturn ok\n}',
     '`.C` 以外の range まで周期の枝に数える'),
    (T, '\t\tcase *ast.CallExpr:\n\t\t\tloopWorks = true\n', '\t\tcase *ast.CallExpr:\n',
     '「仕事が本体にある」形を見なくなる（**枝が空だという理由だけで'
     '黙って通ります**）'),
    (T, '\t\t\treturn false // select の中は「本体の仕事」ではありません\n', '',
     '待つだけの `select` を「本体の仕事」に数える（**待っているだけの'
     'ループが全部違反になります**）'),
    (T, '\tif !hasTicker(body) {\n\t\treturn verdictNoTicker\n\t}\n', '',
     '理由の宛先が走査の対象から外れても気づかなくなる'),
    (T, '\tif !isUntrackedWorker(body, file, fn, nil) {\n\t\treturn verdictNoViolation\n\t}\n', '',
     '**何も留めていない理由**を見なくなる（「理由があるから通っている」と'
     '「見ていないから通っている」が同じ形に戻ります）'),

    # ── `internal/scheduler` も同じ走査で見ること ────────────────────────
    (DAC, '\t\tcase <-ticker.C:\n\t\t\ttrackRun(ctx, "dead_agent_cleanup", d.cleanup)',
          '\t\tcase <-ticker.C:\n\t\t\td.cleanup(ctx)',
     '死んだエージェントの**日次の掃除**が、回ったことを残さなくなる'
     '（**5分のタイマーの枝は包んだまま —— ファイル単位の検査は'
     'これを緑で通していました**）'),
    (T, "\t\tif strings.HasPrefix(rel, \"tick/\") {\n\t\t\treturn nil\n\t\t}\n",
        "\t\tif strings.HasPrefix(rel, \"tick/\") || strings.HasPrefix(rel, \"scheduler/\") {\n\t\t\treturn nil\n\t\t}\n",
     '`internal/scheduler` をまた丸ごと対象外にする（**39 の枝が'
     '枝ごとの検査から外れます**）'),
    (T, '\t\tif id, ok := call.Fun.(*ast.Ident); ok && id.Name == trackRunName {\n\t\t\tfound = true\n\t\t\treturn true\n\t\t}\n',
        '',
     '`trackRun` を「記録している」と認めなくなる（**`internal/scheduler` の'
     '39 の枝が全部違反として並びます**）'),
    (T, '\tif id, ok := fun.(*ast.Ident); ok {\n\t\treturn id.Name == trackRunName\n\t}\n',
        '',
     '`trackRun` に渡している 26 の仕事を「回している仕事」に数えなくなる'
     '（**そこに `metrics.BackgroundFailed` を書いても何も言いません**）'),
    (T, 'const minTrackedWorkerNames = 120', 'const minTrackedWorkerNames = 0',
     '対象の床を 0 に落とす（走査そのものの床）'),
    (T, '\t\tfn := findFunc(f, trackRunName)\n', '\t\tfn := findFunc(f, "trackRunXXX")\n',
     '`trackRun` の定義を1つも見つけなくなる（**自前の `trackRun` を'
     '持てば、包まずに通せます**）'),
    (T, '\tif !callsTickRun(body) {\n\t\treturn "`tick.Run` を呼んでいません"\n\t}\n', '',
     '`trackRun` の中身が `tick.Run` を指していなくても気づかなくなる'
     '（**名前だけで 39 の枝が「包んである」になります**）'),
    (T, '\tif rel != trackRunHome {\n', '\tif false {\n',
     '別の package の自前の `trackRun` を許す'),
]

RUN_TICK = ('TestEveryPeriodicWorkerRecordsThatItRan|TestTheWorkerDetectorRecognisesTheRealThing|'
            'TestNoUntrackedTickerReasonHasGoneStale|TestFailReachesTheRun|'
            'TestFailOutsideARunIsQuietButDoesNotPanic|TestRunGivesEachRunItsOwnRecord|'
            'TestUntrackedWorkerJudgementRecognisesTheRealThing|TestStartupOnlyWrappingIsNotEnough|'
            'TestDeclaresFuncComparesTheName|TestTheWorkerScanFloorNoticesAnEmptyWalk|'
            'TestWorkThenWaitLoopsAreSeen|TestEveryUntrackedTickerReasonIsHoldingSomethingBack|'
            'TestTheInertReasonJudgementRecognisesTheRealThing|'
            'TestTheOnlyTrackRunIsTheSchedulerDelegation|TestTheSpellingDetectorRecognisesTheRealThing|'
            'TestTheTrackRunVerdictRecognisesTheRealThing|TestTheTrackedWorkerNameFloorNoticesAnEmptyWalk|'
            'TestTrackedWorkersDoNotReportPastTheRun')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         RUN_TICK + '|TestFailWritesSomewhereOtherThanTheLog|'
                    'TestTrackRunDoesNotStampSuccessAfterAFailure|'
                    'TestFunctionsThatCannotReturnAnErrorStillReportRowsErr|'
                    'TestReportsFailureTellsWarnFromReporting|'
                    'TestTheSchedulerWrappersStillPointAtTheRealThing',
         './internal/tick/', './internal/scheduler/', './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
