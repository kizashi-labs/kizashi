#!/usr/bin/env python3
"""報告する相手がいない失敗も、部品ごとの件数には残ること。

対象:
  server/internal/store/users.go
  server/internal/webhooks/dispatcher.go
  server/internal/store/live_response.go
  server/internal/api/handlers/bas_handler.go
  server/internal/tick/background_failed_test.go
  server/internal/tick/scan_honesty_test.go
  server/internal/api/handlers/discarded_write_test.go

捨てている書き込みの分類 `no-caller`（goroutine の中など、error を渡す
相手がいない）10 か所を `metrics.BackgroundFailed` に通しました。
**「回」が無いので `tick.Fail` は使えません** —— 部品ごとの件数が
唯一の跡です。

直す前に黙っていたもの:

    users.go        **総当たりに対するロックアウトの計数**（落ちると
                    ロックアウトが黙って効かなくなります）／成功時の
                    リセット（失敗回数が積み上がったまま残ります）
    dispatcher.go   webhook の配送履歴と成功/失敗の計数、最終発火
    engine.go       抑制ルールのヒット数（**「効いていないルール」を
                    見つけるための数**）
    live_response   期限切れセッションの一括処理
    bas_handler     201 を返したあとの実行完了（**pending のまま残ります**）

## 見つかったもの

`ExpireOldSessions` を「報告する相手がいない」に分類しかけて呼び出し側を
見たら、**`cmd/api/main.go` の5分の ticker** でした ——「回」が無いのでは
なく、誰も作っていません。

実測 (2026-08-12): `cmd/` の周期の枝は 8、`tick.Run` は 0。**この
campaign の走査は `server/internal` しか見ていませんでした。**
6つ目の分類 `未追跡` を足して記録し、**8つとも `tick.Run` で包んで 0 に
しました。** `ExpireOldSessions` は回を持ったので `tick.Fail` に移り、
`未追跡` は空になりました —— 空であることが規則です。

置いていない変異:

  `metrics.BackgroundFailed` の中身への変異は置いていません。
  **`server_background.py` が見ています**（ログだけ・件数だけ、など）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

US = 'server/internal/store/users.go'
WD = 'server/internal/webhooks/dispatcher.go'
LR = 'server/internal/store/live_response.go'
BH = 'server/internal/api/handlers/bas_handler.go'
BF = 'server/internal/tick/background_failed_test.go'
SH = 'server/internal/tick/scan_honesty_test.go'
DW = 'server/internal/api/handlers/discarded_write_test.go'

CASES = [
    # ── 元の実装に戻す ───────────────────────────────────────────────────
    (US, '\t\t\tvar err error\n'
         '\t\t\tif newCount >= maxFailedLogins {\n'
         '\t\t\t\tlockUntil := time.Now().Add(loginLockDuration)\n'
         '\t\t\t\t_, err = s.pool.Exec(context.Background(),\n'
         '\t\t\t\t\t`UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,\n'
         '\t\t\t\t\tnewCount, lockUntil, u.ID)\n'
         '\t\t\t} else {\n'
         '\t\t\t\t_, err = s.pool.Exec(context.Background(),\n'
         '\t\t\t\t\t`UPDATE users SET failed_login_count = $1 WHERE id = $2`,\n'
         '\t\t\t\t\tnewCount, u.ID)\n\t\t\t}\n'
         '\t\t\tif err != nil {\n'
         '\t\t\t\tmetrics.BackgroundFailed("login_lockout", err,\n'
         '\t\t\t\t\t"ログイン失敗回数を記録できませんでした。ロックアウトが効きません",\n'
         '\t\t\t\t\t"user_id", u.ID, "count", newCount)\n\t\t\t}\n',
         '\t\t\tif newCount >= maxFailedLogins {\n'
         '\t\t\t\tlockUntil := time.Now().Add(loginLockDuration)\n'
         '\t\t\t\t_, _ = s.pool.Exec(context.Background(),\n'
         '\t\t\t\t\t`UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,\n'
         '\t\t\t\t\tnewCount, lockUntil, u.ID)\n'
         '\t\t\t} else {\n'
         '\t\t\t\t_, _ = s.pool.Exec(context.Background(),\n'
         '\t\t\t\t\t`UPDATE users SET failed_login_count = $1 WHERE id = $2`,\n'
         '\t\t\t\t\tnewCount, u.ID)\n\t\t\t}\n'
         '\t\t\t_ = metrics.BackgroundFailed\n',
     '**ロックアウトの計数**が黙って捨てられる（元の実装。総当たりに'
     '対する防御が、効いていないことに気づけません）'),

    (BH, """\tif _, err := h.pool.Exec(ctx,
\t\t`UPDATE bas_runs SET status='completed', started_at=$2, completed_at=$2,
\t\t  detection_rate=0, prevention_rate=0,
\t\t  steps_total=0, steps_detected=0, steps_prevented=0
\t\t WHERE id=$1`,
\t\trunID, now); err != nil {
\t\tmetrics.BackgroundFailed("bas_run", err,
\t\t\t"BAS 実行の完了を記録できませんでした。この実行は pending のまま残ります",
\t\t\t"run_id", runID)
\t}""",
         """\t_, _ = h.pool.Exec(ctx,
\t\t`UPDATE bas_runs SET status='completed', started_at=$2, completed_at=$2,
\t\t  detection_rate=0, prevention_rate=0,
\t\t  steps_total=0, steps_detected=0, steps_prevented=0
\t\t WHERE id=$1`,
\t\trunID, now)
\t_ = metrics.BackgroundFailed""",
     'BAS の実行完了が黙って捨てられる（**元の実装。pending のまま'
     '残ります**）'),
    (LR, """\tif _, err := s.pool.Exec(ctx, `
\t\tUPDATE live_response_sessions
\t\tSET status = 'expired', closed_at = NOW()
\t\tWHERE status = 'active'
\t\t  AND last_activity < NOW() - INTERVAL '30 minutes'
\t`); err != nil {
\t\ttick.Fail(ctx, err,
\t\t\t"期限切れのライブレスポンスセッションを閉じられませんでした")
\t}""",
         """\t_, _ = s.pool.Exec(ctx, `
\t\tUPDATE live_response_sessions
\t\tSET status = 'expired', closed_at = NOW()
\t\tWHERE status = 'active'
\t\t  AND last_activity < NOW() - INTERVAL '30 minutes'
\t`)
\t_ = tick.Fail""",
     '期限切れセッションの処理が黙る（**元の実装。閉じたはずの'
     'セッションが active のまま残ります**）'),

    # ── 分類 ─────────────────────────────────────────────────────────────
    (BF, '\tcase catStartup, catPerReq, catPerEvent, catReturns, catMechanism, catUntracked:',
         '\tcase catStartup, catPerReq, catPerEvent, catReturns, catMechanism, catUntracked, "":',
     '空の分類を通す（**分類しなくても緑になります**）'),
    (BF, '\tbackgroundFailedCount = 83', '\tbackgroundFailedCount = 100',
     '件数を留めなくなる'),
    (BF, '\tcatUntracked: 0,', '\tcatUntracked: 5,',
     '`未追跡` の 0 を留めなくなる（**包んでいない周期処理があっても'
     '通ります**）'),

    # ── `cmd/` の上限 ────────────────────────────────────────────────────
    (SH, 'const untrackedCmdTickers = 0', 'const untrackedCmdTickers = 100',
     '`cmd/` の未追跡の上限を留めなくなる'),
    (SH, 'const cmdRoot = "../../cmd"', 'const cmdRoot = "../../internal"',
     '`cmd/` ではなく `internal/` を見る（**8つが数から消えます**）'),
    (SH, '\treturn strings.Count(body, ".C:"), strings.Count(body, "tick.Run(")',
         '\treturn strings.Count(body, ".C:"), strings.Count(body, ".C:")',
     '包んだ数の数え方を壊す（**全部が追跡済みに見えます**）'),
    (SH, '\treturn strings.Count(body, ".C:"), strings.Count(body, "tick.Run(")',
         '\treturn strings.Count(body, "zzz"), strings.Count(body, "tick.Run(")',
     '周期の枝を数えなくなる（**走査の床が落とします**）'),
    (SH, '\t\tif d := c.branches - c.runs; d > 0 {',
         '\t\tif d := c.branches - c.runs; d > 100 {',
     '未追跡の枝を数えなくなる'),
    (SH, '\tn := 0\n\tfor _, c := range counts {', '\tn := 0\n\treturn n\n\tfor _, c := range counts {',
     '判定が常に 0 を返す'),
    (SH, '\t\tif i := strings.Index(line, "//"); i >= 0 {\n\t\t\tline = line[:i]\n\t\t}',
         '\t\tif i := strings.Index(line, "//"); i < 0 {\n\t\t\tline = line[:0]\n\t\t}',
     'コメントの落とし方を壊す'),

    # ── 捨てている書き込みの件数 ─────────────────────────────────────────
    (DW, 'const discardedWritesTotal = 0', 'const discardedWritesTotal = 26',
     '直した 10 か所を、まだ捨てていることにする'),
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestEveryBackgroundFailedSiteIsClassified|TestPeriodicWorkInCmdIsNotGrowingUntracked|'
         'TestTheCmdTickerCountIgnoresComments|TestTheClassificationJudgementsRecogniseTheRealThing|'
         'TestTheSmallCategoriesKeepTheirCount',
         './internal/tick/'],
    cwd='server',
)

# **走らせる package が足りないと、変異は「殺されない」ではなく
# 「試されない」で通り抜けます。** そして出力は SURVIVED —— 網が無いのと
# 見分けが付きません。
#
# `./internal/detection/` を足したのは、抑制ヒット数の書き込みが上流の
# 一本化で `internal/suppression` から `internal/detection` へ移ったからです
# （#74）。網（TestAFailedSuppressionHitCountIsReported）はずっとあったのに、
# **ここが handlers しか走らせていなかったので当たっていませんでした。**
WRITE_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified|'
         'TestEveryWriteCategoryIsOneOfTheFour|'
         'TestAFailedSuppressionHitCountIsReported|TestNoSuppressionCounterIsNotAFailure',
         './internal/api/handlers/', './internal/detection/'],
    cwd='server',
)

TICK_CASES = [c for c in CASES if c[0] in (BF, SH)]
SRC_CASES = [c for c in CASES if c[0] not in (BF, SH, DW)]
WRITE_CASES = [c for c in CASES if c[0] == DW]

if __name__ == '__main__':
    rc = HARNESS.run(TICK_CASES)
    rc |= WRITE_HARNESS.run(SRC_CASES + WRITE_CASES)
    sys.exit(rc)
