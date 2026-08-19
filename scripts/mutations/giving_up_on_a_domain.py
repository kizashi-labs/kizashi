#!/usr/bin/env python3
"""1つのドメインを諦めたとき、行と回の両方に出ていること。

対象:
  server/internal/scheduler/cert_expiry_checker.go
  server/internal/scheduler/giving_up_on_a_domain_test.go
  server/internal/tick/tracked_workers_test.go

`checkDomainCert` はドメインごとに早く戻ります。諦めた枝は2つのことを
しなければなりません:

    recordCertUnreachable   行に status='error' を書く（画面に出る）
    fail                    この回を「終えられなかった」に落とす（計測に出る）

実測 (2026-08-12): 3つの枝のうち **2つが `slog.Warn` + 行の更新だけ**
でした —— TLS の型アサーション失敗と、ピア証明書0件です。どちらも
`error` 値を持たない失敗で、`fail` に渡すものが無かったのが理由です。

    行  status='error'           ← 画面には出ていました
    回  last_success が動く      ← **その回は成功として刻まれていました**

名前のある error を2つ作って `fail` に渡しました。**「渡す error が
無い」は、Warn に留まってよい理由ではありませんでした。**

置いていない変異:

  `errors.New` の文字列を空にする変異は置いていますが、error 値そのものを
  `nil` にする変異は置いていません。**`fail(ctx, nil, …)` はコンパイルは
  通りますが、`TestTheTwoNamedErrorsSayWhatHappened` は変数を直接見るので
  そちらで殺せます** —— 同じことを2通りで確かめる意味がありません。

  `!verdict.alert` の枝に `fail` を足す変異は置いていません。**それは
  「アラートを上げる必要が無かった回を失敗にする」** で、この検査が
  止めたい向きの逆です（片側だけの枝として落ちるので、殺せてはいます）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

C = 'server/internal/scheduler/cert_expiry_checker.go'
T = 'server/internal/scheduler/giving_up_on_a_domain_test.go'
W = 'server/internal/tick/tracked_workers_test.go'

CASES = [
    # ── 元の実装に戻す ───────────────────────────────────────────────────
    (C, '\t\tfail(ctx, fmt.Errorf("%w (%T)", errNotATLSConn, conn),\n'
        '\t\t\t"証明書を読めませんでした", "domain", cert.domain, "port", port)\n',
        '\t\tslog.Warn("TLS接続の型アサーションに失敗しました", "domain", cert.domain)\n',
     '型アサーション失敗が `slog.Warn` に戻る（**元の実装。画面には出ますが'
     '回は成功として刻まれます**）'),
    (C, '\t\tfail(ctx, errNoPeerCertificate,\n'
        '\t\t\t"証明書を読めませんでした", "domain", cert.domain, "port", port)\n',
        '\t\tslog.Warn("ピア証明書が取得できませんでした", "domain", cert.domain)\n',
     'ピア証明書0件が `slog.Warn` に戻る（**元の実装**）'),
    (C, '\t\tfail(ctx, err, "TLS接続に失敗しました", "domain", cert.domain, "port", port)\n',
        '\t\tslog.Warn("TLS接続に失敗しました", "domain", cert.domain)\n',
     'dial 失敗も Warn に落とす'),

    # ── 逆向き: 回だけ失敗にして、行を触らない ───────────────────────────
    (C, '\t\tfail(ctx, errNoPeerCertificate,\n'
        '\t\t\t"証明書を読めませんでした", "domain", cert.domain, "port", port)\n'
        '\t\tc.recordCertUnreachable(ctx, cert)\n',
        '\t\tfail(ctx, errNoPeerCertificate,\n'
        '\t\t\t"証明書を読めませんでした", "domain", cert.domain, "port", port)\n',
     '行を触らない（**画面はそのドメインを前回の status のまま '
     '—— 多くは valid —— で出し続けます**）'),
    (C, '\t\tfail(ctx, err, "TLS接続に失敗しました", "domain", cert.domain, "port", port)\n'
        '\t\tc.recordCertUnreachable(ctx, cert)\n',
        '\t\tfail(ctx, err, "TLS接続に失敗しました", "domain", cert.domain, "port", port)\n',
     'dial 失敗で行を触らない'),

    # ── 渡す error の中身 ────────────────────────────────────────────────
    (C, 'errNoPeerCertificate = errors.New("ピア証明書が0件でした")',
        'errNoPeerCertificate = errors.New("")',
     '中身の無い error を渡す（**ログが「error=」で終わります**）'),
    (C, 'errNotATLSConn       = errors.New("TLS接続の型アサーションに失敗しました")\n'
        '\terrNoPeerCertificate = errors.New("ピア証明書が0件でした")',
        'errNotATLSConn       = errors.New("証明書を読めませんでした")\n'
        '\terrNoPeerCertificate = errNotATLSConn',
     '2つを同じ error にする（**どちらが起きたのか区別できません**）'),

    # ── 判定と走査 ───────────────────────────────────────────────────────
    (T, '\t\tcase b.marksRow && !b.failsRun:', '\t\tcase false:',
     '「行だけ」の向きを見なくする（**元の欠陥がそのまま通ります**）'),
    (T, '\t\tcase b.failsRun && !b.marksRow:', '\t\tcase false:',
     '「回だけ」の向きを見なくする'),
    (T, 'func givingUpProblems(branches []domainBranch) []string {\n\tvar out []string',
        'func givingUpProblems(branches []domainBranch) []string {\n\treturn nil\n\tvar out []string', # noqa: E501
     '判定が何も返さなくなる'),
    (T, 'func (b domainBranch) gaveUp() bool { return b.marksRow || b.failsRun }',
        'func (b domainBranch) gaveUp() bool { return b.marksRow && b.failsRun }',
     '片側だけの枝を「諦めた枝ではない」に数える（**件数が合わなくなります**）'),
    (T, '\t\t\t\t\tif f.Name == "fail" {\n\t\t\t\t\t\tfails = true\n\t\t\t\t\t}',
        '\t\t\t\t\tif f.Name != "" {\n\t\t\t\t\t\tfails = true\n\t\t\t\t\t}',
     'どんな関数呼び出しでも「回を失敗にした」と読む'),
    (T, '\t\t\t\t\tif f.Sel.Name == "recordCertUnreachable" {\n\t\t\t\t\t\tmarks = true\n\t\t\t\t\t}',
        '\t\t\t\t\tif f.Sel.Name != "" {\n\t\t\t\t\t\tmarks = true\n\t\t\t\t\t}',
     'どんなメソッド呼び出しでも「行を書いた」と読む'),
    (T, '\t\tif !returns {\n\t\t\treturn true\n\t\t}', '\t\tif returns {\n\t\t\treturn true\n\t\t}',
     '戻らない枝の方を数える'),
    (T, 'const (\n\tcertGiveUpBranches   = 3\n\tcertEarlyReturnTotal = 4\n)',
        'const (\n\tcertGiveUpBranches   = 0\n\tcertEarlyReturnTotal = 0\n)',
     '件数を 0 に落とす（**走査が何も見つけなくても緑になります**）'),

    # ── Warn の一覧が古くならないこと ────────────────────────────────────
    (W, 'const reachableSlogWarnSites = 22', 'const reachableSlogWarnSites = 23',
     '`fail` に移した2つを、まだ Warn だったことにする'),
]

RUN = ('TestGivingUpOnADomainShowsInBothPlaces|TestTheGivingUpRuleActuallyFires|'
       'TestTheDomainBranchScannerReadsTheRealFunction|'
       'TestTheTwoNamedErrorsSayWhatHappened|TestTheTwoRecognisersLookAtTheName')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/scheduler/'],
    cwd='server',
)

# Warn の一覧は `internal/tick` の検査が持っています。
TICK_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestTrackedWorkersDoNotDowngradeToWarn', './internal/tick/'],
    cwd='server',
)

TICK = {W}
SCHED_CASES = [c for c in CASES if c[0] not in TICK]
TICK_CASES = [c for c in CASES if c[0] in TICK]

if __name__ == '__main__':
    rc = HARNESS.run(SCHED_CASES)
    rc |= TICK_HARNESS.run(TICK_CASES)
    sys.exit(rc)
