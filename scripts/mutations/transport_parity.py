#!/usr/bin/env python3
"""ハートビートの応答を、2つの経路が同じだけ運ぶこと。

対象:
  agent/internal/heartbeat/transport_parity_test.go
  agent/internal/heartbeat/heartbeat.go
  agent/internal/heartbeat/http_sender.go
  agent/internal/transport/grpc_client.go

`FallbackSender` は gRPC を先に試し、失敗したら HTTP に落ちます。
**同じ応答型が、経路によって別のものを運びます** —— それを突き合わせる
ものが、どこにもありませんでした。

実測 (2026-08-12):

    フィールド              サーバ gRPC  端末 gRPC  サーバ HTTP  端末 HTTP
    ConfigUpdateAvailable   ✗            ✓          ✗            ✗
    LatestConfigVersion     ✗            ✓          ✗            ✗
    PendingCommandCount     ✗            ✓          ✗            ✗
    ShouldIsolate           ✓            ✓          ✓            ✓
    UninstallGuard          ✓            ✓          ✓            ✓
    ShouldUnisolate         ✓            ✓          ✓            ✓

**上の3つは、どのサーバも設定していませんでした。** 埋める先もあり
ません —— コマンドは NATS から EventStream 経由で押し出す設計で
数えるキューが無く、設定は `GetConfig` が版 1 を固定で返すだけです。
**この系が採っていない方式（端末が取りに行く形）の名残**だったので、
端末側の受け皿ごと消しました。proto は触っていません。

いまは 2 フィールドで、**理由つきの例外は0件**です。**空であることが
規則です** —— 片方にしか無いフィールドは、`FallbackSender` が gRPC を
先に試す以上、「届く条件」と「届かない条件」を作ります。

置いていない変異:

  3つをサーバ側に実装する方向の変異は置いていません。**それは欠陥の
  修正で、変異ではありません。** 実装するなら、表に足して両方の経路が
  運ぶことを確かめてください。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'agent/internal/heartbeat/transport_parity_test.go'
HS = 'agent/internal/heartbeat/http_sender.go'
GC = 'agent/internal/transport/grpc_client.go'

CASES = [
    # ── 片側だけになる ───────────────────────────────────────────────────
    (HS, '\t\tShouldIsolate:   hbResp.ShouldIsolate,\n', '',
     'HTTP の経路が `ShouldIsolate` を運ばなくなる（**gRPC が落ちている'
     'ときに届きません**）'),
    (GC, '\t\tShouldIsolate:   headerSaysIsolate(respHeader),\n', '',
     'gRPC の経路が `ShouldIsolate` を運ばなくなる（**通常時はこちらが'
     '使われます**）'),
    (GC, '\t\tShouldUnisolate: headerSaysUnisolate(respHeader),\n', '',
     'gRPC の経路が `ShouldUnisolate` を運ばなくなる（**元の実装**）'),

    # ── 判定 ─────────────────────────────────────────────────────────────
    (T, '\t\tif !r.httpRead || !r.grpcRead || !r.httpWrite || !r.grpcWrite {',
        '\t\tif false {',
     '片側だけを見なくなる'),
    (T, '\t\tif _, excused := exceptions[r.field]; excused {\n\t\t\tcontinue\n\t\t}',
        '\t\tif _, excused := exceptions[r.field]; !excused {\n\t\t\tcontinue\n\t\t}',
     '理由のある側だけを違反にする'),
    (T, 'const heartbeatResponseFields = 3', 'const heartbeatResponseFields = 100',
     'フィールド数を留めなくなる'),
    (T, 'var parityExceptions = map[string]string{}',
        'var parityExceptions = map[string]string{"ShouldIsolate": "あとで見ます"}',
     '**理由つきの例外を1つ入れる**（片方の経路にしか無いフィールドが'
     '通ります）'),
    (T, '\t\t\tif i > 0 {\n\t\t\t\tb.WriteByte(\'_\')\n\t\t\t}',
        '\t\t\tif i < 0 {\n\t\t\t\tb.WriteByte(\'_\')\n\t\t\t}',
     'JSON の鍵の作り方を壊す（**どのフィールドもサーバ HTTP に'
     '「無い」ことになります**）'),
    (T, '\t\tif i := strings.Index(line, "//"); i >= 0 {\n\t\t\tline = line[:i]\n\t\t}',
        '\t\tif i := strings.Index(line, "//"); i < 0 {\n\t\t\tline = line[:i+1]\n\t\t}',
     'コメントを落とさなくなる（**説明の中の名前を「運んでいる」と'
     '読み違えます**）'),
    (T, '\tfor f := range exceptions {\n\t\tif !seen[f] {',
        '\tfor f := range exceptions {\n\t\tif seen[f] {',
     '消えたフィールドの理由を挙げなくなる'),
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestBothTransportsCarryTheSameHeartbeatResponse|TestTheParityRuleActuallyFires|'
         'TestTheParityScanReadsRealFiles',
         './internal/heartbeat/'],
    cwd='agent',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
