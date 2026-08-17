#!/usr/bin/env python3
"""隔離状態の巻き戻しが、両方向にあること。

対象:
  server/internal/api/handlers/agents_handler.go
  server/internal/ingestion/handler.go
  server/internal/api/handlers/command_delivery_test.go
  agent/internal/heartbeat/heartbeat.go
  agent/internal/heartbeat/http_sender.go
  agent/internal/transport/grpc_client.go
  agent/cmd/agent/main.go

**巻き戻しは片側しかありませんでした。** サーバは端末が「まだ隔離中」と
言い DB が解除済みのとき `should_unisolate` を返します。逆はありません
——隔離コマンドが端末に届かなかったとき、**DB も画面も「隔離済み」、
端末はネットワークに繋がったまま、それを直すものが何もありません**でした。

もう1つ、届き方の問題がありました。実測 (2026-08-12): gRPC の
ハートビート応答は `ShouldUnisolate` を**運んでいません**（HTTP の
sender だけが読んでいます）。`FallbackSender` は gRPC を先に試すので、
**gRPC が生きている通常時、解除の巻き戻しも端末に届きません** ——
直る条件（gRPC が落ちている）と直らない条件（gRPC は生きていて指示
だけが落ちた）が入れ替わっていました。

両方向・両経路にしました:

    サーバ HTTP    `should_isolate` を追加
    サーバ gRPC    応答メタデータ `x-edr-should-isolate` /
                   `x-edr-should-unisolate`（`x-edr-keepalive` と同じ形。
                   proto の再生成は要りません）
    端末           `HeartbeatResponse.ShouldIsolate` と `SetIsolateFunc`

**それでも隔離は 5xx で答えます。** 直るまで最大 30 秒（ハートビート
間隔）あり、その間、対応する人は「封じ込め済み」と思って次に進みます。

置いていない変異:

  端末側の `isolation.Isolate(…)` に渡す許可 IP への変異は置いて
  いません。**EDR サーバへの経路を残さないと次のハートビートも届かず、
  解除の指示も受け取れません**が、それを殺せる検査は端末の隔離実装
  （iptables / WFP / pf）が要ります。`response.ServerHost` を共有に
  したので、写しがずれることはありません。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

AH = 'server/internal/api/handlers/agents_handler.go'
IH = 'server/internal/ingestion/handler.go'
CD = 'server/internal/api/handlers/command_delivery_test.go'
HB = 'agent/internal/heartbeat/heartbeat.go'
HS = 'agent/internal/heartbeat/http_sender.go'
GC = 'agent/internal/transport/grpc_client.go'

SERVER_CASES = [
    (AH, '\tcase dbIsolated && !reportedIsolated:\n\t\treturn true, false\n',
         '',
     '**隔離の巻き戻しが無くなる**（元の実装。指示が届かなかった端末は'
     '二度と隔離されません）'),
    (AH, '\tcase !dbIsolated && reportedIsolated:\n\t\treturn false, true\n',
         '',
     '解除の巻き戻しが無くなる'),
    (AH, '\tcase dbIsolated && !reportedIsolated:\n\t\treturn true, false',
         '\tcase !dbIsolated && !reportedIsolated:\n\t\treturn true, false',
     '**隔離されていない端末に隔離を指示する**（平常時の端末が'
     'ネットワークから切れます）'),
    (IH, '\tcase dbIsolated && !reportedIsolated:\n\t\treturn []string{"x-edr-should-isolate"}\n',
         '',
     'gRPC の経路から隔離の巻き戻しが消える（**通常時はこちらが使われます**）'),
    (IH, '\tcase !dbIsolated && reportedIsolated:\n\t\treturn []string{"x-edr-should-unisolate"}\n',
         '',
     'gRPC の経路から解除の巻き戻しが消える（**元の実装。gRPC が生きて'
     'いる通常時、解除の指示は端末に届きませんでした**）'),
    (CD, '\t"IsolateEndpoint":   true,\n', '',
     '隔離に巻き戻しが無いことにする'),
]

AGENT_CASES = [
    (HB, '''	if resp.ShouldIsolate && r.isolate != nil {
		slog.Warn("サーバーからの隔離指示を受信しました（ハートビート経由）")
		if err := r.isolate("heartbeat reconcile"); err != nil {
			slog.Error("ハートビート経由の隔離に失敗しました", "error", err)
		} else {
			slog.Warn("ハートビート経由の隔離が完了しました")
		}
	}
''','''''',
     '端末が隔離の指示を無視する（**サーバは「隔離済み」、端末は'
     '繋がったまま**）'),
    (HB, '\tif resp.ShouldIsolate && r.isolate != nil {',
         '\tif !resp.ShouldIsolate && r.isolate != nil {',
     '**指示されていないのに隔離する**（平常時の端末が切れます）'),
    (GC, '\treturn len(md.Get("x-edr-should-isolate")) > 0',
         '\treturn false',
     'gRPC の応答ヘッダから隔離の指示を読まなくなる'),
    (GC, '\treturn len(md.Get("x-edr-should-unisolate")) > 0',
         '\treturn false',
     'gRPC の応答ヘッダから解除の指示を読まなくなる（**元の実装**）'),
]

CASES = SERVER_CASES + AGENT_CASES

SERVER_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestACommandThatDidNotReachTheEndpointIsNotAnsweredWithSuccess|'
         'TestTheCommandDeliveryRuleActuallyFires|TestTheHeartbeatReconcilesIsolationBothWays|'
         'TestReconcileIsolationGoesBothWays',
         './internal/api/handlers/'],
    cwd='server',
)

ING_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', 'TestIsolationHeadersGoBothWays',
         './internal/ingestion/'],
    cwd='server',
)

AGENT_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', './internal/heartbeat/', './internal/transport/'],
    cwd='agent',
)

if __name__ == '__main__':
    rc = SERVER_HARNESS.run([c for c in SERVER_CASES if c[0] != IH])
    rc |= ING_HARNESS.run([c for c in SERVER_CASES if c[0] == IH])
    rc |= AGENT_HARNESS.run(AGENT_CASES)
    sys.exit(rc)
