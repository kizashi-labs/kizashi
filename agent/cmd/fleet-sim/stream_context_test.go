package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// TestStreamContextSurvivesRunDeadline is the regression guard for the ingest-loss
// defect tracked as P2-7.
//
// The event stream must outlive the run deadline. Every host flushes its final
// partial batch in the ctx.Done() branch, and gRPC's Send returns nil as soon as a
// message is handed to the transport — not when the server has it. So if the
// transport dies with the run context, whatever is still queued is counted as sent
// and never arrives: no error, no log, just a smaller number in the events table
// than in the manifest.
//
// The mTLS branch always got this right. The plaintext branch — the one the FP soak
// actually uses, since it passes no -ca-cert — rebuilt the context from ctx when
// attaching the agent-id header and silently undid the WithoutCancel. Measured
// effect: 0〜0.27% of events lost, varying run to run with however many frames
// happened to be in flight at the instant of cancel.
func TestStreamContextSurvivesRunDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caCert string
	}{
		{"平文 (FPソークが使う経路)", ""},
		{"mTLS", "/etc/edr/ca.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			streamCtx, endStream := streamContext(ctx, tc.caCert, "agent-1")
			defer endStream()

			cancel() // the run deadline fires

			select {
			case <-streamCtx.Done():
				t.Fatal("実行期限でストリームのコンテキストが切れました。" +
					"最終バッチは送信済みとして数えられたまま届きません" +
					"（gRPC の Send は転送層に渡した時点で nil を返すため）")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// The stream context must still be cancellable on its own, or the transport would
// leak for the life of the process.
func TestStreamContextCancelFuncStillWorks(t *testing.T) {
	streamCtx, endStream := streamContext(context.Background(), "", "agent-1")
	endStream()
	select {
	case <-streamCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("endStream() でストリームのコンテキストが終了しませんでした")
	}
}

// Plaintext mode identifies the host by header rather than by client-certificate
// CN. Losing it during the fix above would route every host's events to nothing.
func TestStreamContextCarriesAgentIDHeaderInPlaintext(t *testing.T) {
	streamCtx, endStream := streamContext(context.Background(), "", "agent-42")
	defer endStream()

	md, ok := metadata.FromOutgoingContext(streamCtx)
	if !ok {
		t.Fatal("平文モードで送信メタデータがありません。" +
			"サーバはエージェントを解決できません")
	}
	if got := md.Get("x-agent-id"); len(got) != 1 || got[0] != "agent-42" {
		t.Fatalf("x-agent-id = %v, want [agent-42]", got)
	}
}

// mTLS resolves the agent from the certificate CN, so the header must not be added.
func TestStreamContextOmitsAgentIDHeaderUnderMTLS(t *testing.T) {
	streamCtx, endStream := streamContext(context.Background(), "/etc/edr/ca.pem", "agent-42")
	defer endStream()

	if md, ok := metadata.FromOutgoingContext(streamCtx); ok && len(md.Get("x-agent-id")) > 0 {
		t.Error("mTLS で x-agent-id ヘッダが付いています。" +
			"エージェントの識別は証明書 CN で行われます")
	}
}
