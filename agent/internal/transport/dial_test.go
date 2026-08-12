package transport

// 接続確立のブロッキング挙動。
//
// grpc.DialContext + WithBlock から grpc.NewClient へ移した際に落としては
// いけないのが「繋がるまで待ち、繋がらなければエラーを返す」こと。
// NewClient は既定で遅延接続なので、素で置き換えると常に成功が返り:
//
//   - RunWithReconnect が Connect() のエラーで回している指数バックオフが
//     一切効かなくなる (サーバが落ちていても「接続済み」として進む)
//   - 失敗が最初の RPC まで遅延し、原因の特定が難しくなる
//
// ここではその 2 点を直接固定する。

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// listeningAddr は実際に待ち受けている TCP アドレスを返す。
func listeningAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

// deadAddr は誰も待ち受けていないアドレスを返す。
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func insecureOpt() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// TestDialBlocking_ReturnsOnceReady は待ち受けているサーバに繋がること。
func TestDialBlocking_ReturnsOnceReady(t *testing.T) {
	conn, err := dialBlocking(context.Background(), listeningAddr(t), 10*time.Second, insecureOpt())
	if err != nil {
		t.Fatalf("dialBlocking: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// 戻った時点で READY になっていること。ここが Idle のままだと
	// 「接続済み」と報告しつつ実際は未接続、という以前の懸念が再現する。
	if got := conn.GetState().String(); got != "READY" {
		t.Errorf("戻り時点の状態 = %s, want READY", got)
	}
}

// TestDialBlocking_FailsWhenUnreachable は不達なサーバでエラーを返すこと。
//
// この 1 件が本移行の要。ここが nil を返すようになると、
// RunWithReconnect のバックオフが丸ごと死ぬ。
func TestDialBlocking_FailsWhenUnreachable(t *testing.T) {
	start := time.Now()
	conn, err := dialBlocking(context.Background(), deadAddr(t), 500*time.Millisecond, insecureOpt())
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.Close()
		t.Fatal("不達なサーバなのに接続成功が返った (バックオフが効かなくなる)")
	}
	if conn != nil {
		t.Error("エラー時に ClientConn が返っている (呼び出し側が閉じ忘れる)")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	// タイムアウトで打ち切られること。無期限に待つと再接続ループが止まる。
	if elapsed > 5*time.Second {
		t.Errorf("打ち切りに %v かかっている (timeout=500ms)", elapsed)
	}
}

// TestWaitForReady_RespectsContextCancellation は timeout ではなく
// ctx のキャンセルでも抜けられること。エージェント停止時に
// 接続待ちで固まらないための保証。
func TestWaitForReady_RespectsContextCancellation(t *testing.T) {
	conn, err := grpc.NewClient(deadAddr(t), insecureOpt())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// timeout=0 (ctx の期限のみ) で待つ。
	err = waitForReady(ctx, conn, 0)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("キャンセルに %v かかっている", elapsed)
	}
}

// TestWaitForReady_ReturnsImmediatelyWhenAlreadyReady は既に READY なら
// 即座に返ること。再接続のたびに無駄な待ちが入らないこと。
func TestWaitForReady_ReturnsImmediatelyWhenAlreadyReady(t *testing.T) {
	addr := listeningAddr(t)
	conn, err := dialBlocking(context.Background(), addr, 10*time.Second, insecureOpt())
	if err != nil {
		t.Fatalf("dialBlocking: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	start := time.Now()
	if err := waitForReady(context.Background(), conn, 10*time.Second); err != nil {
		t.Fatalf("2 回目の waitForReady: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("READY 済みなのに %v かかっている", elapsed)
	}
}

// TestWaitForReady_ClosedConnectionIsNotReady は閉じた接続で
// 待ち続けないこと。Shutdown を待ち状態として扱うと永久にブロックする。
func TestWaitForReady_ClosedConnectionIsNotReady(t *testing.T) {
	conn, err := grpc.NewClient(deadAddr(t), insecureOpt())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- waitForReady(context.Background(), conn, 3*time.Second) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("閉じた接続で成功が返った")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("閉じた接続で待ち続けている")
	}
}
