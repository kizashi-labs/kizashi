package transport

// gRPC 接続の確立。
//
// 以前は grpc.DialContext + WithBlock + WithTimeout を使っていた。3 つとも
// deprecated (SA1019) で、後継の grpc.NewClient は**接続を待たない**。
// 素直に置き換えると Connect() が「接続できていなくても成功」を返すようになり、
// 呼び出し側の前提が崩れる:
//
//   - RunWithReconnect は Connect() のエラーで指数バックオフを回す。常に成功が
//     返ると、サーバが落ちていてもバックオフに入らず、失敗は最初の RPC まで
//     遅延する
//   - Enroll はサーバ不達なら早く失敗してほしい。登録できていないのに
//     「登録処理を続行」してしまう
//
// そこで NewClient で作った後に明示的に接続を開始し、READY になるまで待つ
// ヘルパを置く。従来の WithBlock + WithTimeout と同じ「接続できるまで待ち、
// 待ちきれなければエラー」を保つ。

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// errConnShutdown は接続が確立前に閉じられたことを表す。
var errConnShutdown = errors.New("grpc: connection shut down before becoming ready")

// waitForReady は conn が READY になるまで待つ。
//
// timeout が正なら ctx にその期限を被せる (0 以下なら ctx の期限のみ)。
// 待ちきれなければ ctx のエラーを返す — 従来 WithTimeout が
// DeadlineExceeded を返していたのと同じ形。
//
// NewClient で作った ClientConn は Idle 状態から始まる。Connect() で接続を
// 促し、状態が変わるたびに評価し直す。TransientFailure の後は gRPC 側が
// バックオフして自動的に再試行するため、こちらは待つだけでよい。ただし
// Idle に戻ることもあるので、その都度 Connect() を呼び直す。
func waitForReady(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for {
		switch s := conn.GetState(); s {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errConnShutdown
		case connectivity.Idle:
			conn.Connect()
			// Connect() 直後に READY になっている可能性があるため、
			// WaitForStateChange に入る前にもう一周させる。
			if conn.GetState() == connectivity.Ready {
				return nil
			}
			if !conn.WaitForStateChange(ctx, connectivity.Idle) {
				return ctx.Err()
			}
		default:
			// Connecting / TransientFailure — 状態が動くのを待つ。
			if !conn.WaitForStateChange(ctx, s) {
				return ctx.Err()
			}
		}
	}
}

// dialBlocking は NewClient + waitForReady をまとめたもの。
// 接続できなかった場合は ClientConn を閉じてからエラーを返すので、
// 呼び出し側が後始末を気にしなくてよい。
func dialBlocking(ctx context.Context, addr string, timeout time.Duration, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	if err := waitForReady(ctx, conn, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
