// Package response — ライブレスポンスのハング耐性テスト。
// 1つのコマンドが終了しない状況でも、ポーリングループが止まらないことを検証する。
package response

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sleepCmd returns a shell command that blocks for roughly the given seconds.
func sleepCmd(seconds int) string {
	if runtime.GOOS == "windows" {
		// ping emits one packet per second; n+1 pings span about n seconds.
		return fmt.Sprintf("ping -n %d 127.0.0.1 > nul", seconds+1)
	}
	return fmt.Sprintf("sleep %d", seconds)
}

// backgroundSleepCmd returns a command whose shell exits immediately while a
// child keeps running with the inherited stdout pipe still open.
func backgroundSleepCmd(seconds int) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("start /b ping -n %d 127.0.0.1", seconds+1)
	}
	return fmt.Sprintf("sleep %d &", seconds)
}

// newPollServer returns a stub server that hands out firstCmd on the first poll
// and nothing afterwards, counting how many times it was polled.
func newPollServer(t *testing.T, firstCmd string, polls *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/live-response/poll"):
			if atomic.AddInt64(polls, 1) == 1 {
				_, _ = fmt.Fprintf(w, `{"commands":[{"id":"c1","input":%q}]}`, firstCmd)
				return
			}
			_, _ = w.Write([]byte(`{"commands":[]}`))
		case strings.HasSuffix(r.URL.Path, "/live-response/output"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A command that never finishes used to block the poll loop forever, taking the
// whole session down with it — including the 401 check that ends an expired
// session. Polling must continue while it runs.
func TestLiveResponsePoller_HungCommandDoesNotStallPolling(t *testing.T) {
	var polls int64
	srv := newPollServer(t, sleepCmd(60), &polls)

	p := StartLiveResponse(t.Context(), LiveResponseStartPayload{
		SessionID:   "s1",
		Token:       "t1",
		CallbackURL: srv.URL,
	})
	defer p.Stop()

	// Polls run every second. If the hung command blocked the loop, the count
	// would stay at 1.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&polls) >= 4 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("ポーリングが停止した: %d 回しか実行されていない", atomic.LoadInt64(&polls))
}

// Cancelling the session context must tear down a command still running under
// it, rather than leaving it orphaned until its own 30s timeout.
func TestLiveResponsePoller_ExecuteHonoursSessionContext(t *testing.T) {
	p := &LiveResponsePoller{}
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer cancel()

	start := time.Now()
	out, _, _ := p.execute(ctx, sleepCmd(60))
	elapsed := time.Since(start)

	if elapsed > commandTimeout {
		t.Fatalf("セッション ctx のキャンセルで打ち切られていない: %v かかった", elapsed)
	}
	if !strings.Contains(out, "中断") {
		t.Errorf("中断した旨が出力に含まれていない: %q", out)
	}
}

// A shell that exits while a background child still holds the inherited stdout
// pipe leaves Wait blocked until that child finishes. WaitDelay must bound it.
func TestLiveResponsePoller_ExecuteReturnsWhenPipeHeldByGrandchild(t *testing.T) {
	if testing.Short() {
		t.Skip("WaitDelay の経過を待つため -short では実行しない")
	}

	p := &LiveResponsePoller{}
	start := time.Now()
	_, _, _ = p.execute(t.Context(), backgroundSleepCmd(60))
	elapsed := time.Since(start)

	// Without WaitDelay this blocks for the full 60s the grandchild runs.
	if elapsed > waitDelay+10*time.Second {
		t.Fatalf("孫プロセスがパイプを保持したまま Wait がブロックした: %v かかった", elapsed)
	}
}
