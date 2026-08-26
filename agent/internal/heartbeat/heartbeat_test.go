package heartbeat

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// ─── Mock sender ─────────────────────────────────────────────

type mockSender struct {
	calls   atomic.Int64
	lastReq *HeartbeatRequest
	resp    *HeartbeatResponse
	err     error
}

func (m *mockSender) SendHeartbeat(_ context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	m.calls.Add(1)
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	if m.resp != nil {
		return m.resp, nil
	}
	return &HeartbeatResponse{}, nil
}

// ─── Helpers ─────────────────────────────────────────────────

// eventually は cond が true になるまで timeout までポーリングする。
// 「一定時間スリープしてから1回だけ確認する」形の時間依存を避けるため。
func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// resetPublicIPCache はパッケージレベルのパブリックIPキャッシュを初期状態に戻す。
func resetPublicIPCache() {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	publicIPCached = ""
	publicIPExpiry = time.Time{}
}

// ─── NewReporter ─────────────────────────────────────────────

func TestNewReporter_StoresFields(t *testing.T) {
	tests := []struct {
		name     string
		agentID  string
		version  string
		interval time.Duration
	}{
		{"basic", "agent-001", "1.0.0", 30 * time.Second},
		{"empty id", "", "0.1", time.Minute},
		{"short interval", "agent-xyz", "2.0", time.Millisecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &mockSender{}
			r := NewReporter(tc.agentID, tc.version, func() string { return "" }, "", sender, tc.interval, nil, nil, nil)
			if r == nil {
				t.Fatal("NewReporter returned nil")
			}
			if r.agentID != tc.agentID {
				t.Errorf("agentID = %q, want %q", r.agentID, tc.agentID)
			}
			if r.version != tc.version {
				t.Errorf("version = %q, want %q", r.version, tc.version)
			}
			if r.interval != tc.interval {
				t.Errorf("interval = %v, want %v", r.interval, tc.interval)
			}
		})
	}
}

// ─── sendOnce ─────────────────────────────────────────────────

func TestSendOnce_CallsSender(t *testing.T) {
	sender := &mockSender{}
	r := NewReporter("agent-001", "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)
	r.sendOnce(context.Background())

	if sender.calls.Load() != 1 {
		t.Errorf("sender called %d times, want 1", sender.calls.Load())
	}
}

func TestSendOnce_PopulatesAgentID(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
	}{
		{"known id", "agent-abc"},
		{"numeric id", "12345"},
		{"empty id", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &mockSender{}
			r := NewReporter(tc.agentID, "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)
			r.sendOnce(context.Background())

			if sender.lastReq == nil {
				t.Fatal("sender never received a request")
			}
			if sender.lastReq.AgentID != tc.agentID {
				t.Errorf("AgentID = %q, want %q", sender.lastReq.AgentID, tc.agentID)
			}
		})
	}
}

func TestSendOnce_PopulatesVersion(t *testing.T) {
	tests := []struct {
		version string
	}{
		{"1.0.0"},
		{"2.3.4-rc1"},
		{""},
	}

	for _, tc := range tests {
		t.Run("version "+tc.version, func(t *testing.T) {
			sender := &mockSender{}
			r := NewReporter("a1", tc.version, func() string { return "" }, "", sender, time.Hour, nil, nil, nil)
			r.sendOnce(context.Background())

			if sender.lastReq.AgentVersion != tc.version {
				t.Errorf("AgentVersion = %q, want %q", sender.lastReq.AgentVersion, tc.version)
			}
		})
	}
}

func TestSendOnce_StatusOnline(t *testing.T) {
	sender := &mockSender{}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, func() bool { return false }, nil, nil)
	r.sendOnce(context.Background())

	if sender.lastReq.Status != "online" {
		t.Errorf("Status = %q, want %q", sender.lastReq.Status, "online")
	}
}

func TestSendOnce_StatusIsolated(t *testing.T) {
	sender := &mockSender{}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, func() bool { return true }, nil, nil)
	r.sendOnce(context.Background())

	if sender.lastReq.Status != "isolated" {
		t.Errorf("Status = %q, want %q", sender.lastReq.Status, "isolated")
	}
}

func TestSendOnce_StatusNilIsolated(t *testing.T) {
	// nil isolated func should default to "online"
	sender := &mockSender{}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)
	r.sendOnce(context.Background())

	if sender.lastReq.Status != "online" {
		t.Errorf("Status = %q, want %q", sender.lastReq.Status, "online")
	}
}

func TestSendOnce_BufferedCallback(t *testing.T) {
	tests := []struct {
		name       string
		bufferedFn func() int
		wantCount  int
	}{
		{"nil buffered", nil, 0},
		{"returns 42", func() int { return 42 }, 42},
		{"returns zero", func() int { return 0 }, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &mockSender{}
			r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, nil, tc.bufferedFn, nil)
			r.sendOnce(context.Background())

			if sender.lastReq.EventsBuffered != tc.wantCount {
				t.Errorf("EventsBuffered = %d, want %d", sender.lastReq.EventsBuffered, tc.wantCount)
			}
		})
	}
}

func TestSendOnce_SenderError_DoesNotPanic(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"connection refused", errors.New("connection refused")},
		{"timeout", context.DeadlineExceeded},
		{"generic error", errors.New("something went wrong")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &mockSender{err: tc.err}
			r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)
			// Must not panic.
			r.sendOnce(context.Background())
		})
	}
}

// ─── Run (start/stop via context) ─────────────────────────────

func TestRun_SendsImmediately(t *testing.T) {
	sender := &mockSender{}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// 固定スリープではなくポーリングで待つ。sendOnce は送信前に getLocalIPs() →
	// クラウドメタデータのプローブを行うため、初回だけ数百ミリ秒かかる環境がある
	// （非クラウドWindowsではlink-localへの接続が即座に失敗しない）。
	if !eventually(5*time.Second, func() bool { return sender.calls.Load() >= 1 }) {
		t.Error("expected at least one heartbeat call after Run started")
	}

	cancel()
	<-done
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	sender := &mockSender{}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// Cancel after a short wait.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Correct: Run returned.
	case <-time.After(500 * time.Millisecond):
		t.Error("Run did not stop after context cancellation")
	}
}

// ─── ShouldUnisolate ─────────────────────────────────────────

func TestSendOnce_ShouldUnisolate_CallsUnisolate(t *testing.T) {
	called := false
	sender := &mockSender{resp: &HeartbeatResponse{ShouldUnisolate: true}}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, func() bool { return true }, nil, func() error {
		called = true
		return nil
	})
	r.sendOnce(context.Background())
	if !called {
		t.Error("unisolate func should have been called when ShouldUnisolate=true")
	}
}

func TestSendOnce_ShouldUnisolate_FalseDoesNotCall(t *testing.T) {
	called := false
	sender := &mockSender{resp: &HeartbeatResponse{ShouldUnisolate: false}}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, func() bool { return true }, nil, func() error {
		called = true
		return nil
	})
	r.sendOnce(context.Background())
	if called {
		t.Error("unisolate func must NOT be called when ShouldUnisolate=false")
	}
}

func TestSendOnce_ShouldUnisolate_NilUnisolateNosPanic(t *testing.T) {
	sender := &mockSender{resp: &HeartbeatResponse{ShouldUnisolate: true}}
	r := NewReporter("a1", "1.0", func() string { return "" }, "", sender, time.Hour, func() bool { return true }, nil, nil)
	// Must not panic even with nil unisolate callback.
	r.sendOnce(context.Background())
}

// ─── fetchPublicIP（キャッシュ / 所要時間の上限） ──────────────

func TestFetchPublicIP_BoundedDuration(t *testing.T) {
	resetPublicIPCache()
	t.Cleanup(resetPublicIPCache)

	start := time.Now()
	fetchPublicIP()
	elapsed := time.Since(start)

	// 4エンドポイントを順に試すため上限は 4*metadataTimeout。
	// CI/実機の負荷を考慮して倍の余裕を持たせる。
	limit := 8 * metadataTimeout
	if elapsed > limit {
		t.Errorf("fetchPublicIP に %v かかった（上限 %v）", elapsed, limit)
	}
}

func TestFetchPublicIP_CachesResult(t *testing.T) {
	resetPublicIPCache()
	t.Cleanup(resetPublicIPCache)

	first := fetchPublicIP()

	start := time.Now()
	second := fetchPublicIP()
	elapsed := time.Since(start)

	if second != first {
		t.Errorf("2回目の結果 = %q, 1回目 = %q（一致すべき）", second, first)
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("2回目の fetchPublicIP に %v かかった: キャッシュが効いていない", elapsed)
	}
}

func TestFetchPublicIP_RefetchesAfterExpiry(t *testing.T) {
	resetPublicIPCache()
	t.Cleanup(resetPublicIPCache)

	publicIPMu.Lock()
	publicIPCached = "203.0.113.7"
	publicIPExpiry = time.Now().Add(time.Hour)
	publicIPMu.Unlock()

	if got := fetchPublicIP(); got != "203.0.113.7" {
		t.Fatalf("有効期間内のキャッシュが返らず %q を返した", got)
	}

	// 期限切れにすると再プローブして期限を張り直す。
	publicIPMu.Lock()
	publicIPExpiry = time.Now().Add(-time.Second)
	publicIPMu.Unlock()

	fetchPublicIP()

	publicIPMu.Lock()
	expiry := publicIPExpiry
	publicIPMu.Unlock()
	if !expiry.After(time.Now()) {
		t.Error("期限切れ後の呼び出しでキャッシュ期限が更新されていない")
	}
}

// ─── HeartbeatRequest / HeartbeatResponse types ───────────────

func TestHeartbeatRequest_ZeroValue(t *testing.T) {
	var req HeartbeatRequest
	// CPUUsage は *float64 です。**ゼロ値は 0 ではなく nil**で、
	// 「測っていない」を意味します。0 だと「アイドル」という測定値です。
	if req.AgentID != "" || req.CPUUsage != nil || req.EventsBuffered != 0 {
		t.Error("zero-value HeartbeatRequest should have empty/zero fields")
	}
}
