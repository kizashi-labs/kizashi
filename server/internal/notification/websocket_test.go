package notification

// SSE ハブの配信経路。
//
// NATS 接続は nil で足りる (subscribeNATS が nil を見て何もしない)。
// 実際のブラウザ接続も要らず、handleSSE は httptest.ResponseRecorder が
// http.Flusher を満たすのでそのまま駆動できる。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestHub は NATS 無しのハブを返す。
func newTestHub() *WebSocketHub {
	return NewWebSocketHub(nil)
}

// addClient はテスト用のクライアントをハブへ直接登録する。
func addClient(h *WebSocketHub, m map[string]*sseClient, id, agentID string, buf int) *sseClient {
	c := &sseClient{id: id, ch: make(chan []byte, buf), agentID: agentID}
	h.mu.Lock()
	m[id] = c
	h.mu.Unlock()
	return c
}

// recv は指定時間内に 1 件受け取る。
func recv(t *testing.T, c *sseClient) []byte {
	t.Helper()
	select {
	case b := <-c.ch:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("配信が届かない")
		return nil
	}
}

func TestNewWebSocketHub_NilNATSIsSafe(t *testing.T) {
	h := newTestHub()
	if h == nil {
		t.Fatal("nil が返っている")
	}
	// subscribeNATS が goroutine で走るので、nil 参照で落ちないことを待って確認する。
	time.Sleep(50 * time.Millisecond)

	if h.clients == nil || h.cloudClients == nil || h.billingClients == nil {
		t.Error("クライアントマップが初期化されていない")
	}
}

// ── Broadcast ────────────────────────────────────────────────────

func TestBroadcast_DeliversToAllAlertClients(t *testing.T) {
	h := newTestHub()
	a := addClient(h, h.clients, "c1", "", 4)
	b := addClient(h, h.clients, "c2", "", 4)

	h.Broadcast(map[string]any{"type": "alert", "id": 7})

	for name, c := range map[string]*sseClient{"c1": a, "c2": b} {
		var got map[string]any
		if err := json.Unmarshal(recv(t, c), &got); err != nil {
			t.Fatalf("%s: 不正な JSON: %v", name, err)
		}
		if got["type"] != "alert" {
			t.Errorf("%s: type = %v, want alert", name, got["type"])
		}
	}
}

// TestBroadcast_FullBufferDoesNotBlock は詰まったクライアントが 1 つあっても
// 配信全体が止まらないことを見る。ここが止まるとアラート配信が
// 1 クライアントの遅延で全体停止する。
func TestBroadcast_FullBufferDoesNotBlock(t *testing.T) {
	h := newTestHub()
	stuck := addClient(h, h.clients, "stuck", "", 1)
	healthy := addClient(h, h.clients, "healthy", "", 4)

	// stuck のバッファを埋める。
	stuck.ch <- []byte("filler")

	done := make(chan struct{})
	go func() {
		h.Broadcast(map[string]any{"type": "alert"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("バッファ満杯のクライアントで Broadcast がブロックしている")
	}

	// 詰まっていない方には届く。
	recv(t, healthy)
}

func TestBroadcast_UnmarshalableMessageIsDropped(t *testing.T) {
	h := newTestHub()
	c := addClient(h, h.clients, "c1", "", 2)

	// チャネルは JSON にできない。エラーで握って配信しない。
	h.Broadcast(map[string]any{"bad": make(chan int)})

	select {
	case got := <-c.ch:
		t.Errorf("JSON 化できない値が配信されている: %s", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestBroadcastCloud_OnlyReachesCloudClients(t *testing.T) {
	h := newTestHub()
	cloud := addClient(h, h.cloudClients, "cloud1", "", 4)
	alert := addClient(h, h.clients, "alert1", "", 4)

	h.BroadcastCloud(map[string]any{"type": "cloud"})

	recv(t, cloud)
	select {
	case got := <-alert.ch:
		t.Errorf("クラウド配信がアラートクライアントに届いている: %s", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestBroadcastBilling_OnlyReachesBillingClients(t *testing.T) {
	h := newTestHub()
	billing := addClient(h, h.billingClients, "b1", "", 4)
	alert := addClient(h, h.clients, "a1", "", 4)

	h.BroadcastBilling(map[string]any{"type": "subscription"})

	recv(t, billing)
	select {
	case got := <-alert.ch:
		t.Errorf("請求配信がアラートクライアントに届いている: %s", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestBroadcastToAgent_FiltersByAgentID は端末別ストリームの絞り込み。
// ここが漏れると、ある端末の画面に別テナントの端末のイベントが流れる。
func TestBroadcastToAgent_FiltersByAgentID(t *testing.T) {
	h := newTestHub()
	const target = "agent-A"

	match := addClient(h, h.clients, "match", target, 4)
	other := addClient(h, h.clients, "other", "agent-B", 4)
	all := addClient(h, h.clients, "all", "", 4) // 全件購読

	h.BroadcastToAgent(target, map[string]any{"type": "event"})

	recv(t, match)

	select {
	case got := <-other.ch:
		t.Errorf("別端末のクライアントに届いている: %s", got)
	case <-time.After(100 * time.Millisecond):
	}

	// agentID 空のクライアントの扱いは実装依存。届いても届かなくても
	// 上の 2 点が守られていれば分離としては成立する。
	select {
	case <-all.ch:
	case <-time.After(50 * time.Millisecond):
	}
}

// ── handleSSE ────────────────────────────────────────────────────

// TestHandleAlerts_SendsWelcomeAndStreams は SSE 応答の形を見る。
func TestHandleAlerts_SendsWelcomeAndStreams(t *testing.T) {
	h := newTestHub()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/ws/alerts", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.HandleAlerts(w, req)
		close(done)
	}()

	// クライアントが登録されるまで待つ。
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.RLock()
		n := len(h.clients)
		h.mu.RUnlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("SSE クライアントが登録されない")
		}
		time.Sleep(10 * time.Millisecond)
	}

	h.Broadcast(map[string]any{"type": "alert", "id": 1})
	time.Sleep(150 * time.Millisecond)

	// 切断してハンドラを終わらせる。
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("切断してもハンドラが戻らない")
	}

	// SSE のヘッダと本文。
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"type":"connected"`) {
		t.Errorf("welcome イベントが無い: %q", body)
	}
	if !strings.Contains(body, `"type":"alert"`) {
		t.Errorf("配信したイベントが本文に無い: %q", body)
	}

	// 切断後にクライアントが登録解除されること。残ると配信のたびに
	// 死んだチャネルへ書き込み続ける。
	h.mu.RLock()
	n := len(h.clients)
	h.mu.RUnlock()
	if n != 0 {
		t.Errorf("切断後もクライアントが %d 件残っている", n)
	}
}

// TestHandleSSE_NonFlusherIsRejected は Flusher を実装しない ResponseWriter を
// 拒否すること。SSE はフラッシュできないと成立しない。
func TestHandleSSE_NonFlusherIsRejected(t *testing.T) {
	h := newTestHub()

	w := &nonFlusherWriter{header: http.Header{}}
	req := httptest.NewRequest(http.MethodGet, "/ws/alerts", nil)
	h.HandleAlerts(w, req)

	if w.status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.status)
	}
}

type nonFlusherWriter struct {
	header http.Header
	status int
}

func (n *nonFlusherWriter) Header() http.Header         { return n.header }
func (n *nonFlusherWriter) Write(b []byte) (int, error) { return len(b), nil }
func (n *nonFlusherWriter) WriteHeader(code int)        { n.status = code }

// ── ヘルパ ───────────────────────────────────────────────────────

// TestGenerateWSID_IsUnique は ID の衝突が無いこと。衝突するとクライアントが
// マップ上で上書きされ、片方が配信を受け取れなくなる。
//
// 時刻のみだった頃は一意性がクロック分解能に依存しており、分解能の粗いホストで
// 同一ナノ秒の 2 接続が衝突しえた。現在は乱数成分を足しているので、時刻が
// 完全に同じでも衝突しない。
func TestGenerateWSID_IsUnique(t *testing.T) {
	const n = 10000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := generateWSID()
		if id == "" {
			t.Fatal("空の ID が返っている")
		}
		if seen[id] {
			t.Fatalf("ID が衝突した: %s", id)
		}
		seen[id] = true
	}
}

// TestGenerateWSID_UniqueUnderConcurrency は同時接続を模した並行生成でも
// 衝突しないこと。時刻のみの実装ではここが最も衝突しやすい。
func TestGenerateWSID_UniqueUnderConcurrency(t *testing.T) {
	const workers, perWorker = 16, 500

	var mu sync.Mutex
	seen := make(map[string]bool, workers*perWorker)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := make([]string, 0, perWorker)
			for i := 0; i < perWorker; i++ {
				ids = append(ids, generateWSID())
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range ids {
				if seen[id] {
					t.Errorf("並行生成で ID が衝突した: %s", id)
					return
				}
				seen[id] = true
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*perWorker {
		t.Errorf("生成された一意な ID = %d, want %d", len(seen), workers*perWorker)
	}
}

// TestGenerateWSID_KeepsTimestampPrefix は ID の先頭が接続時刻のままであること。
// ログに出た ID から接続時刻を読み取れる利点を保つため、乱数は末尾に足す。
func TestGenerateWSID_KeepsTimestampPrefix(t *testing.T) {
	before := time.Now().Add(-time.Second)
	id := generateWSID()
	after := time.Now().Add(time.Second)

	prefix, _, found := strings.Cut(id, "-")
	if !found {
		t.Fatalf("ID に乱数部の区切りが無い: %q", id)
	}
	ts, err := time.ParseInLocation("20060102150405.000000000", prefix, time.Local)
	if err != nil {
		t.Fatalf("ID 先頭が時刻として解釈できない: %q (%v)", prefix, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("ID の時刻 %v が生成時刻の前後 1 秒に収まっていない", ts)
	}
}

func TestFormatTime(t *testing.T) {
	ts := time.Date(2026, 8, 2, 3, 4, 5, 123456789, time.UTC)
	if got := formatTime(ts); got != "20260802030405.123456789" {
		t.Errorf("formatTime = %q", got)
	}
}

func TestSplitSubject(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"alerts.created", []string{"alerts", "created"}},
		{"a.b.c", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string{""}},
		{"trailing.", []string{"trailing", ""}},
	}
	for _, tc := range cases {
		got := splitSubject(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitSubject(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitSubject(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
