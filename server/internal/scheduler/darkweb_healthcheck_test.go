package scheduler

// Tor 経由の死活監視 (healthCheck)。
//
// healthCheck は SOCKS5 プロキシ経由で .onion に HTTP を投げる。テストでは
// SOCKS5 のハンドシェイクだけを実装したスタブを立て、CONNECT 先の名前は無視して
// ローカルの httptest サーバへ中継する。これで Tor も .onion も無しに、
// 生存判定と fail_count の増減・自動無効化まで通せる。
//
// SOCKS5 (RFC 1928) の CONNECT は以下だけで足りる:
//   1. クライアント: 0x05 <nmethods> <methods...>
//   2. サーバ:       0x05 0x00            (認証なし)
//   3. クライアント: 0x05 0x01 0x00 <atyp> <addr> <port>
//   4. サーバ:       0x05 0x00 0x00 0x01 <bind addr 4B> <bind port 2B>
//   5. 以降は素通し

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// socks5Stub は CONNECT を受けて、宛先に関わらず target へ中継する。
type socks5Stub struct {
	ln     net.Listener
	target string // 中継先 (host:port)

	mu      sync.Mutex
	connect int // CONNECT を受けた回数
}

func newSOCKS5Stub(t *testing.T, target string) *socks5Stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socks5Stub{ln: ln, target: target}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *socks5Stub) addr() string { return s.ln.Addr().String() }

func (s *socks5Stub) connectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connect
}

func (s *socks5Stub) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *socks5Stub) handle(c net.Conn) {
	defer c.Close()

	// 1) メソッド交渉
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	nMethods := int(head[1])
	if _, err := io.ReadFull(c, make([]byte, nMethods)); err != nil {
		return
	}
	// 2) 認証なしを選択
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 3) CONNECT 要求。宛先は読み捨てる (.onion を解決する必要はない)。
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
			return
		}
	case 0x03: // ドメイン名
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0]))); err != nil {
			return
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, make([]byte, 16)); err != nil {
			return
		}
	default:
		return
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil { // ポート
		return
	}

	s.mu.Lock()
	s.connect++
	s.mu.Unlock()

	// 4) 成功応答
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(resp[8:], 0)
	if _, err := c.Write(resp); err != nil {
		return
	}

	// 5) 中継
	up, err := net.Dial("tcp", s.target)
	if err != nil {
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(up, c) }()
	go func() { defer wg.Done(); _, _ = io.Copy(c, up) }()
	wg.Wait()
}

// seedSite は死活監視の対象サイトを 1 件用意し、その id を返す。
func seedSite(t *testing.T, pool *pgxpool.Pool, onion string, failCount int, active bool) string {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM darkweb_ransomware_sites WHERE onion_url = $1`, onion)
	}
	cleanup()
	t.Cleanup(cleanup)

	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO darkweb_ransomware_sites
		    (group_name, onion_url, source, fail_count, is_active, last_checked_at)
		VALUES ('ITestHealth', $1, 'test', $2, $3, NOW() - INTERVAL '8 days')
		RETURNING id`, onion, failCount, active).Scan(&id); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	return id
}

func siteState(t *testing.T, pool *pgxpool.Pool, id string) (failCount int, active bool) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT fail_count, is_active FROM darkweb_ransomware_sites WHERE id = $1`, id,
	).Scan(&failCount, &active); err != nil {
		t.Fatalf("状態取得: %v", err)
	}
	return
}

// newHealthScheduler は SOCKS5 スタブを向いたスケジューラを返す。
func newHealthScheduler(pool *pgxpool.Pool, socksAddr string) *DarkWebScheduler {
	return NewDarkWebScheduler(pool, "socks5://"+socksAddr, false)
}

// TestHealthCheck_AliveSiteResetsFailCount は応答するサイトで fail_count が
// 0 に戻り、有効のまま維持されること。
func TestHealthCheck_AliveSiteResetsFailCount(t *testing.T) {
	pool := darkwebTestPool(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)

	stub := newSOCKS5Stub(t, originHostPort(t, origin.URL))
	// 既に 3 回失敗している状態から始める。
	id := seedSite(t, pool, "itest-alive-aaa.onion", 3, true)

	newHealthScheduler(pool, stub.addr()).healthCheck(context.Background())

	if stub.connectCount() == 0 {
		t.Fatal("SOCKS5 プロキシ経由で接続していない")
	}

	fails, active := siteState(t, pool, id)
	if fails != 0 {
		t.Errorf("fail_count = %d, want 0 (生存確認でリセットされるはず)", fails)
	}
	if !active {
		t.Error("生存しているサイトが無効化されている")
	}
}

// TestHealthCheck_DeadSiteIncrementsFailCount は応答しないサイトで
// fail_count が加算されること。
func TestHealthCheck_DeadSiteIncrementsFailCount(t *testing.T) {
	pool := darkwebTestPool(t)

	// 中継先を閉じたポートにして接続失敗を作る。
	closed := freePort(t)
	stub := newSOCKS5Stub(t, closed)
	id := seedSite(t, pool, "itest-dead-bbb.onion", 1, true)

	newHealthScheduler(pool, stub.addr()).healthCheck(context.Background())

	fails, active := siteState(t, pool, id)
	if fails != 2 {
		t.Errorf("fail_count = %d, want 2 (1 + 1)", fails)
	}
	// 5 未満なので有効のまま。
	if !active {
		t.Error("失敗 2 回で無効化されている (閾値は 5)")
	}
}

// TestHealthCheck_DisablesSiteAfterFiveFailures は 5 回連続失敗で自動無効化。
// ここが効かないと死んだ .onion を延々と叩き続ける。
func TestHealthCheck_DisablesSiteAfterFiveFailures(t *testing.T) {
	pool := darkwebTestPool(t)

	closed := freePort(t)
	stub := newSOCKS5Stub(t, closed)
	// 4 回失敗済み → 今回の失敗で 5 になり無効化される。
	id := seedSite(t, pool, "itest-disable-ccc.onion", 4, true)

	newHealthScheduler(pool, stub.addr()).healthCheck(context.Background())

	fails, active := siteState(t, pool, id)
	if fails != 5 {
		t.Errorf("fail_count = %d, want 5", fails)
	}
	if active {
		t.Error("5 回失敗しても無効化されていない")
	}
}

// TestHealthCheck_ServerErrorCountsAsDead は 5xx を死亡扱いにすること。
// 200 番台以外でも生存とみなすと、エラーページを返すだけのサイトが
// いつまでも有効に残る。
func TestHealthCheck_ServerErrorCountsAsDead(t *testing.T) {
	pool := darkwebTestPool(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(origin.Close)

	stub := newSOCKS5Stub(t, originHostPort(t, origin.URL))
	id := seedSite(t, pool, "itest-5xx-ddd.onion", 0, true)

	newHealthScheduler(pool, stub.addr()).healthCheck(context.Background())

	fails, _ := siteState(t, pool, id)
	if fails != 1 {
		t.Errorf("fail_count = %d, want 1 (500 は死亡扱い)", fails)
	}
}

// TestHealthCheck_BadProxyIsTolerated はプロキシに繋がらない場合でも
// 落ちずに戻ること。Tor コンテナ停止中にスケジューラが死んでは困る。
func TestHealthCheck_BadProxyIsTolerated(t *testing.T) {
	pool := darkwebTestPool(t)
	id := seedSite(t, pool, "itest-noproxy-eee.onion", 0, true)

	// 誰も待ち受けていないアドレス。
	NewDarkWebScheduler(pool, "socks5://"+freePort(t), false).
		healthCheck(context.Background())

	// 接続できないので失敗として計上される。落ちないことが要点。
	if fails, _ := siteState(t, pool, id); fails != 1 {
		t.Errorf("fail_count = %d, want 1", fails)
	}
}

// originHostPort は httptest の URL から host:port を取り出す。
func originHostPort(t *testing.T, rawURL string) string {
	t.Helper()
	hostPort := rawURL
	for _, prefix := range []string{"http://", "https://"} {
		if len(hostPort) > len(prefix) && hostPort[:len(prefix)] == prefix {
			hostPort = hostPort[len(prefix):]
			break
		}
	}
	return hostPort
}

// freePort は誰も待ち受けていない 127.0.0.1 のアドレスを返す。
func freePort(t *testing.T) string {
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
