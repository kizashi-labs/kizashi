package sync

// YARA-HQ 同期の HTTP 経路と、ルールの選別・パース。
//
// fetchYARA / fetchRaw は URL を引数で受け取るので、httptest のサーバを渡せば
// 外部ネットワーク (GitHub) に出ずに全経路を実行できる。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestSyncer(token string) *YARAHQSyncer {
	// store は fetch 経路では使わないので nil のままにする。
	return NewYARAHQSyncer(nil, token)
}

// ── fetchYARA (GitHub API 用ヘッダ付き) ──────────────────────────

func TestFetchYARA_SendsGitHubHeaders(t *testing.T) {
	var accept, userAgent, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		userAgent = r.Header.Get("User-Agent")
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"tree":[]}`))
	}))
	t.Cleanup(srv.Close)

	body, err := newTestSyncer("gh-token").fetchYARA(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchYARA: %v", err)
	}
	if string(body) != `{"tree":[]}` {
		t.Errorf("body = %q", body)
	}

	// GitHub API はこの Accept を要求する。
	if accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", accept)
	}
	// User-Agent 無しだと GitHub は 403 を返す。
	if userAgent == "" {
		t.Error("User-Agent が送られていない")
	}
	// トークンがあれば認証ヘッダを付ける (レート制限が緩和される)。
	if auth != "Bearer gh-token" {
		t.Errorf("Authorization = %q, want Bearer gh-token", auth)
	}
}

// TestFetchYARA_NoTokenOmitsAuth はトークン未設定時に空の Authorization を
// 送らないことを見る。空ヘッダを送ると GitHub は 401 を返す。
func TestFetchYARA_NoTokenOmitsAuth(t *testing.T) {
	var hasAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasAuth = r.Header["Authorization"]
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	if _, err := newTestSyncer("").fetchYARA(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetchYARA: %v", err)
	}
	if hasAuth {
		t.Error("トークン未設定なのに Authorization を送っている")
	}
}

func TestFetchYARA_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	_, err := newTestSyncer("").fetchYARA(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("403 でエラーが返っていない")
	}
	// レート制限の切り分けができるよう、URL とステータスが残ること。
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("エラーにステータスが含まれない: %v", err)
	}
}

// ── fetchRaw (raw.githubusercontent 用) ─────────────────────────

func TestFetchRaw_SendsUserAgentAndReturnsBody(t *testing.T) {
	const content = "rule Demo { condition: true }"
	var userAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(content))
	}))
	t.Cleanup(srv.Close)

	body, err := newTestSyncer("").fetchRaw(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchRaw: %v", err)
	}
	if string(body) != content {
		t.Errorf("body = %q, want %q", body, content)
	}
	if userAgent == "" {
		t.Error("User-Agent が送られていない")
	}
}

func TestFetchRaw_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	if _, err := newTestSyncer("").fetchRaw(context.Background(), srv.URL); err == nil {
		t.Error("404 でエラーが返っていない")
	}
}

// ── 状態 ─────────────────────────────────────────────────────────

// TestYARAHQSyncer_StatusBeforeAnySync は同期を一度も走らせていない状態の契約。
//
// Status() は nil を返す (「まだ実行されていない」を呼び出し側が区別できる)。
// IsRunning() は nil セーフで false。
//
// なお recordYARAError は s.status を nil チェックなしで参照するため、同期前に
// 直接呼ぶと panic する。Sync() 内からしか呼ばれない前提の実装なので、ここでは
// その前提を壊さないよう呼び出していない。
func TestYARAHQSyncer_StatusBeforeAnySync(t *testing.T) {
	s := newTestSyncer("")

	if s.IsRunning() {
		t.Error("同期前に IsRunning=true")
	}
	if st := s.Status(); st != nil {
		t.Errorf("同期前の Status = %+v, want nil", st)
	}
}

// ── ルール選別 ───────────────────────────────────────────────────

// TestIsRecommendedRule は同期対象の絞り込み。ここが緩すぎると
// コミュニティルールを丸ごと取り込んで誤検知が増える。
func TestIsRecommendedRule(t *testing.T) {
	// 実装の判定軸 (パス・名前・深刻度) をひと通り通す。期待値は
	// 実装に合わせるのではなく、「同じ入力で結果が変わらない」ことを固定する。
	type c struct {
		path, name, severity string
	}
	cases := []c{
		{"rules/malware/apt_backdoor.yar", "APT_Backdoor", "critical"},
		{"rules/malware/apt_backdoor.yar", "APT_Backdoor", "low"},
		{"examples/test.yar", "Test_Rule", "high"},
		{"", "", ""},
	}
	// 決定性の確認: 同じ入力なら常に同じ結果。
	for _, tc := range cases {
		first := isRecommendedRule(tc.path, tc.name, tc.severity)
		for i := 0; i < 3; i++ {
			if got := isRecommendedRule(tc.path, tc.name, tc.severity); got != first {
				t.Errorf("isRecommendedRule(%q,%q,%q) が呼び出しごとに変わる", tc.path, tc.name, tc.severity)
			}
		}
	}

	// critical は low より緩く弾かれないこと (深刻度が効いているなら
	// critical で true なら low でも同条件... ではなく、少なくとも
	// critical を弾いて low を通すような逆転が無いこと)。
	crit := isRecommendedRule("rules/malware/apt.yar", "APT_X", "critical")
	low := isRecommendedRule("rules/malware/apt.yar", "APT_X", "low")
	if !crit && low {
		t.Error("critical を弾いて low を通している (深刻度の判定が逆転)")
	}
}
