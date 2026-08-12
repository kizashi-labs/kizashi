package intel

// VirusTotal クライアントの HTTP 経路とレスポンス解釈。
//
// lookup は URL を引数で受け取るので、httptest のサーバを渡せば外部ネットワーク
// に出ずに全経路を実行できる。本番コードに手を入れる必要はない。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestVTClient(t *testing.T, handler http.HandlerFunc) (*VirusTotalClient, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c := NewVirusTotalClient("test-api-key")
	return c, srv.URL
}

func TestVirusTotalClient_IsConfigured(t *testing.T) {
	if NewVirusTotalClient("").IsConfigured() {
		t.Error("APIキー未設定で IsConfigured=true")
	}
	if !NewVirusTotalClient("k").IsConfigured() {
		t.Error("APIキー設定済みで IsConfigured=false")
	}
}

// TestVirusTotalClient_Lookup_ParsesMaliciousVerdict は正常応答の解釈。
func TestVirusTotalClient_Lookup_ParsesMaliciousVerdict(t *testing.T) {
	var gotAPIKey, gotAccept string
	c, url := newTestVTClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-apikey")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"attributes": {
					"last_analysis_stats": {
						"malicious": 42, "suspicious": 3, "undetected": 20, "harmless": 5
					},
					"reputation": -75,
					"tags": ["trojan", "downloader"]
				}
			}
		}`))
	})

	got, err := c.lookup(context.Background(), url, "file")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// 認証ヘッダを送っていないと VT は 401 を返す。
	if gotAPIKey != "test-api-key" {
		t.Errorf("x-apikey = %q, want test-api-key", gotAPIKey)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}

	if !got.Found {
		t.Error("Found = false, want true")
	}
	if got.Malicious != 42 {
		t.Errorf("Malicious = %d, want 42", got.Malicious)
	}
	if got.Suspicious != 3 {
		t.Errorf("Suspicious = %d, want 3", got.Suspicious)
	}
	if got.Reputation != -75 {
		t.Errorf("Reputation = %d, want -75", got.Reputation)
	}
	if got.Type != "file" {
		t.Errorf("Type = %q, want file", got.Type)
	}
	if len(got.Tags) != 2 {
		t.Errorf("Tags = %v, want 2 件", got.Tags)
	}
}

// TestVirusTotalClient_Lookup_NotFound は 404 が「未知の IOC」として
// エラーではなく Found=false で返ることを見る。ここをエラーにすると、
// 単に VT が知らないだけの IOC で照会全体が失敗する。
func TestVirusTotalClient_Lookup_NotFound(t *testing.T) {
	c, url := newTestVTClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	got, err := c.lookup(context.Background(), url, "ip")
	if err != nil {
		t.Fatalf("404 でエラーを返している: %v", err)
	}
	if got.Found {
		t.Error("Found = true, want false")
	}
	if got.Type != "ip" {
		t.Errorf("Type = %q, want ip", got.Type)
	}
}

// TestVirusTotalClient_Lookup_RateLimit は 429 を区別できることを見る。
// 呼び出し側がバックオフを判断できないと API キーが停止されうる。
func TestVirusTotalClient_Lookup_RateLimit(t *testing.T) {
	c, url := newTestVTClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := c.lookup(context.Background(), url, "domain")
	if err == nil {
		t.Fatal("429 でエラーが返っていない")
	}
	if !contains(err.Error(), "rate limit") {
		t.Errorf("エラーメッセージにレート制限の記載が無い: %v", err)
	}
}

func TestVirusTotalClient_Lookup_ServerError(t *testing.T) {
	c, url := newTestVTClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := c.lookup(context.Background(), url, "file"); err == nil {
		t.Error("500 でエラーが返っていない")
	}
}

func TestVirusTotalClient_Lookup_InvalidJSON(t *testing.T) {
	c, url := newTestVTClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	})

	if _, err := c.lookup(context.Background(), url, "file"); err == nil {
		t.Error("不正な JSON でエラーが返っていない")
	}
}

// TestParseVTAttributes_EmptyAttributes は属性が空でも落ちないこと。
func TestParseVTAttributes_EmptyAttributes(t *testing.T) {
	got := parseVTAttributes(map[string]interface{}{}, "url")
	if got == nil {
		t.Fatal("nil が返っている")
	}
	if !got.Found {
		t.Error("Found = false, want true (応答自体は得られている)")
	}
	if got.Malicious != 0 || got.TotalEngines != 0 {
		t.Errorf("空属性なのに件数が入っている: %+v", got)
	}
}

// TestToFloat64 は JSON 由来の値だけを扱う前提を固定する。
//
// 入力は encoding/json が map[string]interface{} に入れた値なので、数値は必ず
// float64 になる。int / int64 は 0 に落ちるが、この経路では発生しないため
// 意図的な割り切り。将来 JSON 以外から呼ぶようになったら要見直し。
func TestToFloat64(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want float64
	}{
		{"float64 はそのまま", float64(3.5), 3.5},
		{"整数値の float64", float64(42), 42},
		{"文字列は 0", "42", 0},
		{"nil は 0", nil, 0},
		{"bool は 0", true, 0},
		{"JSON 経路では現れない int は 0", int(7), 0},
	}
	for _, tc := range cases {
		if got := toFloat64(tc.in); got != tc.want {
			t.Errorf("%s: toFloat64(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
