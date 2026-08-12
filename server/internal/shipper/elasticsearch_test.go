package shipper

import (
	"context"
	"testing"
)

// ─── NewElasticsearchShipper ──────────────────────────────────────────────────

func TestNewElasticsearchShipper_NotNil(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "user", "pass", "edr-events")
	if s == nil {
		t.Fatal("NewElasticsearchShipper は nil を返すべきではありません")
	}
}

func TestNewElasticsearchShipper_EnabledWhenURLProvided(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	if !s.enabled {
		t.Error("URL が設定されているとき enabled は true であるべきです")
	}
}

func TestNewElasticsearchShipper_DisabledWhenURLEmpty(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	if s.enabled {
		t.Error("URL が空のとき enabled は false であるべきです")
	}
}

func TestNewElasticsearchShipper_DefaultIndex(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	if s.index != "edr-events" {
		t.Errorf("デフォルト index: got %q, want edr-events", s.index)
	}
}

func TestNewElasticsearchShipper_CustomIndex(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "my-index")
	if s.index != "my-index" {
		t.Errorf("カスタム index: got %q, want my-index", s.index)
	}
}

func TestNewElasticsearchShipper_TrimsTrailingSlash(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200/", "", "", "")
	if s.url != "http://localhost:9200" {
		t.Errorf("URL 末尾スラッシュ除去: got %q, want http://localhost:9200", s.url)
	}
}

func TestNewElasticsearchShipper_BufferInitialized(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	if s.buffer == nil {
		t.Error("buffer が初期化されていません")
	}
	if len(s.buffer) != 0 {
		t.Errorf("初期 buffer 長: got %d, want 0", len(s.buffer))
	}
}

func TestNewElasticsearchShipper_MaxBuf(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	if s.maxBuf != 100 {
		t.Errorf("maxBuf: got %d, want 100", s.maxBuf)
	}
}

func TestNewElasticsearchShipper_HTTPClientNotNil(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	if s.client == nil {
		t.Error("httpClient が nil です")
	}
}

func TestNewElasticsearchShipper_CredentialsStored(t *testing.T) {
	s := NewElasticsearchShipper("http://es:9200", "admin", "secret", "idx")
	if s.username != "admin" {
		t.Errorf("username: got %q, want admin", s.username)
	}
	if s.password != "secret" {
		t.Errorf("password: got %q, want secret", s.password)
	}
}

// ─── Ship (disabled) ──────────────────────────────────────────────────────────

func TestShip_Disabled_DoesNotBuffer(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	s.Ship(context.Background(), "alert", map[string]interface{}{"id": "1"})
	if len(s.buffer) != 0 {
		t.Errorf("無効シッパー: buffer に積まれるべきでない: got %d", len(s.buffer))
	}
}

func TestShip_Enabled_AddsToBuffer(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	s.Ship(context.Background(), "alert", map[string]interface{}{"id": "1"})
	if len(s.buffer) != 1 {
		t.Errorf("有効シッパー: buffer に 1 件積まれるべき: got %d", len(s.buffer))
	}
}

func TestShip_SetsTimestamp(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	doc := map[string]interface{}{"id": "1"}
	s.Ship(context.Background(), "alert", doc)
	if _, ok := doc["@timestamp"]; !ok {
		t.Error("Ship: @timestamp が設定されていません")
	}
}

func TestShip_SetsDocType(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	doc := map[string]interface{}{"id": "1"}
	s.Ship(context.Background(), "process_event", doc)
	if doc["doc_type"] != "process_event" {
		t.Errorf("Ship: doc_type got %v, want process_event", doc["doc_type"])
	}
}

func TestShip_BufferFullFlushes(t *testing.T) {
	// maxBuf=2 で 2 件目追加後に自動フラッシュ (enabled=false なので Flush は何もしない)
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	s.maxBuf = 2
	// Flush が HTTP を叩かないよう、enabled=false にする
	s.enabled = false
	s.Ship(context.Background(), "a", map[string]interface{}{"n": 1})
	s.Ship(context.Background(), "b", map[string]interface{}{"n": 2})
	// enabled=false なので Ship は buffer に追加しない
	if len(s.buffer) != 0 {
		t.Errorf("disabled ship buffer: got %d, want 0", len(s.buffer))
	}
}

// ─── Flush (disabled / empty) ─────────────────────────────────────────────────

func TestFlush_Disabled_DoesNothing(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	// panic しないこと
	s.Flush(context.Background())
}

func TestFlush_EmptyBuffer_DoesNothing(t *testing.T) {
	s := NewElasticsearchShipper("http://localhost:9200", "", "", "")
	s.Flush(context.Background()) // 空バッファでも panic しない
}

// ─── minInt ───────────────────────────────────────────────────────────────────

func TestMinInt_ASmaller(t *testing.T) {
	if got := minInt(3, 5); got != 3 {
		t.Errorf("minInt(3,5): got %d, want 3", got)
	}
}

func TestMinInt_BSmaller(t *testing.T) {
	if got := minInt(7, 4); got != 4 {
		t.Errorf("minInt(7,4): got %d, want 4", got)
	}
}

func TestMinInt_Equal(t *testing.T) {
	if got := minInt(6, 6); got != 6 {
		t.Errorf("minInt(6,6): got %d, want 6", got)
	}
}

func TestMinInt_NegativeValues(t *testing.T) {
	if got := minInt(-1, -3); got != -3 {
		t.Errorf("minInt(-1,-3): got %d, want -3", got)
	}
}

func TestMinInt_ZeroAndPositive(t *testing.T) {
	if got := minInt(0, 5); got != 0 {
		t.Errorf("minInt(0,5): got %d, want 0", got)
	}
}

// ─── Test (disabled) ─────────────────────────────────────────────────────────

func TestTest_Disabled_ReturnsError(t *testing.T) {
	s := NewElasticsearchShipper("", "", "", "")
	_, err := s.Test(context.Background())
	if err == nil {
		t.Error("ES_URL 未設定の Test はエラーを返すべきです")
	}
}
