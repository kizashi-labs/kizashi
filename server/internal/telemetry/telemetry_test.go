package telemetry

import (
	"context"
	"testing"
)

// ─── InitMetrics ──────────────────────────────────────────────────────────────

func TestInitMetrics_NoEndpoint_ReturnsShutdownFn(t *testing.T) {
	// OTEL_EXPORTER_OTLP_ENDPOINT 未設定 → noop プロバイダー使用
	shutdown, err := InitMetrics(context.Background(), "edr-test")
	if err != nil {
		t.Fatalf("InitMetrics: 予期しないエラー: %v", err)
	}
	if shutdown == nil {
		t.Fatal("InitMetrics: shutdown 関数が nil です")
	}
}

func TestInitMetrics_ShutdownFn_ReturnsNil(t *testing.T) {
	shutdown, _ := InitMetrics(context.Background(), "edr-test")
	err := shutdown(context.Background())
	if err != nil {
		t.Errorf("shutdown(): 予期しないエラー: %v", err)
	}
}

func TestInitMetrics_WithEndpoint_ReturnsShutdownFn(t *testing.T) {
	// エンドポイント設定時もフォールバックで noop が使われる (OTLP sdk 未追加)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	shutdown, err := InitMetrics(context.Background(), "edr-test")
	if err != nil {
		t.Fatalf("InitMetrics (endpoint): 予期しないエラー: %v", err)
	}
	if shutdown == nil {
		t.Fatal("InitMetrics (endpoint): shutdown 関数が nil です")
	}
}

// ─── Meter ────────────────────────────────────────────────────────────────────

func TestMeter_NotNil(t *testing.T) {
	// InitMetrics を先に呼んで noop プロバイダーをセット
	_, _ = InitMetrics(context.Background(), "edr-test")
	m := Meter("test.meter")
	if m == nil {
		t.Fatal("Meter: nil を返すべきではありません")
	}
}
