package threatintel

// 公開フィードのうち、外部ネットワークに出ない経路。
//
// FetchURLhaus / FetchEmergingThreats は取得先 URL がハードコードされており、
// テストから差し替えられない (呼ぶと CI から外部へ出てしまう) ため対象外。
// ここでは静的フォールバックと、API キー未設定時の早期リターンを固定する。

import (
	"context"
	"net"
	"testing"
)

// TestFetchCIDRReport_ReturnsStaticRanges は静的フォールバックの中身を見る。
//
// 本番の脅威フィードが使えないときにここへ落ちるので、返す値が壊れていると
// 「フォールバックしたのに何も入らない」状態になる。
func TestFetchCIDRReport_ReturnsStaticRanges(t *testing.T) {
	iocs, err := FetchCIDRReport(context.Background())
	if err != nil {
		t.Fatalf("FetchCIDRReport: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatal("静的フォールバックが空")
	}

	seen := map[string]bool{}
	for _, ioc := range iocs {
		if ioc.ID == "" {
			t.Errorf("ID が空: %+v", ioc)
		}
		if seen[ioc.Value] {
			t.Errorf("値が重複している: %s", ioc.Value)
		}
		seen[ioc.Value] = true

		if ioc.Type != "ip" {
			t.Errorf("Type = %q, want ip (%s)", ioc.Type, ioc.Value)
		}
		if ioc.Source == "" {
			t.Errorf("Source が空: %s", ioc.Value)
		}
		// 値が CIDR として妥当であること。壊れていると取り込み側で弾かれる。
		if _, _, err := net.ParseCIDR(ioc.Value); err != nil {
			t.Errorf("CIDR として不正: %q (%v)", ioc.Value, err)
		}
		// severity は 1–10 スケール。
		if ioc.Severity < 1 || ioc.Severity > 10 {
			t.Errorf("Severity = %d, 1–10 の範囲外 (%s)", ioc.Severity, ioc.Value)
		}
		// confidence は 0–100。
		if ioc.Confidence < 0 || ioc.Confidence > 100 {
			t.Errorf("Confidence = %d, 0–100 の範囲外 (%s)", ioc.Confidence, ioc.Value)
		}
		if len(ioc.Tags) == 0 {
			t.Errorf("Tags が空: %s (フォールバック由来だと分からなくなる)", ioc.Value)
		}
		if ioc.CreatedAt.IsZero() {
			t.Errorf("CreatedAt がゼロ値: %s", ioc.Value)
		}
	}

	// ID は呼び出しごとに新しく振られる (同じ ID を再利用すると upsert が衝突する)。
	again, err := FetchCIDRReport(context.Background())
	if err != nil {
		t.Fatalf("FetchCIDRReport(2回目): %v", err)
	}
	if len(again) != len(iocs) {
		t.Fatalf("件数が呼び出しごとに変わる: %d -> %d", len(iocs), len(again))
	}
	if again[0].ID == iocs[0].ID {
		t.Error("ID が使い回されている")
	}
	if again[0].Value != iocs[0].Value {
		t.Errorf("値の順序が安定していない: %q -> %q", iocs[0].Value, again[0].Value)
	}
}

// TestFetchAbuseIPDB_NoAPIKeyReturnsEmpty は API キー未設定時に外部へ出ずに
// 空を返すこと。ここが早期リターンしないと、キー無しで毎回 401 を叩きに行く。
func TestFetchAbuseIPDB_NoAPIKeyReturnsEmpty(t *testing.T) {
	iocs, err := FetchAbuseIPDB(context.Background(), "")
	if err != nil {
		t.Fatalf("FetchAbuseIPDB: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("件数 = %d, want 0", len(iocs))
	}
	if iocs == nil {
		t.Error("nil が返っている。呼び出し側は空スライスを期待している")
	}
}
