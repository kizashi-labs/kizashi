package netanalysis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every query in this package read events.data. Ingestion writes events.raw_data
// and is the only writer of the table, so all four analyses were reading a
// column that has never existed. Measured against 12 real network events:
//
//	                        before          after
//	GetTopConnections       0 rows          1 row
//	GetPortAnalysis         0 rows          1 row
//	GetBeaconingDetection   0 rows          1 row
//	GetNetworkStats         total=0         total=12
//	returned error          nil (all four)  nil
//
// The errors were swallowed and an empty slice returned with a nil error, so
// /admin/network/* answered 200 with "no network activity" — what a quiet
// network looks like. They propagate now; the handler already turns them into a
// 500.
//
// Two further defects were hidden behind the column name, because Postgres
// reports the first error it finds:
//
//   - The beaconing query computed AVG(LEAD(ts) OVER (...) - ts), an aggregate
//     containing a window function. Postgres rejects that outright (42803). The
//     statement could never have run under any column name.
//   - It then compared STDDEV(ts) — the spread of the timestamps — against the
//     mean interval. Regular beaconing spreads its timestamps evenly across the
//     window, so that number grows with the window while the interval does not:
//     the more textbook the beacon, the further it sat from tripping the test.
//     Regularity is a property of the gaps between connections, and the gaps are
//     what is measured now.
//   - GetTopConnections put bytes_sent in its GROUP BY next to the connection
//     identity. Real traffic sends a different number of bytes every time, so
//     each event formed its own group and COUNT(*) was 1 for all of them —
//     "the most active pairs" ranked nothing.
//
// The package's existing tests all exercise deriveFlags, calculateThreatScore
// and portRiskLevel. Not one of them touches a query, which is how a module
// that returned nothing at all kept a green suite. These tests drive the SQL.

// The destination this file's fixtures talk to. TEST-NET-3 (RFC 5737), and
// distinct from anything another package seeds, so assertions can pick out
// their own rows from a shared events table rather than assuming they are the
// only writer.
const probeDstIP = "203.0.113.201"

func queryPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedNetworkEvents writes connections to probeDstIP at the given offsets,
// shaped exactly the way ingestion.normalizeEventData writes a network event.
func seedNetworkEvents(t *testing.T, pool *pgxpool.Pool, offsets []time.Duration) string {
	t.Helper()
	ctx := context.Background()

	// 自分で端末を1台作ります。
	//
	// **以前は `SELECT id FROM agents LIMIT 1` で借りて、無ければ skip
	// していました。** 開発用の DB には他の検査が残した行があるので、
	// 手元では走ります。CI の DB は毎回まっさらなので、**この5本は
	// 一度も走っていませんでした。** skip した検査と通った検査は、
	// 同じ `ok` の行を出します。
	//
	// tenant_id は列の既定値（既存の既定テナント）に任せます。
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, status, source, settings)
		VALUES ($1::uuid, $2, 'linux', 'online', 'agent', '{}'::jsonb)`,
		agentID, "netprobe-"+agentID[:8]); err != nil {
		t.Fatalf("端末を作れません: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id = $1`, agentID)
	})

	clear := func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM events WHERE event_type='network' AND raw_data->>'dst_ip'=$1`, probeDstIP)
	}
	clear()
	t.Cleanup(clear)

	base := time.Now().Add(-2 * time.Hour)
	for i, off := range offsets {
		if _, err := pool.Exec(ctx, `
			INSERT INTO events (time, agent_id, event_type, raw_data)
			VALUES ($1, $2::uuid, 'network', $3::jsonb)`,
			base.Add(off), agentID,
			fmt.Sprintf(`{"src_ip":"10.0.0.5","src_port":44000,"dst_ip":%q,
			  "dst_port":8443,"protocol":"tcp","direction":"outbound",
			  "bytes_sent":%d,"bytes_recv":512,"pid":900,
			  "process_name":"curl","state":"ESTABLISHED","hostname":"netprobe"}`,
				probeDstIP, 1000+i),
		); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
	return agentID
}

// evenOffsets returns n connections spaced exactly apart — a textbook beacon.
func evenOffsets(n int, spacing time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = time.Duration(i) * spacing
	}
	return out
}

// ─── The queries read the column ingestion writes ─────────────────────────────

// The headline: real events must reach all four analyses.
func TestEveryAnalysisSeesRealNetworkEvents(t *testing.T) {
	pool := queryPool(t)
	seedNetworkEvents(t, pool, evenOffsets(12, time.Minute))
	a := NewAnalyzer(pool)
	ctx := context.Background()

	conns, err := a.GetTopConnections(ctx, 24, 50)
	if err != nil {
		t.Fatalf("GetTopConnections: %v", err)
	}
	if findConn(conns) == nil {
		t.Errorf("投入した接続が上位接続に現れません。"+
			"events の JSONB 列は raw_data です (%d 件返却)", len(conns))
	}

	ports, err := a.GetPortAnalysis(ctx, 24)
	if err != nil {
		t.Fatalf("GetPortAnalysis: %v", err)
	}
	if !hasPort(ports, 8443) {
		t.Errorf("ポート 8443 がポート分析に現れません (%d 件返却)", len(ports))
	}

	beacons, err := a.GetBeaconingDetection(ctx, 24)
	if err != nil {
		t.Fatalf("GetBeaconingDetection: %v", err)
	}
	if findBeacon(beacons) == nil {
		t.Errorf("等間隔の12接続がビーコン候補に現れません (%d 件返却)", len(beacons))
	}

	stats, err := a.GetNetworkStats(ctx, 24)
	if err != nil {
		t.Fatalf("GetNetworkStats: %v", err)
	}
	// Other packages share this table, so the assertion is a floor rather than
	// an equality.
	if stats.TotalConnections < 12 {
		t.Errorf("接続数が %d 件。投入した12件を下回っています", stats.TotalConnections)
	}
	if stats.UniqueIPs < 1 || stats.UniquePorts < 1 {
		t.Errorf("uniqueIPs=%d uniquePorts=%d、いずれも1以上のはずです",
			stats.UniqueIPs, stats.UniquePorts)
	}
}

// ─── A failure is not an empty result ─────────────────────────────────────────

// All four used to log a warning and return an empty slice with a nil error, so
// an outage was reported as "no network activity".
func TestAFailedQueryIsAnErrorNotAnEmptyResult(t *testing.T) {
	pool := queryPool(t)
	a := NewAnalyzer(pool)

	dead, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := a.GetTopConnections(dead, 24, 10); err == nil {
		t.Error("GetTopConnections がクエリ失敗時に nil を返しました。" +
			"空の結果は「通信がない」という主張であって、障害の報告ではありません")
	}
	if _, err := a.GetPortAnalysis(dead, 24); err == nil {
		t.Error("GetPortAnalysis がクエリ失敗時に nil を返しました")
	}
	if _, err := a.GetBeaconingDetection(dead, 24); err == nil {
		t.Error("GetBeaconingDetection がクエリ失敗時に nil を返しました")
	}
	// GetNetworkStats runs two queries and used to discard both errors. Under a
	// dead context both fail, so "an error came back" would still hold with one
	// of the two silenced — the second would cover for the first. The assertion
	// is therefore on which query reported: the first to fail is the counter
	// query, so that is the error the caller must see.
	_, err := a.GetNetworkStats(dead, 24)
	if err == nil {
		t.Fatal("GetNetworkStats がクエリ失敗時に nil を返しました。" +
			"2つの QueryRow はエラーを完全に破棄していました")
	}
	if !strings.Contains(err.Error(), "network stats") {
		t.Errorf("返ったエラーが %q。最初に失敗するのは件数クエリなので "+
			"\"network stats\" を含むはずです — 1つ目のエラーが握り潰され、"+
			"2つ目が肩代わりしています", err)
	}
}

// ─── Top connections aggregate rather than fragment ───────────────────────────

// bytes_sent varies per connection, which is why grouping by it produced one
// group per event and a COUNT(*) of 1 everywhere.
func TestTopConnectionsAggregateAcrossVaryingByteCounts(t *testing.T) {
	pool := queryPool(t)
	seedNetworkEvents(t, pool, evenOffsets(12, time.Minute))

	conns, err := NewAnalyzer(pool).GetTopConnections(context.Background(), 24, 50)
	if err != nil {
		t.Fatalf("GetTopConnections: %v", err)
	}
	got := findConn(conns)
	if got == nil {
		t.Fatal("投入した接続が現れません")
	}

	if got.PacketCount != 12 {
		t.Errorf("接続数が %d、期待は12。"+
			"bytes_sent を GROUP BY に含めるとイベントごとに別グループになり、"+
			"「最も活発な接続」が何も順位付けしなくなります", got.PacketCount)
	}
	// 1000..1011 inclusive.
	const wantBytes = 12*1000 + (0+11)*12/2
	if got.BytesSent != wantBytes {
		t.Errorf("bytes_sent が %d、期待は %d（合計されていません）", got.BytesSent, wantBytes)
	}
	if got.DstPort != 8443 || got.Protocol != "tcp" {
		t.Errorf("接続の識別子が壊れています: port=%d protocol=%q", got.DstPort, got.Protocol)
	}
}

// ─── Beaconing measures the gaps, not the timestamps ──────────────────────────

// A regular series is a beacon and an irregular one is not. The old query could
// answer neither: it was rejected by Postgres before it ran.
func TestBeaconingSeparatesRegularFromIrregular(t *testing.T) {
	pool := queryPool(t)
	ctx := context.Background()

	t.Run("規則的な接続はビーコンとして検出される", func(t *testing.T) {
		seedNetworkEvents(t, pool, evenOffsets(12, time.Minute))
		beacons, err := NewAnalyzer(pool).GetBeaconingDetection(ctx, 24)
		if err != nil {
			t.Fatalf("GetBeaconingDetection: %v", err)
		}
		got := findBeacon(beacons)
		if got == nil {
			t.Fatal("60秒間隔の12接続が検出されませんでした")
		}
		if got.IntervalSecs < 59 || got.IntervalSecs > 61 {
			t.Errorf("平均間隔が %.1f 秒、期待は約60秒", got.IntervalSecs)
		}
		if got.ConnectionCount != 12 {
			t.Errorf("接続数が %d、期待は12", got.ConnectionCount)
		}
		if got.Confidence < 0.9 {
			t.Errorf("完全に等間隔なのに確度が %.2f しかありません", got.Confidence)
		}
	})

	t.Run("不規則な接続はビーコンとして検出されない", func(t *testing.T) {
		// Same count and same span, but the gaps vary wildly.
		seedNetworkEvents(t, pool, []time.Duration{
			0, 3 * time.Second, 200 * time.Second, 210 * time.Second,
			1000 * time.Second, 1005 * time.Second, 2400 * time.Second,
			2401 * time.Second, 4000 * time.Second, 4400 * time.Second,
			6000 * time.Second, 6600 * time.Second,
		})
		beacons, err := NewAnalyzer(pool).GetBeaconingDetection(ctx, 24)
		if err != nil {
			t.Fatalf("GetBeaconingDetection: %v", err)
		}
		if got := findBeacon(beacons); got != nil {
			t.Errorf("間隔がばらついているのにビーコンと判定されました "+
				"(interval=%.1f confidence=%.2f)。"+
				"タイムスタンプの分散ではなく間隔の分散で判定する必要があります",
				got.IntervalSecs, got.Confidence)
		}
	})
}

// Fewer than five connections is not enough to call anything periodic.
func TestBeaconingNeedsEnoughConnections(t *testing.T) {
	pool := queryPool(t)
	seedNetworkEvents(t, pool, evenOffsets(4, time.Minute))

	beacons, err := NewAnalyzer(pool).GetBeaconingDetection(context.Background(), 24)
	if err != nil {
		t.Fatalf("GetBeaconingDetection: %v", err)
	}
	if got := findBeacon(beacons); got != nil {
		t.Errorf("4接続でビーコン判定されました (最低5接続必要): count=%d", got.ConnectionCount)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func findConn(conns []ConnectionSummary) *ConnectionSummary {
	for i := range conns {
		if conns[i].DstIP == probeDstIP {
			return &conns[i]
		}
	}
	return nil
}

func findBeacon(beacons []BeaconCandidate) *BeaconCandidate {
	for i := range beacons {
		if beacons[i].DstIP == probeDstIP {
			return &beacons[i]
		}
	}
	return nil
}

func hasPort(ports []PortStat, want int) bool {
	for _, p := range ports {
		if p.Port == want {
			return true
		}
	}
	return false
}
