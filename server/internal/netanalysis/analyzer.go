// Package netanalysis provides network traffic pattern analysis from stored
// network events.  It does NOT perform raw packet capture; it analyses the
// network events already stored in the events table.
package netanalysis

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// commonPorts is the set of well-known ports that are not flagged as unusual.
var commonPorts = map[int]bool{
	22: true, 25: true, 53: true, 80: true, 110: true, 143: true,
	443: true, 465: true, 587: true, 993: true, 995: true,
	3306: true, 5432: true, 6379: true, 8080: true, 8443: true,
}

// ConnectionSummary aggregates network activity between a source/destination pair.
type ConnectionSummary struct {
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	DstPort     int       `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	BytesSent   int64     `json:"bytes_sent"`
	PacketCount int       `json:"packet_count"`
	Duration    string    `json:"duration"`
	Hostname    string    `json:"hostname"`
	AgentID     string    `json:"agent_id"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ThreatScore int       `json:"threat_score"`
	Flags       []string  `json:"flags"` // tor_exit, known_c2, unusual_port, high_frequency
}

// PortStat summarises traffic on a single destination port.
type PortStat struct {
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	ConnectionCount int    `json:"connection_count"`
	UniqueHosts     int    `json:"unique_hosts"`
	IsCommon        bool   `json:"is_common"`
	RiskLevel       string `json:"risk_level"`
}

// BeaconCandidate is a destination IP that shows regular connection intervals
// (potential C2 beaconing behaviour).
type BeaconCandidate struct {
	DstIP           string  `json:"dst_ip"`
	AgentID         string  `json:"agent_id"`
	IntervalSecs    float64 `json:"interval_secs"`
	ConnectionCount int     `json:"connection_count"`
	Confidence      float64 `json:"confidence"`
}

// Analyzer queries network events already stored in the database.
type Analyzer struct {
	pool *pgxpool.Pool
}

// NewAnalyzer creates an Analyzer.
func NewAnalyzer(pool *pgxpool.Pool) *Analyzer {
	return &Analyzer{pool: pool}
}

// GetTopConnections aggregates network events by src+dst+port and returns the
// most active pairs within the past <hours> hours.
func (a *Analyzer) GetTopConnections(ctx context.Context, hours, limit int) ([]ConnectionSummary, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	// bytes_sent is SUMmed, not grouped by. It used to appear in the GROUP BY
	// alongside the connection identity, and real traffic sends a different
	// number of bytes every time — so each event formed its own group, COUNT(*)
	// was 1 for all of them, and "the most active pairs" ranked nothing.
	rows, err := a.pool.Query(ctx, `
		SELECT
			COALESCE(raw_data->>'src_ip',''),
			COALESCE(raw_data->>'dst_ip',''),
			COALESCE((raw_data->>'dst_port')::int, 0),
			COALESCE(raw_data->>'protocol','tcp'),
			COALESCE(SUM((raw_data->>'bytes_sent')::bigint), 0),
			COUNT(*),
			COALESCE(raw_data->>'hostname',''),
			agent_id,
			MIN(time),
			MAX(time)
		FROM events
		WHERE event_type='network'
		  AND time >= $1
		GROUP BY raw_data->>'src_ip', raw_data->>'dst_ip', raw_data->>'dst_port',
		         raw_data->>'protocol', raw_data->>'hostname', agent_id
		ORDER BY COUNT(*) DESC
		LIMIT $2`,
		since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("netanalysis: top connections: %w", err)
	}
	defer rows.Close()

	var results []ConnectionSummary
	for rows.Next() {
		var cs ConnectionSummary
		var bytesSent int64
		if err := rows.Scan(
			&cs.SrcIP, &cs.DstIP, &cs.DstPort, &cs.Protocol,
			&bytesSent, &cs.PacketCount, &cs.Hostname,
			&cs.AgentID, &cs.FirstSeen, &cs.LastSeen,
		); err != nil {
			continue
		}
		cs.BytesSent = bytesSent
		cs.Duration = cs.LastSeen.Sub(cs.FirstSeen).Round(time.Second).String()
		cs.Flags = deriveFlags(cs.DstPort, cs.PacketCount)
		cs.ThreatScore = calculateThreatScore(cs.Flags)
		results = append(results, cs)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// GetPortAnalysis returns per-port statistics for network events in the past
// <hours> hours. Ports above 1024 that are not in the common set are flagged.
func (a *Analyzer) GetPortAnalysis(ctx context.Context, hours int) ([]PortStat, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := a.pool.Query(ctx, `
		SELECT
			COALESCE((raw_data->>'dst_port')::int, 0) AS port,
			COALESCE(raw_data->>'protocol','tcp')     AS protocol,
			COUNT(*)                              AS conn_count,
			COUNT(DISTINCT raw_data->>'src_ip')       AS unique_hosts
		FROM events
		WHERE event_type='network'
		  AND time >= $1
		  AND raw_data->>'dst_port' IS NOT NULL
		GROUP BY port, protocol
		ORDER BY conn_count DESC
		LIMIT 50`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("netanalysis: port analysis: %w", err)
	}
	defer rows.Close()

	var results []PortStat
	for rows.Next() {
		var ps PortStat
		if err := rows.Scan(&ps.Port, &ps.Protocol, &ps.ConnectionCount, &ps.UniqueHosts); err != nil {
			continue
		}
		ps.IsCommon = commonPorts[ps.Port]
		ps.RiskLevel = portRiskLevel(ps.Port, ps.IsCommon, ps.ConnectionCount)
		results = append(results, ps)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// GetBeaconingDetection finds destination IPs that connect with very regular
// intervals — a common indicator of C2 beaconing.
func (a *Analyzer) GetBeaconingDetection(ctx context.Context, hours int) ([]BeaconCandidate, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Two things were wrong with this query beyond the column name, and the
	// column name hid both — Postgres reports the first error it finds.
	//
	// It computed AVG(LEAD(ts) OVER (...) - ts), an aggregate containing a
	// window function, which Postgres rejects outright with 42803. The
	// statement could never have run, with any column name.
	//
	// And it measured STDDEV(ts) — the spread of the timestamps themselves —
	// against the mean interval. Regular beaconing spreads its timestamps
	// evenly across the whole window, so stddev_ts grows with the window while
	// the interval stays put: the more textbook the beacon, the further it sat
	// from tripping the "stddev < 0.15 × interval" test. Regularity is a
	// property of the gaps, so the gaps are what is measured now.
	//
	// STDDEV_POP over the observed gaps: this describes the series in hand
	// rather than estimating a population from a sample, and a perfectly
	// regular beacon lands on exactly 0.
	rows, err := a.pool.Query(ctx, `
		WITH per_conn AS (
			SELECT
				agent_id,
				raw_data->>'dst_ip' AS dst_ip,
				EXTRACT(EPOCH FROM time) AS ts
			FROM events
			WHERE event_type='network'
			  AND time >= $1
			  AND raw_data->>'dst_ip' IS NOT NULL
		),
		gaps AS (
			SELECT
				agent_id,
				dst_ip,
				LEAD(ts) OVER (PARTITION BY agent_id, dst_ip ORDER BY ts) - ts AS gap
			FROM per_conn
		),
		intervals AS (
			SELECT
				agent_id,
				dst_ip,
				COUNT(*) + 1        AS cnt,          -- n gaps means n+1 connections
				AVG(gap)            AS avg_interval,
				STDDEV_POP(gap)     AS stddev_gap
			FROM gaps
			WHERE gap IS NOT NULL
			GROUP BY agent_id, dst_ip
			HAVING COUNT(*) >= 4                     -- i.e. at least 5 connections
		)
		SELECT agent_id, dst_ip, avg_interval, cnt, stddev_gap
		FROM intervals
		WHERE avg_interval > 0
		  AND stddev_gap IS NOT NULL
		  AND stddev_gap < avg_interval * 0.15
		ORDER BY stddev_gap / avg_interval ASC
		LIMIT 20`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("netanalysis: beaconing detection: %w", err)
	}
	defer rows.Close()

	var results []BeaconCandidate
	for rows.Next() {
		var bc BeaconCandidate
		var stddev float64
		if err := rows.Scan(&bc.AgentID, &bc.DstIP, &bc.IntervalSecs, &bc.ConnectionCount, &stddev); err != nil {
			continue
		}
		// Confidence: lower std-dev relative to interval = higher confidence.
		if bc.IntervalSecs > 0 {
			bc.Confidence = 1.0 - (stddev / bc.IntervalSecs)
			if bc.Confidence < 0 {
				bc.Confidence = 0
			}
		}
		results = append(results, bc)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// NetworkStats holds top-level network activity counters.
type NetworkStats struct {
	TotalConnections int64 `json:"total_connections"`
	UniqueIPs        int64 `json:"unique_ips"`
	UniquePorts      int64 `json:"unique_ports"`
	ThreatsDetected  int64 `json:"threats_detected"`
}

// GetNetworkStats returns high-level network statistics for the past 24 hours.
func (a *Analyzer) GetNetworkStats(ctx context.Context, hours int) (NetworkStats, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	var stats NetworkStats

	// Both errors used to be discarded, so a failure left every counter at zero
	// and the dashboard rendered "no network activity" — the same thing a quiet
	// network looks like. They are returned now; the handler answers 500.
	if err := a.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(DISTINCT raw_data->>'dst_ip'),
			COUNT(DISTINCT (raw_data->>'dst_port')::int)
		FROM events
		WHERE event_type='network' AND time >= $1`,
		since,
	).Scan(&stats.TotalConnections, &stats.UniqueIPs, &stats.UniquePorts); err != nil {
		return NetworkStats{}, fmt.Errorf("netanalysis: network stats: %w", err)
	}

	// A simple proxy for threats: unusual ports (>1024 and not in common set)
	// with high connection counts.
	if err := a.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT raw_data->>'dst_port' AS p
			FROM events
			WHERE event_type='network' AND time >= $1
			  AND (raw_data->>'dst_port')::int > 1024
			GROUP BY p
			HAVING COUNT(*) > 100
		) sub`,
		since,
	).Scan(&stats.ThreatsDetected); err != nil {
		return NetworkStats{}, fmt.Errorf("netanalysis: threat proxy: %w", err)
	}

	return stats, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func deriveFlags(dstPort, packetCount int) []string {
	var flags []string
	if dstPort > 1024 && !commonPorts[dstPort] {
		flags = append(flags, "unusual_port")
	}
	if packetCount > 500 {
		flags = append(flags, "high_frequency")
	}
	return flags
}

func calculateThreatScore(flags []string) int {
	score := 0
	for _, f := range flags {
		switch f {
		case "tor_exit":
			score += 40
		case "known_c2":
			score += 50
		case "unusual_port":
			score += 20
		case "high_frequency":
			score += 15
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func portRiskLevel(port int, isCommon bool, count int) string {
	if isCommon {
		return "low"
	}
	if port > 1024 && count > 200 {
		return "high"
	}
	if port > 1024 {
		return "medium"
	}
	return "low"
}
