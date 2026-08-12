package behavioral

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// ProcessEntry は typical_processes の1エントリ。
type ProcessEntry struct {
	Name      string  `json:"name"`
	Frequency float64 `json:"frequency"`
	IsRare    bool    `json:"is_rare"`
}

// NetworkDest は typical_destinations の1エントリ。
type NetworkDest struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	VolumeMB float64 `json:"volume_mb"`
}

// Deviation は recent_deviations の1エントリ。
type Deviation struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	DetectedAt  string `json:"detected_at"`
}

// BuildEnrichedBaseline クエリを使って agent_id に対応するリッチなベースラインを構築する。
func (e *Engine) BuildEnrichedBaseline(
	ctx context.Context,
	agentID string,
	lookbackDays int,
	exclusionRules json.RawMessage,
) (*store.EndpointBaseline, error) {
	if lookbackDays <= 0 {
		lookbackDays = 30
	}

	since := time.Now().AddDate(0, 0, -lookbackDays)

	// ─── データポイント数 ──────────────────────────────────────────
	var dataPoints int64
	_ = e.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND time >= $2
	`, agentID, since).Scan(&dataPoints)

	// ─── アクティビティヒートマップ (7日 × 24時間) ─────────────────
	activeHours := buildHeatmap(ctx, e, agentID)

	// ─── 典型的プロセス (top 50) ──────────────────────────────────
	typicalProcesses, err := buildTypicalProcesses(ctx, e, agentID, since)
	if err != nil {
		typicalProcesses = []ProcessEntry{}
	}

	// ─── 典型的ネットワーク宛先 (top 30) ─────────────────────────
	typicalDests, err := buildTypicalDests(ctx, e, agentID, since)
	if err != nil {
		typicalDests = []NetworkDest{}
	}

	// ─── 典型的ディレクトリ (top 20) ────────────────────────────
	typicalDirs, err := buildTypicalDirs(ctx, e, agentID, since)
	if err != nil {
		typicalDirs = []string{}
	}

	// ─── 最近の逸脱 ───────────────────────────────────────────────
	recentDevs, err := buildRecentDeviations(ctx, e, agentID)
	if err != nil {
		recentDevs = []Deviation{}
	}

	// ─── 信頼スコアとステータス ───────────────────────────────────
	// targetPoints = lookbackDays × 24h × 100events/h (目標値)
	targetPoints := int64(lookbackDays) * 24 * 100
	confidenceScore := int(math.Min(100, float64(dataPoints)/float64(targetPoints)*100))

	anomalyCount := len(recentDevs)

	var status string
	switch {
	case confidenceScore < 20:
		status = "insufficient_data"
	case confidenceScore < 70:
		status = "learning"
	case anomalyCount > 3:
		status = "anomalous"
	default:
		status = "established"
	}

	// ─── JSON変換 ─────────────────────────────────────────────────
	hoursJSON, _ := json.Marshal(activeHours)
	procsJSON, _ := json.Marshal(typicalProcesses)
	destsJSON, _ := json.Marshal(typicalDests)
	dirsJSON, _ := json.Marshal(typicalDirs)
	devsJSON, _ := json.Marshal(recentDevs)

	if exclusionRules == nil {
		exclusionRules = json.RawMessage("[]")
	}

	return &store.EndpointBaseline{
		ID:                  agentID,
		BaselineStatus:      status,
		LearningStarted:     time.Now().AddDate(0, 0, -lookbackDays).Format(time.RFC3339),
		DataPointsCollected: dataPoints,
		LastUpdated:         time.Now().Format(time.RFC3339),
		AnomalyCount:        anomalyCount,
		ConfidenceScore:     confidenceScore,
		ActiveHours:         json.RawMessage(hoursJSON),
		TypicalProcesses:    json.RawMessage(procsJSON),
		TypicalDestinations: json.RawMessage(destsJSON),
		TypicalDirectories:  json.RawMessage(dirsJSON),
		RecentDeviations:    json.RawMessage(devsJSON),
		ExclusionRules:      exclusionRules,
	}, nil
}

// buildHeatmap は直近7日間のイベントを (曜日 × 時間) でカウントし 0-100 に正規化した配列を返す。
func buildHeatmap(ctx context.Context, e *Engine, agentID string) [7][24]int {
	var matrix [7][24]int

	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	rows, err := e.pool.Query(ctx, `
		SELECT EXTRACT(DOW FROM time)::int  AS dow,
		       EXTRACT(HOUR FROM time)::int AS hr,
		       COUNT(*)                     AS cnt
		FROM events
		WHERE agent_id = $1::uuid
		  AND time >= $2
		GROUP BY dow, hr
	`, agentID, sevenDaysAgo)
	if err != nil {
		return matrix
	}
	defer rows.Close()

	var maxVal int
	for rows.Next() {
		var dow, hr, cnt int
		if err := rows.Scan(&dow, &hr, &cnt); err != nil {
			continue
		}
		if dow >= 0 && dow < 7 && hr >= 0 && hr < 24 {
			matrix[dow][hr] = cnt
			if cnt > maxVal {
				maxVal = cnt
			}
		}
	}

	// 0-100 に正規化
	if maxVal > 0 {
		for d := range matrix {
			for h := range matrix[d] {
				matrix[d][h] = int(float64(matrix[d][h]) / float64(maxVal) * 100)
			}
		}
	}
	return matrix
}

// buildTypicalProcesses は上位50プロセスを頻度付きで返す。
func buildTypicalProcesses(ctx context.Context, e *Engine, agentID string, since time.Time) ([]ProcessEntry, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT raw_data->>'process_name' AS pname,
		       COUNT(*)                  AS cnt
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND time >= $2
		  AND raw_data->>'process_name' IS NOT NULL
		GROUP BY pname
		ORDER BY cnt DESC
		LIMIT 50
	`, agentID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var total int64
	type row struct {
		name string
		cnt  int64
	}
	var rawRows []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.cnt); err != nil {
			continue
		}
		rawRows = append(rawRows, r)
		total += r.cnt
	}

	if total == 0 {
		return []ProcessEntry{}, nil
	}

	entries := make([]ProcessEntry, 0, len(rawRows))
	for _, r := range rawRows {
		freq := float64(r.cnt) / float64(total) * 100
		entries = append(entries, ProcessEntry{
			Name:      r.name,
			Frequency: math.Round(freq*10) / 10,
			IsRare:    freq < 5,
		})
	}
	return entries, nil
}

// buildTypicalDests は上位30ネットワーク宛先を返す。
func buildTypicalDests(ctx context.Context, e *Engine, agentID string, since time.Time) ([]NetworkDest, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(hostname,''), dst_ip::text) AS host,
		       dst_port,
		       COALESCE(NULLIF(protocol,''), 'TCP')        AS proto,
		       SUM(bytes_sent + bytes_recv)::float8 / 1048576.0 AS volume_mb
		FROM network_connections
		WHERE agent_id = $1::uuid
		  AND time >= $2
		GROUP BY host, dst_port, proto
		ORDER BY volume_mb DESC
		LIMIT 30
	`, agentID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []NetworkDest
	for rows.Next() {
		var d NetworkDest
		var vol float64
		if err := rows.Scan(&d.Host, &d.Port, &d.Protocol, &vol); err != nil {
			continue
		}
		d.VolumeMB = math.Round(vol*100) / 100
		entries = append(entries, d)
	}
	return entries, nil
}

// buildTypicalDirs は上位20ディレクトリを返す。
func buildTypicalDirs(ctx context.Context, e *Engine, agentID string, since time.Time) ([]string, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT
		    regexp_replace(
		        raw_data->>'file_path',
		        '[^/\\]*$', ''
		    ) AS dir
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'file'
		  AND time >= $2
		  AND raw_data->>'file_path' IS NOT NULL
		ORDER BY dir
		LIMIT 20
	`, agentID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dirs []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			continue
		}
		if strings.TrimSpace(d) != "" {
			dirs = append(dirs, d)
		}
	}
	return dirs, nil
}

// buildRecentDeviations は anomaly_scores テーブルから最近の逸脱を返す。
func buildRecentDeviations(ctx context.Context, e *Engine, agentID string) ([]Deviation, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT id::text, process_name, z_score, detected_at
		FROM anomaly_scores
		WHERE agent_id = $1::uuid
		ORDER BY detected_at DESC
		LIMIT 20
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devs []Deviation
	for rows.Next() {
		var id, processName string
		var zScore float64
		var detectedAt time.Time
		if err := rows.Scan(&id, &processName, &zScore, &detectedAt); err != nil {
			continue
		}
		devs = append(devs, Deviation{
			ID:          id,
			Category:    "Process",
			Description: fmt.Sprintf("異常プロセス検知: %s (z=%.2f)", processName, zScore),
			Severity:    zScoreToSeverity(zScore),
			DetectedAt:  detectedAt.Format(time.RFC3339),
		})
	}
	return devs, nil
}

func zScoreToSeverity(z float64) string {
	switch {
	case z >= 9:
		return "critical"
	case z >= 6:
		return "high"
	case z >= 4:
		return "medium"
	default:
		return "low"
	}
}
