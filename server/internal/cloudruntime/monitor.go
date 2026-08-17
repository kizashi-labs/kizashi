package cloudruntime

// Cloud workload and container runtime protection

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RuntimeThreat represents a detected threat in a container/cloud workload runtime.
type RuntimeThreat struct {
	ID            string    `json:"id"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	ImageName     string    `json:"image_name"`
	AgentID       string    `json:"agent_id"`
	ThreatType    string    `json:"threat_type"` // privilege_escalation/container_escape/crypto_mining/unusual_process/network_scan
	Description   string    `json:"description"`
	Severity      int       `json:"severity"`
	Blocked       bool      `json:"blocked"`
	MITRETech     string    `json:"mitre_tech"`
	DetectedAt    time.Time `json:"detected_at"`
	ProcessName   string    `json:"process_name"`
	CmdLine       string    `json:"cmdline"`
}

// RuntimeStats holds aggregate statistics for runtime threats.
type RuntimeStats struct {
	TotalThreats        int            `json:"total_threats"`
	ByType              map[string]int `json:"by_type"`
	ContainersMonitored int            `json:"containers_monitored"`
	BlockedCount        int            `json:"blocked_count"`
}

// Monitor detects runtime threats in container and cloud workload events stored in the DB.
type Monitor struct {
	pool *pgxpool.Pool
}

// NewMonitor creates a new Monitor.
func NewMonitor(pool *pgxpool.Pool) *Monitor {
	return &Monitor{pool: pool}
}

// DetectRuntimeThreats queries container security events for runtime threats:
//   - Privileged container with shell spawn
//   - Container with host network + unusual process
//   - Crypto miner indicators (xmrig, minerd, cryptonight in cmdline/process_name)
//   - Container escape via /proc/1/root access
func (m *Monitor) DetectRuntimeThreats(ctx context.Context, hours int) ([]*RuntimeThreat, error) {
	if m.pool == nil {
		return []*RuntimeThreat{}, nil
	}

	// events の実際の列は event_id / time (migration 002)。id / created_at は存在せず、
	// このクエリは毎回失敗していた。err は下で空スライスに変換されるため、
	// コンテナランタイム脅威は常に「検出 0 件」に見えていた。
	// 間隔も make_interval(hours => $1) で組む: ($1 || ' hours')::interval は $1 を
	// text 推論させ、pgx が int の hours をエンコードできず実行時に失敗する。
	//
	// 型とキーにも取り違えがあった。
	//
	// event_type は IN ('container_event', 'process', 'container_process') だった。
	// container_event と container_process はどちらも events_event_type_check が
	// 許可しない値で、該当行は永久に存在しない。実際に一致し得たのは 'process'
	// だけで、そこは残す — コンテナ内のプロセスもプロセスイベントとして届く。
	//
	// そしてコマンドラインを 'cmdline' で読んでいた。ingestion が書くのは
	// 'command_line'。クリプトマイナー検知 (xmrig/stratum+tcp/cryptonight) と
	// コンテナ脱出検知 (/proc/1/root) はこのキーだけで判定するので、両方とも
	// 一度も発火していない。この2つは通常のプロセスイベントで判定できるため、
	// キー名を直すだけで機能する。
	//
	// 一方 privileged / host_network / container_id / container_name / image_name
	// はエージェントが収集していなかった。前3者はエンドポイントの /proc から
	// 導出できるようになった (agent/internal/collector/container.go)。
	// container_name / image_name はコンテナランタイムAPIが必要で、まだ無い。
	rows, err := m.pool.Query(ctx, `
		SELECT
			e.event_id,
			COALESCE(e.raw_data->>'container_id', ''),
			COALESCE(e.raw_data->>'container_name', ''),
			COALESCE(e.raw_data->>'image_name', ''),
			COALESCE(e.agent_id::text, ''),
			COALESCE(e.raw_data->>'process_name', ''),
			COALESCE(e.raw_data->>'command_line', ''),
			COALESCE((e.raw_data->>'privileged')::boolean, false),
			COALESCE((e.raw_data->>'host_network')::boolean, false),
			e.time,
			e.raw_data
		FROM events e
		WHERE e.event_type = 'process'
		  AND e.time > NOW() - make_interval(hours => $1)
		  AND (
		      -- Crypto miner indicators
		      (lower(e.raw_data->>'process_name') IN ('xmrig','minerd','cryptonight','nbminer','t-rex','phoenixminer'))
		      OR
		      (lower(e.raw_data->>'command_line') LIKE '%xmrig%'
		       OR lower(e.raw_data->>'command_line') LIKE '%stratum+tcp%'
		       OR lower(e.raw_data->>'command_line') LIKE '%cryptonight%'
		      )
		      OR
		      -- Container escape via /proc/1/root
		      (e.raw_data->>'command_line' LIKE '%/proc/1/root%')
		      OR
		      -- Privileged container with shell
		      ((e.raw_data->>'privileged')::boolean = true
		       AND lower(e.raw_data->>'process_name') IN ('bash','sh','zsh','dash')
		      )
		      OR
		      -- Host network with unusual process
		      ((e.raw_data->>'host_network')::boolean = true
		       AND lower(e.raw_data->>'process_name') NOT IN ('nginx','apache2','node','python','java','')
		      )
		  )
		ORDER BY e.time DESC
		LIMIT 500`,
		hours,
	)
	if err != nil {
		slog.Warn("cloudruntime: DetectRuntimeThreats query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	var threats []*RuntimeThreat
	for rows.Next() {
		var (
			id, containerID, containerName, imageName string
			agentID, processName, cmdline             string
			privileged, hostNetwork                   bool
			createdAt                                 time.Time
			rawData                                   map[string]interface{}
		)
		if err := rows.Scan(
			&id, &containerID, &containerName, &imageName,
			&agentID, &processName, &cmdline,
			&privileged, &hostNetwork,
			&createdAt, &rawData,
		); err != nil {
			continue
		}

		threatType, description, mitreTech, severity := classifyRuntimeThreat(
			processName, cmdline, privileged, hostNetwork,
		)

		threat := &RuntimeThreat{
			ID:            id,
			ContainerID:   containerID,
			ContainerName: containerName,
			ImageName:     imageName,
			AgentID:       agentID,
			ThreatType:    threatType,
			Description:   description,
			Severity:      severity,
			Blocked:       false,
			MITRETech:     mitreTech,
			DetectedAt:    createdAt,
			ProcessName:   processName,
			CmdLine:       cmdline,
		}
		threats = append(threats, threat)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if threats == nil {
		return []*RuntimeThreat{}, nil
	}
	return threats, nil
}

// classifyRuntimeThreat determines threat type, description, MITRE technique, and severity.
func classifyRuntimeThreat(processName, cmdline string, privileged, hostNetwork bool) (string, string, string, int) {
	lowerProc := processName
	lowerCmd := cmdline

	// Crypto mining
	cryptoProcs := map[string]bool{
		"xmrig": true, "minerd": true, "cryptonight": true,
		"nbminer": true, "t-rex": true, "phoenixminer": true,
	}
	if cryptoProcs[lowerProc] || containsAny(lowerCmd, []string{"xmrig", "stratum+tcp", "cryptonight"}) {
		return "crypto_mining",
			"Cryptocurrency miner detected in container: " + processName,
			"T1496", 8
	}

	// Container escape
	if containsAny(lowerCmd, []string{"/proc/1/root"}) {
		return "container_escape",
			"Possible container escape attempt via /proc/1/root",
			"T1611", 9
	}

	// Privilege escalation via privileged container + shell
	if privileged && (lowerProc == "bash" || lowerProc == "sh" || lowerProc == "zsh" || lowerProc == "dash") {
		return "privilege_escalation",
			"Shell spawned in privileged container: " + processName,
			"T1078", 7
	}

	// Unusual process with host network
	if hostNetwork {
		return "unusual_process",
			"Unusual process running with host network access: " + processName,
			"T1205", 6
	}

	return "unusual_process", "Unusual container process: " + processName, "T1059", 5
}

// containsAny checks if s contains any of the given substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// GetRuntimeStats returns aggregate statistics for runtime threats.
func (m *Monitor) GetRuntimeStats(ctx context.Context) RuntimeStats {
	stats := RuntimeStats{
		ByType: map[string]int{},
	}
	if m.pool == nil {
		return stats
	}

	// Count total container events with threats in last 30d.
	//
	// 上と同じく、存在し得ない event_type ('container_event' / 'container_process')
	// を並べていた。コンテナ内のプロセスは 'process' イベントとして届き、
	// container_id はそこに載る。
	_ = m.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT e.event_id) FROM events e
		WHERE e.event_type = 'process'
		  AND e.time > NOW() - INTERVAL '30 days'
		  AND (
		      lower(e.raw_data->>'process_name') IN ('xmrig','minerd','cryptonight','nbminer','t-rex')
		      OR e.raw_data->>'command_line' LIKE '%/proc/1/root%'
		      OR ((e.raw_data->>'privileged')::boolean = true
		          AND lower(e.raw_data->>'process_name') IN ('bash','sh','zsh'))
		  )`,
	).Scan(&stats.TotalThreats)

	// Containers monitored (distinct container IDs in last 30d).
	_ = m.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT e.raw_data->>'container_id')
		FROM events e
		WHERE e.event_type = 'process'
		  AND e.time > NOW() - INTERVAL '30 days'
		  AND e.raw_data ? 'container_id'
		  AND e.raw_data->>'container_id' <> ''`,
	).Scan(&stats.ContainersMonitored)

	return stats
}

// ListThreats returns detected runtime threats for the given time window.
func (m *Monitor) ListThreats(ctx context.Context, hours int) ([]*RuntimeThreat, error) {
	return m.DetectRuntimeThreats(ctx, hours)
}
