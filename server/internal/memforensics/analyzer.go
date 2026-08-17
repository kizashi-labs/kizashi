package memforensics

// Memory forensics analysis from agent-reported memory events
// (Analyzes memory-related events stored in DB, not direct memory access)

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MemoryArtifact represents a detected memory-based threat artifact.
type MemoryArtifact struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agent_id"`
	Hostname     string                 `json:"hostname"`
	ProcessName  string                 `json:"process_name"`
	PID          int                    `json:"pid"`
	ArtifactType string                 `json:"artifact_type"` // injected_dll/hollowed_process/shellcode/heap_spray/reflective_load
	Confidence   float64                `json:"confidence"`    // 0-1
	Indicators   []string               `json:"indicators"`
	MemoryRegion string                 `json:"memory_region"` // heap/stack/rwx_section/module
	RiskScore    int                    `json:"risk_score"`
	DetectedAt   time.Time              `json:"detected_at"`
	MITRETech    string                 `json:"mitre_tech"`
	RawData      map[string]interface{} `json:"raw_data"`
}

// MemForensicsStats holds aggregate statistics for memory forensics.
type MemForensicsStats struct {
	TotalArtifacts int            `json:"total_artifacts"`
	ByType         map[string]int `json:"by_type"`
	HighRiskCount  int            `json:"high_risk_count"`
	LastDetected   *time.Time     `json:"last_detected"`
}

// Analyzer performs memory forensics analysis on agent-reported events stored in the DB.
type Analyzer struct {
	pool *pgxpool.Pool
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(pool *pgxpool.Pool) *Analyzer {
	return &Analyzer{pool: pool}
}

// DetectInjection queries process events for suspicious patterns indicating code injection.
// It looks for:
//   - Processes with unusual parents (e.g., svchost spawned by non-services.exe)
//   - Processes with cmdline containing shellcode indicators (base64 blobs, hex strings)
//
// For each suspicious process it creates a MemoryArtifact with type "injected_dll" or
// "hollowed_process" and persists it to memory_artifacts.
func (a *Analyzer) DetectInjection(ctx context.Context, hours int) ([]*MemoryArtifact, error) {
	if a.pool == nil {
		return []*MemoryArtifact{}, nil
	}

	// Query process events looking for injection indicators.
	// Suspicious patterns:
	//  1. svchost.exe not spawned by services.exe or svchost.exe
	//  2. cmdline containing large base64 or hex-encoded blobs (shellcode patterns)
	//
	// events の実際の列は event_id / time (migration 002)。id / created_at は存在せず、
	// このクエリは毎回失敗していた。err は空スライスに変換されるため、メモリ
	// フォレンジクスは常に「検出 0 件」に見えていた。間隔も make_interval で組む:
	// ($1 || ' hours')::interval は $1 を text 推論させ、pgx が int の hours を
	// エンコードできず失敗する。
	rows, err := a.pool.Query(ctx, `
		SELECT
			e.event_id,
			e.agent_id,
			COALESCE(a.hostname, ''),
			COALESCE(e.raw_data->>'process_name', ''),
			COALESCE((e.raw_data->>'pid')::int, 0),
			COALESCE(e.raw_data->>'parent_name', ''),
			COALESCE(e.raw_data->>'command_line', ''),
			e.time,
			e.raw_data
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE e.event_type = 'process'
		  AND e.time > NOW() - make_interval(hours => $1)
		  AND (
		      -- svchost spawned by non-services parent
		      (lower(e.raw_data->>'process_name') = 'svchost.exe'
		       AND lower(e.raw_data->>'parent_name') NOT IN ('services.exe','svchost.exe','')
		      )
		      OR
		      -- cmdline with hex shellcode-like pattern (>\x40 hex chars)
		      (e.raw_data->>'command_line' ~ '[0-9a-fA-F]{80,}')
		      OR
		      -- cmdline with large base64 blob
		      (e.raw_data->>'command_line' ~ '[A-Za-z0-9+/]{100,}={0,2}')
		  )
		ORDER BY e.time DESC
		LIMIT 500`,
		hours,
	)
	if err != nil {
		slog.Warn("memforensics: DetectInjection query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	var artifacts []*MemoryArtifact
	for rows.Next() {
		var (
			id, agentID, hostname, processName, parentProcess, cmdline string
			pid                                                        int
			createdAt                                                  time.Time
			rawData                                                    map[string]interface{}
		)
		if err := rows.Scan(&id, &agentID, &hostname, &processName, &pid,
			&parentProcess, &cmdline, &createdAt, &rawData); err != nil {
			continue
		}

		artifactType := "hollowed_process"
		indicators := []string{}
		confidence := 0.6
		mitreTech := "T1055"

		if processName == "svchost.exe" && parentProcess != "services.exe" && parentProcess != "svchost.exe" {
			artifactType = "injected_dll"
			indicators = append(indicators, "unusual_parent:"+parentProcess)
			confidence = 0.75
			mitreTech = "T1055.001"
		}
		if len(cmdline) > 80 {
			indicators = append(indicators, "shellcode_in_cmdline")
			confidence = 0.85
			artifactType = "shellcode"
			mitreTech = "T1059"
		}

		riskScore := int(confidence * 100)

		art := &MemoryArtifact{
			AgentID:      agentID,
			Hostname:     hostname,
			ProcessName:  processName,
			PID:          pid,
			ArtifactType: artifactType,
			Confidence:   confidence,
			Indicators:   indicators,
			MemoryRegion: "rwx_section",
			RiskScore:    riskScore,
			DetectedAt:   createdAt,
			MITRETech:    mitreTech,
			RawData:      rawData,
		}

		// Persist to memory_artifacts and get the generated ID.
		var insertedID string
		insertErr := a.pool.QueryRow(ctx, `
			INSERT INTO memory_artifacts
				(agent_id, hostname, process_name, pid, artifact_type, confidence,
				 indicators, memory_region, risk_score, detected_at, mitre_tech, raw_data)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			agentID, hostname, processName, pid, artifactType, confidence,
			indicators, "rwx_section", riskScore, createdAt, mitreTech, rawData,
		).Scan(&insertedID)
		if insertErr != nil {
			// Use original event ID as fallback.
			art.ID = id
		} else {
			art.ID = insertedID
		}

		artifacts = append(artifacts, art)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if artifacts == nil {
		return []*MemoryArtifact{}, nil
	}
	return artifacts, nil
}

// DetectReflectiveLoad looks for processes loading modules from unusual paths
// (not in System32 or SysWOW64).
func (a *Analyzer) DetectReflectiveLoad(ctx context.Context, hours int) ([]*MemoryArtifact, error) {
	if a.pool == nil {
		return []*MemoryArtifact{}, nil
	}

	// DetectInjection と同じ列名・間隔の取り違えがあり、常に 0 件だった。
	//
	// さらに二重に届いていなかった。event_type 'module_load' は
	// events_event_type_check が許可しない値で、そもそも該当行が存在し得ない。
	// ingestion が付ける型は 'image_load'、モジュールのパスを入れるキーは
	// 'image_loaded' (ImageLoadEvent.image_path を正規化時に改名している)。
	// 型・キーのどちらか一方だけ直しても 0 件のままなので、両方を直す。
	rows, err := a.pool.Query(ctx, `
		SELECT
			e.event_id,
			e.agent_id,
			COALESCE(a.hostname, ''),
			COALESCE(e.raw_data->>'process_name', ''),
			COALESCE((e.raw_data->>'pid')::int, 0),
			COALESCE(e.raw_data->>'image_loaded', ''),
			e.time,
			e.raw_data
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE e.event_type = 'image_load'
		  AND e.time > NOW() - make_interval(hours => $1)
		  AND e.raw_data ? 'image_loaded'
		  AND e.raw_data->>'image_loaded' <> ''
		  AND lower(e.raw_data->>'image_loaded') NOT LIKE '%\\system32\\%'
		  AND lower(e.raw_data->>'image_loaded') NOT LIKE '%\\syswow64\\%'
		  AND lower(e.raw_data->>'image_loaded') NOT LIKE '%/system32/%'
		  AND lower(e.raw_data->>'image_loaded') NOT LIKE '%/syswow64/%'
		ORDER BY e.time DESC
		LIMIT 500`,
		hours,
	)
	if err != nil {
		slog.Warn("memforensics: DetectReflectiveLoad query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	var artifacts []*MemoryArtifact
	for rows.Next() {
		var (
			id, agentID, hostname, processName, loadedModule string
			pid                                              int
			createdAt                                        time.Time
			rawData                                          map[string]interface{}
		)
		if err := rows.Scan(&id, &agentID, &hostname, &processName, &pid,
			&loadedModule, &createdAt, &rawData); err != nil {
			continue
		}

		indicators := []string{"module_from_unusual_path:" + loadedModule}
		confidence := 0.7
		riskScore := 70

		art := &MemoryArtifact{
			AgentID:      agentID,
			Hostname:     hostname,
			ProcessName:  processName,
			PID:          pid,
			ArtifactType: "reflective_load",
			Confidence:   confidence,
			Indicators:   indicators,
			MemoryRegion: "module",
			RiskScore:    riskScore,
			DetectedAt:   createdAt,
			MITRETech:    "T1620",
			RawData:      rawData,
		}

		var insertedID string
		insertErr := a.pool.QueryRow(ctx, `
			INSERT INTO memory_artifacts
				(agent_id, hostname, process_name, pid, artifact_type, confidence,
				 indicators, memory_region, risk_score, detected_at, mitre_tech, raw_data)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			agentID, hostname, processName, pid, "reflective_load", confidence,
			indicators, "module", riskScore, createdAt, "T1620", rawData,
		).Scan(&insertedID)
		if insertErr != nil {
			art.ID = id
		} else {
			art.ID = insertedID
		}

		artifacts = append(artifacts, art)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if artifacts == nil {
		return []*MemoryArtifact{}, nil
	}
	return artifacts, nil
}

// GetArtifacts returns persisted memory artifacts for a given agent and time window.
func (a *Analyzer) GetArtifacts(ctx context.Context, agentID string, hours int) ([]*MemoryArtifact, error) {
	if a.pool == nil {
		return []*MemoryArtifact{}, nil
	}

	query := `
		SELECT id, COALESCE(agent_id::text,''), COALESCE(hostname,''),
		       COALESCE(process_name,''), COALESCE(pid,0),
		       COALESCE(artifact_type,''), COALESCE(confidence,0),
		       COALESCE(indicators,'{}'), COALESCE(memory_region,''),
		       COALESCE(risk_score,0), detected_at,
		       COALESCE(mitre_tech,''), COALESCE(raw_data,'{}')
		FROM memory_artifacts
		WHERE detected_at > NOW() - make_interval(hours => $1)`
	args := []interface{}{hours}

	if agentID != "" {
		query += " AND agent_id = $2"
		args = append(args, agentID)
	}
	query += " ORDER BY detected_at DESC LIMIT 1000"

	rows, err := a.pool.Query(ctx, query, args...)
	if err != nil {
		slog.Warn("memforensics: GetArtifacts query failed", "error", err)
		return nil, err
	}
	defer rows.Close()

	var artifacts []*MemoryArtifact
	for rows.Next() {
		art := &MemoryArtifact{}
		var indicators []string
		if err := rows.Scan(
			&art.ID, &art.AgentID, &art.Hostname,
			&art.ProcessName, &art.PID,
			&art.ArtifactType, &art.Confidence,
			&indicators, &art.MemoryRegion,
			&art.RiskScore, &art.DetectedAt,
			&art.MITRETech, &art.RawData,
		); err != nil {
			continue
		}
		art.Indicators = indicators
		artifacts = append(artifacts, art)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if artifacts == nil {
		return []*MemoryArtifact{}, nil
	}
	return artifacts, nil
}

// GetStats returns aggregate statistics for memory artifacts.
func (a *Analyzer) GetStats(ctx context.Context) MemForensicsStats {
	stats := MemForensicsStats{
		ByType: map[string]int{},
	}
	if a.pool == nil {
		return stats
	}

	// Total count.
	_ = a.pool.QueryRow(ctx, `SELECT COUNT(*) FROM memory_artifacts`).Scan(&stats.TotalArtifacts)

	// High risk count (risk_score >= 70).
	_ = a.pool.QueryRow(ctx, `SELECT COUNT(*) FROM memory_artifacts WHERE risk_score >= 70`).Scan(&stats.HighRiskCount)

	// Last detected.
	var lastDetected time.Time
	if err := a.pool.QueryRow(ctx, `SELECT MAX(detected_at) FROM memory_artifacts`).Scan(&lastDetected); err == nil && !lastDetected.IsZero() {
		stats.LastDetected = &lastDetected
	}

	// By type breakdown.
	rows, err := a.pool.Query(ctx, `SELECT artifact_type, COUNT(*) FROM memory_artifacts GROUP BY artifact_type`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var typeName string
			var count int
			if err := rows.Scan(&typeName, &count); err == nil {
				stats.ByType[typeName] = count
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("メモリフォレンジックの集計が途中で終わりました。統計は実際より小さく出ます", "error", err)
		}
	}

	return stats
}
