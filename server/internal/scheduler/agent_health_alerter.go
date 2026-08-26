package scheduler

// AgentHealthAlerter monitors agent health metrics and generates alerts
// when agents exceed configured thresholds.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	healthCheckInterval = 5 * time.Minute

	// cpuThreshold is the percentage above which a CPU alert is raised.
	cpuThreshold = 90.0
	// memThreshold is the percentage above which a memory alert is raised.
	memThreshold = 85.0
	// staleThreshold is how long an agent can be silent while still marked online
	// before being considered stale.
	staleThreshold = 10 * time.Minute
	// dedupWindow is the look-back window used to suppress duplicate alerts.
	dedupWindow = 1 * time.Hour
	// degradedSensorDedupWindow is longer because a blind sensor is a standing
	// condition, not a spike: it stays true until someone redeploys the agent.
	// Re-raising it hourly would teach operators to filter the alert away, which
	// is the outcome this alarm exists to prevent.
	degradedSensorDedupWindow = 24 * time.Hour

	// degradedSensorTitleSuffix identifies the degraded-sensor alert without
	// depending on the hostname its title embeds. Used both to build the title and
	// to find the alert again when the sensor comes back.
	degradedSensorTitleSuffix = " センサー降格（検知能力低下）"
)

// AgentHealthAlerter monitors online agents and creates alerts for health issues.
type AgentHealthAlerter struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewAgentHealthAlerter creates an AgentHealthAlerter.
func NewAgentHealthAlerter(pool *pgxpool.Pool, nc *nats.Conn) *AgentHealthAlerter {
	return &AgentHealthAlerter{pool: pool, nc: nc}
}

// Run starts the 5-minute health-check ticker. Designed to be called as a goroutine.
func (a *AgentHealthAlerter) Run(ctx context.Context) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	slog.Info("エージェントヘルスアラーター起動")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "agent_health_alerter", a.checkHealth)
		}
	}
}

// healthIssue holds a detected health problem for one agent.
type healthIssue struct {
	agentID     string
	hostname    string
	description string
	// title is the alert title. It doubles as the dedup identity, so a CPU spike
	// and a blind sensor no longer suppress each other — they did while every
	// issue shared one title, which would have hidden the sensor alarm behind
	// routine load noise.
	title string
	// dedupFor is how long an identical title stays suppressed for this agent.
	dedupFor time.Duration
}

// checkHealth queries for agent health problems and creates alerts where needed.
func (a *AgentHealthAlerter) checkHealth(ctx context.Context) {
	var issues []healthIssue

	// ── 1. High CPU / memory from settings JSONB ─────────────────────────
	// The agents table may carry a settings JSONB column that agents populate
	// with runtime metrics. We query it only when the column is present; the
	// query is wrapped in a DO block so it fails silently on missing column.
	cpuMemIssues := a.checkCPUMemory(ctx)
	issues = append(issues, cpuMemIssues...)

	// ── 2. Stale agents (online but last_seen older than staleThreshold) ──
	staleIssues := a.checkStaleAgents(ctx)
	issues = append(issues, staleIssues...)

	// ── 3. Sensors degraded to polling ───────────────────────────────────
	issues = append(issues, a.checkDegradedSensors(ctx)...)

	// ── 4. Create alerts (with dedup) ─────────────────────────────────────
	for _, issue := range issues {
		a.maybeCreateAlert(ctx, issue)
	}

	// ── 5. Close sensor alerts whose condition has gone away ─────────────
	a.resolveRecoveredSensorAlerts(ctx)
}

// resolveRecoveredSensorAlerts closes degraded-sensor alerts for agents that are no
// longer degraded.
//
// Every other issue this alerter raises is transient and self-describing: a CPU
// spike stops being re-raised once load drops, and the stale alert is answered by
// the agent checking in. The sensor alert is different — it is a standing condition
// with a 24h dedup, so the alert it leaves behind is a claim about the present
// ("this endpoint is blind"), not a record of a moment. Redeploying the agent fixes
// the endpoint but nothing touched the alert, so the queue kept asserting a
// degradation that no longer existed. An alarm that stays lit after the fix is how
// operators learn to ignore it — the same failure mode the 24h dedup exists to
// avoid.
//
// Scope is deliberately narrow:
//   - only this alert's own title suffix, matched independently of the hostname
//     embedded in the title (a renamed host must still resolve);
//   - only open/investigating; an analyst who already marked it resolved or
//     false_positive keeps their verdict;
//   - status 'auto_resolved' rather than 'resolved', so the console can tell a
//     machine-closed alert from a human-closed one.
//
// Agents that went offline while degraded keep telemetry_mode = 'poll' and are
// therefore left alone: the condition was never observed to change.
func (a *AgentHealthAlerter) resolveRecoveredSensorAlerts(ctx context.Context) {
	rows, err := a.pool.Query(ctx,
		`UPDATE alerts a
		    SET status = 'auto_resolved', resolved_at = NOW()
		  WHERE a.status IN ('open', 'investigating')
		    AND a.title LIKE '%' || $1
		    AND EXISTS (
		          SELECT 1 FROM agents ag
		           WHERE ag.id = a.agent_id
		             AND ag.telemetry_mode IS DISTINCT FROM 'poll'
		        )
		RETURNING a.id::text, a.title`,
		degradedSensorTitleSuffix)
	if err != nil {
		// telemetry_mode missing (migration 357/365 not yet applied) — the alert
		// cannot have been raised either, so there is nothing to close.
		slog.Debug("センサー復旧チェックをスキップ", "error", err)
		return
	}
	defer rows.Close()

	var closed int
	for rows.Next() {
		var id, title string
		if scanErr := rows.Scan(&id, &title); scanErr != nil {
			continue
		}
		closed++
		slog.Info("センサー復旧によりアラートを自動クローズしました", "alert_id", id, "title", title)
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "センサー復旧の走査が途中で終わりました。閉じ切れていないアラートが残ります")
	}
	if closed > 0 {
		slog.Info("センサー降格アラートを自動クローズしました", "件数", closed)
	}
}

// checkCPUMemory queries online agents whose last heartbeat reported high CPU
// or memory usage. cpu_usage is a percentage; memory arrives as absolute MB and
// is converted to a percentage of total_memory_mb. Agents that have not yet
// reported metrics (metrics_updated_at IS NULL) are excluded.
func (a *AgentHealthAlerter) checkCPUMemory(ctx context.Context) []healthIssue {
	rows, err := a.pool.Query(ctx,
		`SELECT id::text, hostname,
		        COALESCE(cpu_usage, 0) AS cpu,
		        CASE WHEN COALESCE(total_memory_mb, 0) > 0
		             THEN COALESCE(memory_usage_mb, 0) / total_memory_mb * 100
		             ELSE 0 END AS mem
		 FROM agents
		 WHERE status = 'online'
		   AND metrics_updated_at IS NOT NULL
		   AND (
		       COALESCE(cpu_usage, 0) > $1
		    OR (COALESCE(total_memory_mb, 0) > 0
		        AND COALESCE(memory_usage_mb, 0) / total_memory_mb * 100 > $2)
		   )
		 LIMIT 50`,
		cpuThreshold, memThreshold,
	)
	if err != nil {
		// The column likely doesn't exist yet — degrade gracefully.
		fail(ctx, err, "CPU/メモリヘルスチェックをスキップ")
		return nil
	}
	defer rows.Close()

	var issues []healthIssue
	for rows.Next() {
		var id, hostname string
		var cpu, mem float64
		if scanErr := rows.Scan(&id, &hostname, &cpu, &mem); scanErr != nil {
			continue
		}
		var desc string
		if cpu > cpuThreshold && mem > memThreshold {
			desc = fmt.Sprintf("CPU使用率 %.1f%% (閾値: %.0f%%)、メモリ使用率 %.1f%% (閾値: %.0f%%) が高い状態です。",
				cpu, cpuThreshold, mem, memThreshold)
		} else if cpu > cpuThreshold {
			desc = fmt.Sprintf("CPU使用率 %.1f%% が閾値 %.0f%% を超えています。", cpu, cpuThreshold)
		} else {
			desc = fmt.Sprintf("メモリ使用率 %.1f%% が閾値 %.0f%% を超えています。", mem, memThreshold)
		}
		issues = append(issues, healthIssue{agentID: id, hostname: hostname, description: desc,
			title: fmt.Sprintf("エージェント %s ヘルス警告", hostname), dedupFor: dedupWindow})
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "CPU/メモリの走査が途中で終わりました。見つかったぶんだけ通知します")
	}
	return issues
}

// checkStaleAgents returns agents that are still marked online but have not
// checked in within staleThreshold.
func (a *AgentHealthAlerter) checkStaleAgents(ctx context.Context) []healthIssue {
	rows, err := a.pool.Query(ctx,
		`SELECT id::text, hostname,
		        EXTRACT(EPOCH FROM (NOW() - last_seen))::int AS seconds_silent
		 FROM agents
		 WHERE status = 'online'
		   AND last_seen IS NOT NULL
		   AND last_seen < NOW() - $1::INTERVAL
		 LIMIT 50`,
		fmt.Sprintf("%.0f seconds", staleThreshold.Seconds()),
	)
	if err != nil {
		fail(ctx, err, "ステールエージェントチェック失敗")
		return nil
	}
	defer rows.Close()

	var issues []healthIssue
	for rows.Next() {
		var id, hostname string
		var secondsSilent int
		if scanErr := rows.Scan(&id, &hostname, &secondsSilent); scanErr != nil {
			continue
		}
		silent := time.Duration(secondsSilent) * time.Second
		desc := fmt.Sprintf(
			"エージェントは 'online' として登録されていますが、%s 以上ハートビートを送信していません（最終確認: %s 前）。",
			staleThreshold, silent.Round(time.Second),
		)
		issues = append(issues, healthIssue{agentID: id, hostname: hostname, description: desc,
			title: fmt.Sprintf("エージェント %s ヘルス警告", hostname), dedupFor: dedupWindow})
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "ステールエージェントの走査が途中で終わりました。見つかったぶんだけ通知します")
	}
	return issues
}

// checkDegradedSensors returns agents whose collectors fell back from eBPF to
// userspace polling.
//
// This is the alarm that did not exist on 2026-08-03, when a Linux endpoint ran for
// days with the eBPF file and network monitors absent: port scans of closed ports
// (T1046) were structurally undetectable and ransomware detection had no process
// attribution, while the fleet view showed a healthy online agent. The data to
// notice it was being reported the whole time — nothing looked at it.
//
// Deliberately narrow, because a noisy alarm is an ignored alarm:
//   - only telemetry_mode = 'poll'. NULL means "not reported" (Windows/macOS and
//     older agents), 'off' means the sensor is disabled by configuration. Neither
//     is a degradation and neither may alert.
//   - only agents currently online, so a decommissioned host does not nag.
//   - a 24h dedup rather than the 1h used for CPU spikes: a blind sensor is a
//     standing condition, not a transient, and re-paging hourly would train
//     operators to ignore it.
func (a *AgentHealthAlerter) checkDegradedSensors(ctx context.Context) []healthIssue {
	rows, err := a.pool.Query(ctx,
		`SELECT id::text, hostname, COALESCE(telemetry_detail, '')
		   FROM agents
		  WHERE status = 'online'
		    AND telemetry_mode = 'poll'
		  LIMIT 50`)
	if err != nil {
		// Column missing (migration 357/365 not yet applied) — degrade quietly.
		slog.Debug("センサー降格チェックをスキップ", "error", err)
		return nil
	}
	defer rows.Close()

	var issues []healthIssue
	for rows.Next() {
		var id, hostname, detail string
		if scanErr := rows.Scan(&id, &hostname, &detail); scanErr != nil {
			continue
		}
		desc := "エージェントのセンサーが eBPF からユーザ空間ポーリングに降格しています。" +
			"閉じたポートへの接続(ポートスキャン T1046)が観測できず、ファイルイベントには" +
			"プロセス帰属が付かないため、ランサムウェア検知もプロセスを特定できません。"
		if detail != "" {
			desc += " センサー別: " + detail + "。"
		}
		desc += " 対処はエージェントの再ビルド/再配備（-tags ebpf の有無ではなく、" +
			"該当機能を含むリビジョンでビルドされているかを確認すること）と、" +
			"bpftool link show での attach 確認。"
		issues = append(issues, healthIssue{
			agentID: id, hostname: hostname, description: desc,
			title:    "エージェント " + hostname + degradedSensorTitleSuffix,
			dedupFor: degradedSensorDedupWindow,
		})
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "ステールエージェントの走査が途中で終わりました。見つかったぶんだけ通知します")
	}
	return issues
}

// maybeCreateAlert checks dedup and creates an alert if no similar alert
// was raised for this agent in the last dedupWindow.
func (a *AgentHealthAlerter) maybeCreateAlert(ctx context.Context, issue healthIssue) {
	// Dedup: skip if a health-monitor alert already exists for this agent in the last hour.
	var existing int
	_ = a.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE agent_id = $1::uuid
		   AND title = $2
		   AND created_at > NOW() - $3::INTERVAL`,
		issue.agentID, issue.title,
		fmt.Sprintf("%.0f seconds", issue.dedupFor.Seconds()),
	).Scan(&existing)

	if existing > 0 {
		slog.Debug("ヘルスアラートは重複のためスキップします", "agent_id", issue.agentID, "title", issue.title)
		return
	}

	title := issue.title

	var alertID string
	err := a.pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status)
		 VALUES ($1::uuid, $2, $3, 5, 'open')
		 RETURNING id::text`,
		issue.agentID, title, issue.description,
	).Scan(&alertID)
	if err != nil {
		fail(ctx, err, "ヘルスアラートの作成に失敗しました", "agent_id", issue.agentID)
		return
	}

	slog.Info("エージェントヘルスアラートを作成しました",
		"alert_id", alertID,
		"agent_id", issue.agentID,
		"hostname", issue.hostname,
	)

	// Publish NATS notification so consumers can react immediately.
	if a.nc != nil {
		payload, _ := json.Marshal(map[string]string{
			"alert_id":    alertID,
			"agent_id":    issue.agentID,
			"hostname":    issue.hostname,
			"description": issue.description,
		})
		if pubErr := a.nc.Publish("alerts.new", payload); pubErr != nil {
			fail(ctx, pubErr, "alerts.new NATSパブリッシュに失敗しました")
		}
	}
}
