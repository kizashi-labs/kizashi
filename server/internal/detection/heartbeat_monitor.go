package detection

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/tick"
)

// HeartbeatMonitor はエージェントのハートビートを監視し、
// 一定時間応答がないエージェントに対してアラートを生成します。
type HeartbeatMonitor struct {
	pool      *pgxpool.Pool
	alertSave AlertSaver
	timeout   time.Duration // この時間応答がなければオフラインと判定
	interval  time.Duration // チェック間隔
}

// NewHeartbeatMonitor は新しい HeartbeatMonitor を返します。
// デフォルトのタイムアウトは5分、チェック間隔は2分です。
func NewHeartbeatMonitor(pool *pgxpool.Pool, saver AlertSaver) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		pool:      pool,
		alertSave: saver,
		timeout:   5 * time.Minute,
		interval:  2 * time.Minute,
	}
}

// NewHeartbeatMonitorWithConfig はタイムアウトとチェック間隔を指定して HeartbeatMonitor を生成します。
// timeoutMin: オフライン判定までの分数（デフォルト5）
// intervalMin: チェック間隔の分数（デフォルト2）
func NewHeartbeatMonitorWithConfig(pool *pgxpool.Pool, saver AlertSaver, timeoutMin, intervalMin int) *HeartbeatMonitor {
	if timeoutMin < 1 {
		timeoutMin = 5
	}
	if intervalMin < 1 {
		intervalMin = 2
	}
	return &HeartbeatMonitor{
		pool:      pool,
		alertSave: saver,
		timeout:   time.Duration(timeoutMin) * time.Minute,
		interval:  time.Duration(intervalMin) * time.Minute,
	}
}

// Run は定期的にエージェントのハートビートを確認します。
// コンテキストがキャンセルされるまでループします。
func (m *HeartbeatMonitor) Run(ctx context.Context) {
	// 起動直後に一度実行する
	tick.Run(ctx, "heartbeat_monitor", m.checkOnce)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick.Run(ctx, "heartbeat_monitor", m.checkOnce)
		}
	}
}

// offlineAgent はオフラインと判定されたエージェントの情報を保持します。
type offlineAgent struct {
	id       string
	hostname string
	lastSeen time.Time
}

// checkOnce は一回分のハートビートチェックを実行します。
// オフラインエージェントの取得と重複アラートチェックをまとめて1クエリで行い N+1 を解消します。
func (m *HeartbeatMonitor) checkOnce(ctx context.Context) {
	// オフラインエージェントを取得し、直近10分以内に重複アラートがないものだけ返す（1クエリで完結）
	// $1: タイムアウト時間（interval型として渡す）
	rows, err := m.pool.Query(ctx, `
		SELECT a.id, a.hostname, a.last_seen
		FROM agents a
		-- 'inactive' は 30 日以上未確認で DeadAgentCleanup が退役扱いにした状態
		-- (migration 315/330 で status の CHECK に追加済み)。除外語彙に入れないと、
		-- 'offline' → 'inactive' へ遷移した瞬間にこのクエリへ再び載り、下の重複抑止が
		-- 10 分窓しか無いため退役済みホストのオフラインアラートを無期限に量産する。
		WHERE a.status NOT IN ('isolated', 'offline', 'inactive')
		  AND a.last_seen < NOW() - $1::interval
		  AND a.last_seen IS NOT NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM alerts al
		      WHERE al.agent_id = a.id
		        AND al.title LIKE '%オフライン%'
		        AND al.created_at > NOW() - INTERVAL '10 minutes'
		  )
	`, m.timeout)
	if err != nil {
		tick.FailComponent(ctx, "heartbeat_monitor", err, "ハートビート監視: エージェントクエリエラー")
		return
	}
	defer rows.Close()

	var offline []offlineAgent
	for rows.Next() {
		var a offlineAgent
		if err := rows.Scan(&a.id, &a.hostname, &a.lastSeen); err != nil {
			tick.Fail(ctx, err, "ハートビート監視: 行スキャンエラー")
			continue
		}
		offline = append(offline, a)
	}
	if err := rows.Err(); err != nil {
		tick.Fail(ctx, err, "ハートビート監視: 行イテレーションエラー")
	}

	for _, agent := range offline {
		m.createOfflineAlert(ctx, agent)
	}
}

// createOfflineAlert はオフラインエージェントに対してアラートを生成します。
// 重複チェックは checkOnce のクエリ内で実施済みのため、ここでは直接保存します。
func (m *HeartbeatMonitor) createOfflineAlert(ctx context.Context, agent offlineAgent) {
	lastSeenStr := agent.lastSeen.Format("2006-01-02 15:04:05 MST")
	alert := &StoredAlert{
		ID:       generateAlertID(),
		AgentID:  agent.id,
		Hostname: agent.hostname,
		// RuleID は空: alerts.rule_id は uuid 型。非UUID文字列は 22P02 で
		// INSERT 失敗しオフラインアラートが保存されない。識別は RuleName が担う。
		RuleName:    "ハートビート監視",
		Severity:    7,
		Status:      "open",
		Title:       fmt.Sprintf("エージェントオフライン: %s", agent.hostname),
		Description: fmt.Sprintf("エージェントが%d分以上応答していません。最終通信: %s", int(m.timeout.Minutes()), lastSeenStr),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.alertSave.SaveAlert(ctx, alert); err != nil {
		tick.FailComponent(ctx, "heartbeat_monitor", err, "ハートビート監視: アラート保存に失敗しました",
			"agent_id", agent.id,
			"hostname", agent.hostname,
			"error", err)
		return
	}

	slog.Info("ハートビート監視: オフラインエージェントを検出しました",
		"agent_id", agent.id,
		"hostname", agent.hostname,
		"last_seen", agent.lastSeen,
	)
}
