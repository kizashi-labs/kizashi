package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// NetworkAnomalyDetector detects network anomalies by periodically analyzing connection data.
type NetworkAnomalyDetector struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewNetworkAnomalyDetector creates a new NetworkAnomalyDetector.
func NewNetworkAnomalyDetector(pool *pgxpool.Pool, nc *nats.Conn) *NetworkAnomalyDetector {
	return &NetworkAnomalyDetector{pool: pool, nc: nc}
}

// Run starts the network anomaly detection loop.
func (d *NetworkAnomalyDetector) Run(ctx context.Context) {
	slog.Info("ネットワーク異常検知スケジューラーを開始しました")
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	// Run once immediately
	d.detect(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("ネットワーク異常検知スケジューラーを停止しました")
			return
		case <-ticker.C:
			d.detect(ctx)
		}
	}
}

func (d *NetworkAnomalyDetector) detect(ctx context.Context) {
	d.detectTrafficSpike(ctx)
	d.detectNewPorts(ctx)
	d.detectHighBeaconing(ctx)
}

func (d *NetworkAnomalyDetector) networkTableExists(ctx context.Context) bool {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='network_connections')`).Scan(&exists)
	return err == nil && exists
}

func (d *NetworkAnomalyDetector) detectTrafficSpike(ctx context.Context) {
	if !d.networkTableExists(ctx) {
		return
	}

	type agentTraffic struct {
		AgentID  string
		Current  int
		Previous int
	}

	rows, err := d.pool.Query(ctx, `
		SELECT
		  agent_id,
		  COUNT(*) FILTER (WHERE time >= NOW() - INTERVAL '10 minutes') AS current_count,
		  COUNT(*) FILTER (WHERE time >= NOW() - INTERVAL '20 minutes' AND time < NOW() - INTERVAL '10 minutes') AS previous_count
		FROM network_connections
		WHERE time >= NOW() - INTERVAL '20 minutes'
		GROUP BY agent_id
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var at agentTraffic
		if err := rows.Scan(&at.AgentID, &at.Current, &at.Previous); err != nil {
			continue
		}
		if at.Current > 100 && at.Previous > 0 && at.Current > at.Previous*3 {
			title := "ネットワークトラフィックスパイク検出"
			desc := "エージェントの直近10分間のネットワーク接続数が前の10分間と比較して3倍以上に増加しました"
			d.createAlert(ctx, at.AgentID, title, desc, 3)
		} else if at.Current > 100 && at.Previous == 0 {
			title := "ネットワークトラフィックスパイク検出"
			desc := "エージェントで大量のネットワーク接続が検出されました"
			d.createAlert(ctx, at.AgentID, title, desc, 3)
		}
	}
}

func (d *NetworkAnomalyDetector) detectNewPorts(ctx context.Context) {
	if !d.networkTableExists(ctx) {
		return
	}

	highRiskPorts := []int{4444, 1337, 31337, 6666, 6667, 9999, 12345}

	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT agent_id, dst_port
		FROM network_connections
		WHERE time >= NOW() - INTERVAL '10 minutes'
		  AND dst_port IS NOT NULL
		  AND dst_port NOT IN (
		    SELECT DISTINCT dst_port FROM network_connections
		    WHERE time >= NOW() - INTERVAL '24 hours'
		      AND time < NOW() - INTERVAL '10 minutes'
		      AND dst_port IS NOT NULL
		  )
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	type portEntry struct {
		AgentID  string
		DestPort int
	}
	var entries []portEntry
	for rows.Next() {
		var e portEntry
		if err := rows.Scan(&e.AgentID, &e.DestPort); err == nil {
			entries = append(entries, e)
		}
	}

	// Check for high-risk ports
	for _, e := range entries {
		for _, hrp := range highRiskPorts {
			if e.DestPort == hrp {
				title := "不審なポート接続検出"
				desc := "高リスクポート（" + itoa(e.DestPort) + "）への接続が検出されました"
				d.createAlert(ctx, e.AgentID, title, desc, 4)
				break
			}
		}
	}
}

func (d *NetworkAnomalyDetector) detectHighBeaconing(ctx context.Context) {
	if !d.networkTableExists(ctx) {
		return
	}

	rows, err := d.pool.Query(ctx, `
		SELECT agent_id, dst_ip, COUNT(*) as conn_count
		FROM network_connections
		WHERE time >= NOW() - INTERVAL '10 minutes'
		  AND dst_ip IS NOT NULL
		GROUP BY agent_id, dst_ip
		HAVING COUNT(*) > 50
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, destIP string
		var count int
		if err := rows.Scan(&agentID, &destIP, &count); err != nil {
			continue
		}
		title := "C2ビーコニング疑い"
		desc := "同一宛先IPアドレス（" + destIP + "）への短時間での大量接続（" + itoa(count) + "回）が検出されました。C2通信の可能性があります"
		d.createAlert(ctx, agentID, title, desc, 4)
	}
}

func (d *NetworkAnomalyDetector) createAlert(ctx context.Context, agentID, title, description string, severity int) {
	var alertsExist bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alerts')`).Scan(&alertsExist)
	if err != nil || !alertsExist {
		slog.Warn("alertsテーブルが存在しないため、アラートを作成できません", "title", title)
		return
	}

	var alertID string
	agentIDPtr := &agentID
	if agentID == "" {
		agentIDPtr = nil
	}

	err = d.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, description, severity, status, source, agent_id)
		 VALUES ($1,$2,$3,'open','network_anomaly',$4) RETURNING id`,
		title, description, severity, agentIDPtr,
	).Scan(&alertID)
	if err != nil {
		slog.Error("アラートの作成に失敗しました", "error", err, "title", title)
		return
	}

	slog.Info("ネットワーク異常アラートを作成しました", "id", alertID, "title", title)

	// Publish to NATS
	if d.nc != nil {
		payload := []byte(`{"id":"` + alertID + `","title":"` + title + `","severity":` + itoa(severity) + `}`)
		if err := d.nc.Publish("alerts.new", payload); err != nil {
			slog.Warn("NATSへのアラート送信に失敗しました", "error", err)
		}
	}
}
