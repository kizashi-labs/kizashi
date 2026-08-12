package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// ThreatHuntAutomator runs automated threat hunting routines on a schedule.
type ThreatHuntAutomator struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewThreatHuntAutomator creates a new ThreatHuntAutomator.
func NewThreatHuntAutomator(pool *pgxpool.Pool, nc *nats.Conn) *ThreatHuntAutomator {
	return &ThreatHuntAutomator{pool: pool, nc: nc}
}

// Run starts the automator ticker every 30 minutes.
func (a *ThreatHuntAutomator) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.huntFromIOCs(ctx)
			a.huntSuspiciousProcessChains(ctx)
		}
	}
}

// huntFromIOCs checks recent high-confidence IOCs and creates alerts on matches.
func (a *ThreatHuntAutomator) huntFromIOCs(ctx context.Context) {
	// 1. Check iocs table exists
	var iocTableExists bool
	err := a.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='iocs')`).
		Scan(&iocTableExists)
	if err != nil || !iocTableExists {
		slog.Debug("脅威ハントオートメーター: iocsテーブルが存在しないためスキップ")
		return
	}

	// 2. Query recent high-confidence IOCs (last 24h)
	// Check if confidence column exists
	var hasConfidence bool
	_ = a.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name='iocs' AND column_name='confidence'
		)`).Scan(&hasConfidence)

	var query string
	if hasConfidence {
		query = `SELECT id, ioc_type, value FROM iocs
		         WHERE created_at >= NOW() - INTERVAL '24 hours' AND confidence > 70`
	} else {
		query = `SELECT id, ioc_type, value FROM iocs
		         WHERE created_at >= NOW() - INTERVAL '24 hours'`
	}

	rows, err := a.pool.Query(ctx, query)
	if err != nil {
		slog.Warn("脅威ハントオートメーター: IOC取得に失敗しました", "error", err)
		return
	}
	defer rows.Close()

	type iocEntry struct {
		id      string
		iocType string
		value   string
	}

	var iocs []iocEntry
	for rows.Next() {
		var e iocEntry
		if rows.Scan(&e.id, &e.iocType, &e.value) == nil {
			iocs = append(iocs, e)
		}
	}
	rows.Close()

	for _, ioc := range iocs {
		switch ioc.iocType {
		case "ip":
			// Check network_connections for connections to this IP
			var tableExists bool
			_ = a.pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='network_connections')`).
				Scan(&tableExists)
			if !tableExists {
				continue
			}

			var agentID string
			err := a.pool.QueryRow(ctx,
				`SELECT agent_id FROM network_connections
				 WHERE remote_ip=$1 AND timestamp >= NOW() - INTERVAL '24 hours'
				 LIMIT 1`, ioc.value).Scan(&agentID)
			if err == nil && agentID != "" {
				a.createAlert(ctx, agentID,
					"IOC IPアドレス接続検出",
					"IOCリストに登録されたIPアドレスへの接続を検出しました: "+ioc.value,
					7)
				a.publishIOCMatch(ctx, ioc.id, ioc.iocType, ioc.value, agentID)
			}

		case "domain":
			// Check dns_events for queries to this domain
			var tableExists bool
			_ = a.pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='dns_events')`).
				Scan(&tableExists)
			if !tableExists {
				continue
			}

			var agentID string
			err := a.pool.QueryRow(ctx,
				`SELECT agent_id FROM dns_events
				 WHERE query=$1 AND timestamp >= NOW() - INTERVAL '24 hours'
				 LIMIT 1`, ioc.value).Scan(&agentID)
			if err == nil && agentID != "" {
				a.createAlert(ctx, agentID,
					"IOC ドメイン問い合わせ検出",
					"IOCリストに登録されたドメインへの問い合わせを検出しました: "+ioc.value,
					7)
				a.publishIOCMatch(ctx, ioc.id, ioc.iocType, ioc.value, agentID)
			}

		case "hash":
			// Check processes for process_hash matches
			var tableExists bool
			_ = a.pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='processes')`).
				Scan(&tableExists)
			if !tableExists {
				continue
			}

			var agentID string
			err := a.pool.QueryRow(ctx,
				`SELECT agent_id FROM processes
				 WHERE process_hash=$1 AND timestamp >= NOW() - INTERVAL '24 hours'
				 LIMIT 1`, ioc.value).Scan(&agentID)
			if err == nil && agentID != "" {
				a.createAlert(ctx, agentID,
					"IOC ハッシュ一致プロセス検出",
					"IOCリストに登録されたハッシュに一致するプロセスを検出しました: "+ioc.value,
					8)
				a.publishIOCMatch(ctx, ioc.id, ioc.iocType, ioc.value, agentID)
			}
		}
	}
}

// publishIOCMatch publishes a NATS message for an IOC match finding.
func (a *ThreatHuntAutomator) publishIOCMatch(ctx context.Context, iocID, iocType, value, agentID string) {
	if a.nc == nil {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"ioc_id":   iocID,
		"ioc_type": iocType,
		"value":    value,
		"agent_id": agentID,
	})
	_ = a.nc.Publish("threat_hunt.ioc_match", payload)
}

// huntSuspiciousProcessChains detects office app spawning shell processes.
func (a *ThreatHuntAutomator) huntSuspiciousProcessChains(ctx context.Context) {
	// 1. Check processes table exists
	var tableExists bool
	err := a.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='processes')`).
		Scan(&tableExists)
	if err != nil || !tableExists {
		slog.Debug("脅威ハントオートメーター: processesテーブルが存在しないためスキップ")
		return
	}

	// 2. Query: office apps spawning shell processes in last 30 minutes
	// Look for cmd.exe/powershell.exe whose parent is an office app
	rows, err := a.pool.Query(ctx,
		`SELECT DISTINCT p.agent_id
		 FROM processes p
		 JOIN processes parent ON p.parent_pid = parent.pid AND p.agent_id = parent.agent_id
		 WHERE LOWER(p.name) IN ('cmd.exe', 'powershell.exe')
		   AND LOWER(parent.name) IN ('winword.exe', 'excel.exe', 'powerpnt.exe')
		   AND p.timestamp >= NOW() - INTERVAL '30 minutes'`)
	if err != nil {
		slog.Debug("脅威ハントオートメーター: プロセスチェーンクエリに失敗しました", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID string
		if rows.Scan(&agentID) == nil {
			a.createAlert(ctx, agentID,
				"疑わしいプロセスチェーン検出",
				"Officeアプリケーションからシェルプロセスが起動されました。マクロ攻撃の可能性があります。",
				8)
		}
	}
}

// createAlert inserts an alert into the alerts table and publishes to NATS.
func (a *ThreatHuntAutomator) createAlert(ctx context.Context, agentID, title, desc string, severity int) {
	// Check alerts table exists
	var tableExists bool
	_ = a.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='alerts')`).
		Scan(&tableExists)
	if !tableExists {
		slog.Warn("脅威ハントオートメーター: alertsテーブルが存在しません")
		return
	}

	var alertID string
	err := a.pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id, title, description, severity, status, source)
		 VALUES ($1, $2, $3, $4, 'open', 'threat_hunt_automator')
		 RETURNING id`,
		agentID, title, desc, severity).Scan(&alertID)
	if err != nil {
		slog.Warn("脅威ハントオートメーター: アラート作成に失敗しました", "error", err)
		return
	}

	slog.Info("脅威ハントオートメーター: アラートを作成しました", "alert_id", alertID, "title", title)

	if a.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"alert_id": alertID,
			"agent_id": agentID,
			"title":    title,
			"severity": severity,
		})
		_ = a.nc.Publish("alerts.new", payload)
	}
}
