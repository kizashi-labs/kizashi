package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// IOCMatcher checks recent process events and network connections against
// the IOC list every minute and creates alerts on matches.
type IOCMatcher struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

func NewIOCMatcher(pool *pgxpool.Pool, nc *nats.Conn) *IOCMatcher {
	return &IOCMatcher{pool: pool, nc: nc}
}

func (m *IOCMatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.match(ctx)
		}
	}
}

// iocEntry holds a single IOC record loaded from the database.
type iocEntry struct {
	value       string
	iocType     string
	threatLevel int
}

// match is the main IOC matching routine called every minute.
func (m *IOCMatcher) match(ctx context.Context) {
	// ── 1. Check if ioc_entries table exists ──────────────────────────────
	var iocTableExists bool
	err := m.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'ioc_entries'
		)`,
	).Scan(&iocTableExists)
	if err != nil || !iocTableExists {
		slog.Debug("IOCマッチャー: ioc_entriesテーブルが存在しないためスキップ")
		return
	}

	// ── 2. Load enabled IOC entries into memory ───────────────────────────
	// Order by confidence so that, when more IOCs exist than the cap, the
	// highest-trust indicators win the in-memory slots (the old query had no
	// ORDER BY, so the 10k it kept was arbitrary). The cap matches the
	// AlertPipeline FeedManager (100k) so both matchers see the same set once
	// the IOC store grows past 10k (e.g. after public-feed expansion).
	rows, err := m.pool.Query(ctx,
		`SELECT value, ioc_type, COALESCE(threat_level, 3)
		 FROM ioc_entries
		 WHERE enabled = true
		 ORDER BY confidence DESC NULLS LAST, last_seen DESC NULLS LAST
		 LIMIT 100000`,
	)
	if err != nil {
		slog.Warn("IOCエントリの読み込みに失敗しました", "error", err)
		return
	}

	var entries []iocEntry
	for rows.Next() {
		var e iocEntry
		if scanErr := rows.Scan(&e.value, &e.iocType, &e.threatLevel); scanErr != nil {
			continue
		}
		entries = append(entries, e)
	}
	rows.Close()

	if len(entries) == 0 {
		slog.Debug("IOCマッチャー: 有効なIOCエントリなし")
		return
	}

	// ── 3. Build lookup maps ─────────────────────────────────────────────
	domainMap := make(map[string]iocEntry)
	ipMap := make(map[string]iocEntry)
	hashMap := make(map[string]iocEntry)

	for _, e := range entries {
		switch e.iocType {
		case "domain", "hostname":
			domainMap[e.value] = e
		case "ip", "ipv4", "ipv6":
			ipMap[e.value] = e
		case "hash", "md5", "sha1", "sha256":
			hashMap[e.value] = e
		}
	}

	matchCount := 0

	// ── 4. Check process_events from last 2 minutes ───────────────────────
	var procTableExists bool
	_ = m.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'process_events'
		)`,
	).Scan(&procTableExists)

	if procTableExists {
		procRows, err := m.pool.Query(ctx,
			`SELECT id::text, agent_id::text,
			        COALESCE(process_name, ''), COALESCE(cmdline, ''), COALESCE(hash, '')
			 FROM process_events
			 WHERE timestamp > NOW() - INTERVAL '2 minutes'
			 LIMIT 5000`,
		)
		if err != nil {
			slog.Warn("プロセスイベントの読み込みに失敗しました", "error", err)
		} else {
			for procRows.Next() {
				var id, agentID, processName, cmdline, hash string
				if scanErr := procRows.Scan(&id, &agentID, &processName, &cmdline, &hash); scanErr != nil {
					continue
				}

				// Check hash
				if hash != "" {
					if ioc, ok := hashMap[hash]; ok {
						title := fmt.Sprintf("IOCマッチ: 不審なハッシュ検出 [%s]", processName)
						desc := fmt.Sprintf("プロセス '%s' のハッシュ '%s' がIOCリストと一致しました。(タイプ: %s)",
							processName, hash, ioc.iocType)
						created := m.createAlert(ctx, id, agentID, title, ioc.threatLevel, desc)
						if created {
							matchCount++
						}
					}
				}

				// Check process_name against domainMap (e.g. known malware exe names registered as domains)
				if processName != "" {
					if ioc, ok := domainMap[processName]; ok {
						title := fmt.Sprintf("IOCマッチ: 不審なプロセス名検出 [%s]", processName)
						desc := fmt.Sprintf("プロセス名 '%s' がIOCドメインリストと一致しました。(タイプ: %s)",
							processName, ioc.iocType)
						created := m.createAlert(ctx, id, agentID, title, ioc.threatLevel, desc)
						if created {
							matchCount++
						}
					}
				}
			}
			procRows.Close()
		}
	}

	// ── 5. Check network_connections from last 2 minutes ─────────────────
	var netTableExists bool
	_ = m.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'network_connections'
		)`,
	).Scan(&netTableExists)

	if netTableExists {
		netRows, err := m.pool.Query(ctx,
			`SELECT agent_id::text, agent_id::text, COALESCE(dst_ip::text, ''), COALESCE(dst_port::text, '')
			 FROM network_connections
			 WHERE time > NOW() - INTERVAL '2 minutes'
			 LIMIT 5000`,
		)
		if err != nil {
			slog.Warn("ネットワーク接続の読み込みに失敗しました", "error", err)
		} else {
			for netRows.Next() {
				var id, agentID, dstIP, dstPort string
				if scanErr := netRows.Scan(&id, &agentID, &dstIP, &dstPort); scanErr != nil {
					continue
				}

				if dstIP != "" {
					if ioc, ok := ipMap[dstIP]; ok {
						title := fmt.Sprintf("IOCマッチ: 不審なIPアドレスへの接続 [%s]", dstIP)
						desc := fmt.Sprintf("宛先IP '%s'(ポート %s) がIOCリストと一致しました。(タイプ: %s)",
							dstIP, dstPort, ioc.iocType)
						created := m.createAlert(ctx, id, agentID, title, ioc.threatLevel, desc)
						if created {
							matchCount++
						}
					}
				}
			}
			netRows.Close()
		}
	}

	// ── 8. Log match count ────────────────────────────────────────────────
	if matchCount > 0 {
		slog.Info("IOCマッチャー: マッチを検出しました", "count", matchCount)
	} else {
		slog.Debug("IOCマッチャー: マッチなし")
	}
}

// createAlert inserts a new alert for an IOC match, with deduplication.
// It returns true if a new alert was created.
func (m *IOCMatcher) createAlert(ctx context.Context, sourceID, agentID, title string, threatLevel int, description string) bool {
	// ── 6a. Deduplicate: check for existing alert with same source_id in last 1 hour ──
	var existing int
	_ = m.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE description LIKE $1
		   AND created_at > NOW() - INTERVAL '1 hour'`,
		"%"+sourceID+"%",
	).Scan(&existing)

	if existing > 0 {
		slog.Debug("IOCアラート重複スキップ", "source_id", sourceID)
		return false
	}

	// Map threat level (1-5 scale) to severity
	severity := threatLevel
	if severity < 1 {
		severity = 3
	}
	if severity > 5 {
		severity = 5
	}

	// ── 6b. Insert alert ──────────────────────────────────────────────────
	descWithSource := fmt.Sprintf("%s\n\nソースID: %s", description, sourceID)

	var alertID string
	var insertErr error
	if agentID != "" {
		insertErr = m.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, agent_id, description, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3::uuid, $4, NOW())
			 RETURNING id::text`,
			title, severity, agentID, descWithSource,
		).Scan(&alertID)
	} else {
		insertErr = m.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, description, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3, NOW())
			 RETURNING id::text`,
			title, severity, descWithSource,
		).Scan(&alertID)
	}

	if insertErr != nil {
		slog.Error("IOCアラートの作成に失敗しました", "title", title, "error", insertErr)
		return false
	}

	slog.Info("IOCアラートを作成しました", "alert_id", alertID, "title", title)

	// ── 7. Publish NATS alerts.new ────────────────────────────────────────
	if m.nc != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"alert_id":    alertID,
			"agent_id":    agentID,
			"title":       title,
			"severity":    severity,
			"description": description,
		})
		if pubErr := m.nc.Publish("alerts.new", payload); pubErr != nil {
			slog.Warn("IOC alerts.new NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}

	return true
}
