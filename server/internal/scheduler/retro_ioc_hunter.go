package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// RetroIOCHunter scans historical telemetry for matches against newly-added IOCs.
//
// The live IOCMatcher covers "new events × all IOCs" every minute, but IOCs that
// arrive later (e.g. a fresh ThreatFox sync of thousands of indicators) are never
// checked against events that already happened. RetroIOCHunter covers the other
// half — "historical events × new IOCs" — so a C2 IP or malware domain added today
// surfaces intrusions that occurred days ago.
//
// A watermark (ioc_hunt_state.last_hunted_at) records how far the IOC set has been
// hunted: each run considers only IOCs whose first_seen is newer than the watermark,
// then advances it. This hunts each IOC against history exactly once, so runs stay
// bounded regardless of how large the total IOC set grows.
type RetroIOCHunter struct {
	pool       *pgxpool.Pool
	nc         *nats.Conn
	lookback   time.Duration // how far back into event history to scan
	interval   time.Duration
	maxNewIOCs int // cap IOCs considered per run (a huge feed drop stays bounded)
	maxMatches int // cap alerts created per run
}

// NewRetroIOCHunter creates a RetroIOCHunter. lookbackDays<=0 defaults to 30,
// interval<=0 defaults to 6h.
func NewRetroIOCHunter(pool *pgxpool.Pool, nc *nats.Conn, lookbackDays int, interval time.Duration) *RetroIOCHunter {
	if lookbackDays <= 0 {
		lookbackDays = 30
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &RetroIOCHunter{
		pool:       pool,
		nc:         nc,
		lookback:   time.Duration(lookbackDays) * 24 * time.Hour,
		interval:   interval,
		maxNewIOCs: 20000,
		maxMatches: 500,
	}
}

// Run hunts once on startup, then every interval, until ctx is cancelled.
func (h *RetroIOCHunter) Run(ctx context.Context) {
	slog.Info("レトロアクティブIOCハンター起動", "lookback", h.lookback, "interval", h.interval)
	h.hunt(ctx)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.hunt(ctx)
		}
	}
}

// hunt performs one retroactive pass: load IOCs newer than the watermark, scan
// historical network/dns events for matches, alert, then advance the watermark.
func (h *RetroIOCHunter) hunt(ctx context.Context) {
	watermark, ok := h.loadWatermark(ctx)
	if !ok {
		return // table missing or unreadable — skip silently (idempotent next run)
	}

	ips, domains := h.loadNewIOCs(ctx, watermark)
	if len(ips) == 0 && len(domains) == 0 {
		slog.Debug("レトロIOCハンター: 新規IOCなし")
		h.advanceWatermark(ctx) // still advance so the window does not grow unbounded
		return
	}
	slog.Info("レトロIOCハンター: 新規IOCを履歴照合します", "ips", len(ips), "domains", len(domains))

	matches := 0
	matches += h.huntField(ctx, "network", "dst_ip", ips, ipDomainThreat(ips))
	matches += h.huntField(ctx, "dns", "query", domains, ipDomainThreat(domains))

	if matches > 0 {
		slog.Warn("レトロIOCハンター: 過去のイベントにIOC一致を検出", "matches", matches)
	}
	h.advanceWatermark(ctx)
}

// iocMeta carries the per-value threat level used to set alert severity.
type iocMeta map[string]int

// ipDomainThreat is a helper so huntField has a uniform lookup; the maps built in
// loadNewIOCs already carry threat levels, so this just returns them.
func ipDomainThreat(m iocMeta) iocMeta { return m }

// loadWatermark returns the current retro-hunt watermark. ok=false means the
// state table is missing/unreadable and the caller should skip this run.
func (h *RetroIOCHunter) loadWatermark(ctx context.Context) (time.Time, bool) {
	var wm time.Time
	err := h.pool.QueryRow(ctx, `SELECT last_hunted_at FROM ioc_hunt_state WHERE id = 1`).Scan(&wm)
	if err != nil {
		slog.Debug("レトロIOCハンター: watermark取得をスキップ", "error", err)
		return time.Time{}, false
	}
	return wm, true
}

// advanceWatermark sets last_hunted_at to now so the next run only considers IOCs
// added after this pass.
func (h *RetroIOCHunter) advanceWatermark(ctx context.Context) {
	_, err := h.pool.Exec(ctx,
		`UPDATE ioc_hunt_state SET last_hunted_at = NOW(), updated_at = NOW() WHERE id = 1`)
	if err != nil {
		slog.Warn("レトロIOCハンター: watermark前進に失敗", "error", err)
	}
}

// loadNewIOCs loads active IOCs whose first_seen is newer than the watermark,
// partitioned into ip and domain value→threatLevel maps. Hash IOCs are omitted:
// the events store does not carry a file-hash field to match against.
func (h *RetroIOCHunter) loadNewIOCs(ctx context.Context, watermark time.Time) (ips, domains iocMeta) {
	ips = iocMeta{}
	domains = iocMeta{}
	rows, err := h.pool.Query(ctx, `
		SELECT value, ioc_type, COALESCE(threat_level, 3)
		FROM ioc_entries
		WHERE enabled = true AND first_seen > $1
		ORDER BY first_seen
		LIMIT $2`,
		watermark, h.maxNewIOCs,
	)
	if err != nil {
		slog.Debug("レトロIOCハンター: 新規IOC読み込みをスキップ", "error", err)
		return ips, domains
	}
	defer rows.Close()
	for rows.Next() {
		var value, iocType string
		var threat int
		if rows.Scan(&value, &iocType, &threat) != nil {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch iocType {
		case "ip", "ipv4", "ipv6":
			ips[value] = threat
		case "domain", "hostname":
			domains[strings.ToLower(value)] = threat
		}
	}
	return ips, domains
}

// huntField scans historical events of eventType whose raw_data->>field matches any
// of the given IOC values, creating a deduplicated retro alert per matching event.
// Returns the number of alerts created.
func (h *RetroIOCHunter) huntField(ctx context.Context, eventType, field string, iocs, threat iocMeta) int {
	if len(iocs) == 0 {
		return 0
	}
	values := make([]string, 0, len(iocs))
	for v := range iocs {
		values = append(values, v)
	}

	// Match historical events against the new-IOC value set. LOWER() on the dns
	// query mirrors the lowercased domain keys; dst_ip is compared as-is.
	expr := "raw_data->>'" + field + "'"
	if eventType == "dns" {
		expr = "LOWER(" + expr + ")"
	}
	// NB: the events hypertable's identifier column is event_id (there is no `id`).
	q := fmt.Sprintf(`
		SELECT event_id::text, agent_id::text, %s AS matched, time
		FROM events
		WHERE event_type = $1
		  AND time > NOW() - $2::interval
		  AND %s = ANY($3::text[])
		ORDER BY time DESC
		LIMIT $4`, expr, expr)

	rows, err := h.pool.Query(ctx, q, eventType,
		fmt.Sprintf("%d seconds", int(h.lookback.Seconds())), values, h.maxMatches)
	if err != nil {
		slog.Warn("レトロIOCハンター: 履歴スキャン失敗", "event_type", eventType, "error", err)
		return 0
	}
	defer rows.Close()

	created := 0
	for rows.Next() {
		var eventID, agentID, matched string
		var ts time.Time
		if rows.Scan(&eventID, &agentID, &matched, &ts) != nil {
			continue
		}
		sev := threat[matched]
		if eventType == "dns" {
			// domain keys are lowercased
			sev = threat[strings.ToLower(matched)]
		}
		if h.createRetroAlert(ctx, eventID, agentID, eventType, field, matched, ts, sev) {
			created++
		}
	}
	return created
}

// createRetroAlert inserts a deduplicated retro-hunt alert. Dedup keys on the
// historical event id, so re-runs (or the live matcher) do not double-alert the
// same event. Returns true when a new alert row was written.
func (h *RetroIOCHunter) createRetroAlert(ctx context.Context, eventID, agentID, eventType, field, value string, occurredAt time.Time, threat int) bool {
	var existing int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE description LIKE $1`,
		"%"+eventID+"%",
	).Scan(&existing)
	if existing > 0 {
		return false
	}

	severity := threat
	if severity < 1 {
		severity = 3
	}
	if severity > 5 {
		severity = 5
	}

	title := fmt.Sprintf("[RETRO] 過去のIOC一致: %s に %s へのアクセス", eventType, value)
	desc := fmt.Sprintf(
		"レトロアクティブ照合: %s イベント(%s=%s)が新規登録IOCと一致しました。"+
			"発生時刻: %s\n\nイベントID: %s",
		eventType, field, value, occurredAt.Format("2006-01-02 15:04:05 MST"), eventID)

	var alertID string
	var err error
	if agentID != "" && agentID != "00000000-0000-0000-0000-000000000000" {
		err = h.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, agent_id, description, source, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3::uuid, $4, 'retro_ioc', NOW())
			 RETURNING id::text`,
			title, severity, agentID, desc,
		).Scan(&alertID)
	} else {
		err = h.pool.QueryRow(ctx,
			`INSERT INTO alerts (id, title, severity, status, description, source, created_at)
			 VALUES (gen_random_uuid(), $1, $2, 'open', $3, 'retro_ioc', NOW())
			 RETURNING id::text`,
			title, severity, desc,
		).Scan(&alertID)
	}
	if err != nil {
		slog.Error("レトロIOCアラート作成に失敗", "title", title, "error", err)
		return false
	}
	slog.Info("レトロIOCアラートを作成", "alert_id", alertID, "value", value, "event_type", eventType)

	if h.nc != nil {
		_ = h.nc.Publish("alerts.new", []byte(fmt.Sprintf(
			`{"alert_id":%q,"agent_id":%q,"title":%q,"severity":%d}`,
			alertID, agentID, title, severity)))
	}
	return true
}
