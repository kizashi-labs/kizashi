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
	trackRun(ctx, "retro_ioc_hunter", h.hunt)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "retro_ioc_hunter", h.hunt)
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

	ips, domains, hashes, complete := h.loadNewIOCs(ctx, watermark)
	if len(ips) == 0 && len(domains) == 0 && len(hashes) == 0 {
		if !complete {
			// 「新規IOCなし」と「IOCを読めなかった」は同じ空集合です。
			// 後者で watermark を進めると、読めなかったIOCは照合済みとして
			// 二度と対象になりません。
			slog.Warn("レトロIOCハンター: IOCを読み切れなかったため watermark を進めません")
			return
		}
		slog.Debug("レトロIOCハンター: 新規IOCなし")
		h.advanceWatermark(ctx) // still advance so the window does not grow unbounded
		return
	}
	slog.Info("レトロIOCハンター: 新規IOCを履歴照合します",
		"ips", len(ips), "domains", len(domains), "hashes", len(hashes))

	matches := 0
	scan := func(eventType, field string, lower bool, iocs iocMeta) {
		n, ok := h.huntField(ctx, eventType, field, lower, iocs, ipDomainThreat(iocs))
		matches += n
		complete = complete && ok
	}
	scan("network", "dst_ip", false, ips)
	scan("dns", "query", true, domains)

	// Hash IOCs were previously hunted by nothing. scheduler.IOCMatcher claimed
	// to do it every minute but guarded on a process_events table that no
	// migration creates, so no hash was ever compared against a process; that
	// worker is gone. detection.IOCMatcher covers hashes on live events in
	// cmd/detection, which leaves history — the half this component exists for.
	//
	// Hashes are carried by process, file and image_load events, under the three
	// key names addHashes writes. Compared lowercased, as detection.IOCMatcher
	// does, because feeds and agents disagree on case.
	for _, eventType := range []string{"process", "file", "image_load"} {
		for _, field := range []string{"sha256", "md5", "sha1"} {
			scan(eventType, field, true, hashes)
		}
	}

	if matches > 0 {
		slog.Warn("レトロIOCハンター: 過去のイベントにIOC一致を検出", "matches", matches)
	}
	// watermark は「ここまでは照合し終えた」という宣言です。読み切れていない
	// パスで進めると、その区間は永久に未照合のまま「照合済み」になります。
	// 進めなければ次回やり直せます — 窓が広がるコストの方がはるかに安いです。
	if !complete {
		slog.Warn("レトロIOCハンター: 履歴を読み切れなかったため watermark を進めません。" +
			"次回のパスでやり直します")
		return
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
		fail(ctx, err, "レトロIOCハンター: watermark取得をスキップ")
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
		fail(ctx, err, "レトロIOCハンター: watermark前進に失敗")
	}
}

// loadNewIOCs loads active IOCs whose first_seen is newer than the watermark,
// partitioned into ip and domain value→threatLevel maps. Hash IOCs are omitted:
// the events store does not carry a file-hash field to match against.
// complete=false means the IOC set is a partial one — the caller must not treat
// this pass as having covered everything, because the watermark it would advance
// says exactly that.
func (h *RetroIOCHunter) loadNewIOCs(ctx context.Context, watermark time.Time) (ips, domains, hashes iocMeta, complete bool) {
	ips = iocMeta{}
	domains = iocMeta{}
	hashes = iocMeta{}
	// Reads `type`, `is_active` and `severity` — the same three columns
	// cmd/detection's ListActiveIOCs uses for live matching.
	//
	// It used to read ioc_type, enabled and threat_level, which are the other
	// half of three duplicated pairs on this table, and the wrong half of each:
	//
	//	type      NOT NULL, CHECK (hash|ip|domain|url|email)
	//	ioc_type  nullable, unconstrained — 4 of the 6 writers never set it,
	//	          including manual adds (store/ioc.go) and the TAXII and STIX
	//	          importers
	//	is_active what store.SetActive toggles, and what live matching filters on
	//	enabled   never updated by anything after insert
	//	severity  1-10, set by every importer
	//	threat_level  defaults to 5 and is left there by every path but one
	//
	// The nullable column was the serious one. A NULL ioc_type fails the Scan
	// below, and in pgx a scan error ends the iteration — so a single manually
	// added indicator did not merely skip itself, it aborted the whole batch
	// and every IOC ordered after it went unhunted. Measured: one well-formed
	// domain IOC loaded on its own; adding one NULL-ioc_type row ahead of it by
	// first_seen dropped the load to nothing.
	//
	// The other two were quieter. Deactivating an indicator through the API
	// clears is_active, which this never consulted, so retro hunting carried on
	// alerting on it. And every retro alert took its severity from
	// threat_level's default rather than the severity the feed actually set.
	rows, err := h.pool.Query(ctx, `
		SELECT value, type, COALESCE(severity, 5)
		FROM ioc_entries
		WHERE is_active = true AND first_seen > $1
		ORDER BY first_seen
		LIMIT $2`,
		watermark, h.maxNewIOCs,
	)
	if err != nil {
		fail(ctx, err, "レトロIOCハンター: 新規IOCを読み込めませんでした")
		return ips, domains, hashes, false
	}
	defer rows.Close()
	for rows.Next() {
		var value, iocType string
		var threat int
		if err := rows.Scan(&value, &iocType, &threat); err != nil {
			// pgx ends iteration on a scan error, so this is the end of the
			// batch whatever we do — say so rather than returning a silently
			// truncated IOC set as though it were complete.
			fail(ctx, err, "レトロIOCハンター: IOC行の読み取りに失敗しました。"+
				"このバッチの残りは処理されません")
			return ips, domains, hashes, false
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
		case "hash", "md5", "sha1", "sha256":
			// The same vocabulary detection.IOCMatcher groups under "hash".
			hashes[strings.ToLower(value)] = threat
		}
	}
	// 途中で失敗した反復は短いIOC集合を残します。watermark を進めると、
	// 読めなかったぶんのIOCは「照合済み」になり二度と対象になりません。
	if err := rows.Err(); err != nil {
		fail(ctx, err, "レトロIOCハンター: IOC一覧の走査に失敗しました。"+
			"このパスは未完了として扱います")
		return ips, domains, hashes, false
	}
	return ips, domains, hashes, true
}

// huntField scans historical events of eventType whose raw_data->>field matches any
// of the given IOC values, creating a deduplicated retro alert per matching event.
// Returns the number of alerts created.
// complete=false means this scan did not cover the whole window it claimed to.
func (h *RetroIOCHunter) huntField(ctx context.Context, eventType, field string, lower bool, iocs, threat iocMeta) (created int, complete bool) {
	if len(iocs) == 0 {
		return 0, true
	}
	values := make([]string, 0, len(iocs))
	for v := range iocs {
		values = append(values, v)
	}

	// Match historical events against the new-IOC value set. `lower` mirrors the
	// lowercased keys the caller built — domains and hashes are folded, dst_ip is
	// compared as-is.
	expr := "raw_data->>'" + field + "'"
	if lower {
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
		fail(ctx, err, "レトロIOCハンター: 履歴スキャン失敗", "event_type", eventType)
		return 0, false
	}
	defer rows.Close()

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
	// 切り詰められた履歴スキャンは「一致なし」と見分けがつきません。
	// この状態で watermark を進めると、走査できなかった区間は
	// 二度と照合されません。
	if err := rows.Err(); err != nil {
		fail(ctx, err, "レトロIOCハンター: 履歴の走査が途中で終わりました。"+
			"このパスは未完了として扱います", "event_type", eventType, "field", field)
		return created, false
	}
	return created, true
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

	// alerts.severity is CHECK (1..10) and ioc_entries.severity uses the same
	// scale. This used to clamp at 5, so a retro hit on a critical indicator
	// could not produce an alert above the middle of the range.
	severity := threat
	if severity < 1 {
		severity = 3
	}
	if severity > 10 {
		severity = 10
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
		fail(ctx, err, "レトロIOCアラート作成に失敗", "title", title)
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
