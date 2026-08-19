package scheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// ThreatFeedImporter periodically fetches all enabled threat feeds and imports IOCs.
type ThreatFeedImporter struct {
	pool    *pgxpool.Pool
	nc      *nats.Conn
	enabled bool // THREAT_FEED_SYNC_ENABLED（既定 true）
}

// NewThreatFeedImporter creates a ThreatFeedImporter.
func NewThreatFeedImporter(pool *pgxpool.Pool, nc *nats.Conn) *ThreatFeedImporter {
	return &ThreatFeedImporter{pool: pool, nc: nc, enabled: true}
}

// WithEnabled は外向きのフィード取得そのものを止められるようにする。
// FeedScheduler と同じスイッチで動く（どちらも同じ threat_feeds を引くため、
// 片方だけ止めても外向き通信は残ってしまう）。
func (t *ThreatFeedImporter) WithEnabled(enabled bool) *ThreatFeedImporter {
	t.enabled = enabled
	return t
}

// Run starts the importer loop. Designed to be called as a goroutine.
func (t *ThreatFeedImporter) Run(ctx context.Context) {
	if !t.enabled {
		slog.Info("脅威フィードインポーター: 無効です (THREAT_FEED_SYNC_ENABLED=false)")
		return
	}
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	slog.Info("脅威フィードインポーターを起動しました")
	trackRun(ctx, "threat_feed_importer", t.importAll)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "threat_feed_importer", t.importAll)
		}
	}
}

func (t *ThreatFeedImporter) importAll(ctx context.Context) {
	// Check that threat_feeds table exists
	var exists bool
	err := t.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='threat_feeds')`).Scan(&exists)
	if err != nil {
		fail(ctx, err, "脅威フィード: threat_feeds テーブルの有無を確認できませんでした")
		return
	}
	if !exists {
		// 配備でこの機能を使っていないだけ。失敗ではありません。
		return
	}

	// TAXII 2.1 feeds are owned by FeedScheduler (internal/intel.TAXIIClient):
	// they need the TAXII Accept header, auth, added_after paging and STIX
	// parsing that this legacy importer lacks. Exclude them here so a taxii21
	// feed isn't double-fetched as a plain-text URL (which only produced a
	// redundant request + error log, since the "default" branch never upserts).
	rows, err := t.pool.Query(ctx,
		`SELECT id, name, url, COALESCE(format,'') FROM threat_feeds
		 WHERE enabled = TRUE AND COALESCE(source_format,'') <> 'taxii21'`)
	if err != nil {
		fail(ctx, err, "脅威フィードの取得に失敗しました")
		return
	}
	defer rows.Close()

	type feedRow struct {
		id     string
		name   string
		url    string
		format string
	}
	var feeds []feedRow
	for rows.Next() {
		var f feedRow
		if err := rows.Scan(&f.id, &f.name, &f.url, &f.format); err != nil {
			continue
		}
		feeds = append(feeds, f)
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "フィード一覧の走査が途中で終わりました。今回のパスで取り込まないフィードがあります")
	}
	rows.Close()

	for _, feed := range feeds {
		t.importFeed(ctx, feed.id, feed.name, feed.url, feed.format)
	}
}

func (t *ThreatFeedImporter) importFeed(ctx context.Context, feedID, feedName, url, format string) {
	start := time.Now()

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fail(ctx, err, "フィードリクエストの作成に失敗しました", "feed", feedName)
		return
	}
	req.Header.Set("User-Agent", "EDR-Platform-ThreatFeedImporter/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fail(ctx, err, "フィードの取得に失敗しました", "feed", feedName)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		fail(ctx, err, "フィードの読み取りに失敗しました", "feed", feedName)
		return
	}
	body := string(bodyBytes)

	// 保存先テーブルの存在確認。以前は存在しない `iocs` を見ていたため
	// doUpsert が常に false になり、upsertIOC が一度も呼ばれていなかった。
	// 実テーブルは migration 177 の threat_intel_iocs。
	var iocsExists bool
	if err := t.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		  WHERE table_schema='public' AND table_name='threat_intel_iocs')`).Scan(&iocsExists); err != nil {
		fail(ctx, err, "IOC保存先テーブルの確認に失敗しました")
	}

	var count int
	switch strings.ToLower(format) {
	case "csv":
		count = t.importCSV(ctx, body, feedName, feedID, iocsExists)
	case "json":
		count = t.importJSON(ctx, body, feedName, feedID, iocsExists)
	case "stix":
		count = t.countSTIXIndicators(ctx, body)
	default:
		count = t.countLines(body)
	}

	durationMs := time.Since(start).Milliseconds()
	slog.Info("フィードインポート完了", "feed", feedName, "count", count, "duration_ms", durationMs)

	if t.nc != nil {
		payload := map[string]interface{}{
			"feed_id":        feedID,
			"feed_name":      feedName,
			"count_imported": count,
			"duration_ms":    durationMs,
		}
		b, _ := json.Marshal(payload)
		_ = t.nc.Publish("threat_feed.imported", b)
	}
}

func (t *ThreatFeedImporter) importCSV(ctx context.Context, body, source, feedID string, doUpsert bool) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 4)
		if len(parts) < 2 {
			continue
		}
		indicator := strings.TrimSpace(parts[0])
		iocType := strings.TrimSpace(parts[1])
		severity := "medium"
		description := ""
		if len(parts) > 2 {
			severity = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			description = strings.TrimSpace(parts[3])
		}
		if indicator == "" {
			continue
		}
		if doUpsert {
			t.upsertIOC(ctx, indicator, iocType, severity, source, description)
		}
		count++
	}
	return count
}

func (t *ThreatFeedImporter) importJSON(ctx context.Context, body, source, feedID string, doUpsert bool) int {
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &items); err != nil {
		fail(ctx, err, "JSONフィードのパースに失敗しました", "source", source)
		return 0
	}
	count := 0
	for _, item := range items {
		indicator, _ := item["indicator"].(string)
		if indicator == "" {
			indicator, _ = item["value"].(string)
		}
		if indicator == "" {
			continue
		}
		iocType, _ := item["type"].(string)
		severity, _ := item["severity"].(string)
		description, _ := item["description"].(string)
		if doUpsert {
			t.upsertIOC(ctx, indicator, iocType, severity, source, description)
		}
		count++
	}
	return count
}

func (t *ThreatFeedImporter) countSTIXIndicators(ctx context.Context, body string) int {
	var bundle map[string]interface{}
	if err := json.Unmarshal([]byte(body), &bundle); err != nil {
		fail(ctx, err, "脅威フィード: STIX バンドルを読めないため0件として数えました")
		return 0
	}
	objects, _ := bundle["objects"].([]interface{})
	count := 0
	for _, obj := range objects {
		m, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}
		if t2, _ := m["type"].(string); t2 == "indicator" {
			count++
		}
	}
	return count
}

func (t *ThreatFeedImporter) countLines(body string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

// iocSeverityToInt はフィードが文字列で持つ深刻度を、threat_intel_iocs.severity
// (INTEGER, alerts と同じ 1–10 スケール) に写す。未知の値は列のデフォルトと同じ 5。
func iocSeverityToInt(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	case "info", "informational":
		return 1
	default:
		return 5
	}
}

// upsertIOC は取り込んだインジケータを threat_intel_iocs に登録する。
//
// 以前は存在しない `iocs` テーブルへ INSERT しており、しかもエラーを握りつぶして
// いたため、フィードの取得に成功していても IOC が 1 件も保存されていなかった。
// 実テーブルは migration 177 の threat_intel_iocs で、
//   - description 列は無い（説明は tags に載せる）
//   - severity は INTEGER（フィードは "high" 等の文字列で持つ）
//   - 一意制約は (ioc_type, value) であって value 単独ではない
//
// という 3 点が食い違っていた。
func (t *ThreatFeedImporter) upsertIOC(ctx context.Context, value, iocType, severity, source, description string) {
	if iocType == "" {
		iocType = "unknown"
	}
	tags := []string{}
	if description != "" {
		tags = append(tags, description)
	}
	if _, err := t.pool.Exec(ctx,
		`INSERT INTO threat_intel_iocs (id, ioc_type, value, severity, source, tags, created_at)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (ioc_type, value) DO NOTHING`,
		iocType, value, iocSeverityToInt(severity), source, tags,
	); err != nil {
		fail(ctx, err, "IOCの登録に失敗しました", "value", value, "source", source)
	}
}
