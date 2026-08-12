// EDR Platform - Detection Engine Server
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edr-platform/server/internal/behavioral"
	"github.com/edr-platform/server/internal/detection"
	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/health"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/scheduler"
	"github.com/edr-platform/server/internal/siem"
	"github.com/edr-platform/server/internal/store"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── Config ───────────────────────────────────────────────
	dbURL := mustEnv("DATABASE_URL")
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	claudeAPIKey := getEnv("CLAUDE_API_KEY", "")
	claudeModel := getEnv("CLAUDE_MODEL", "claude-opus-4-6")
	autoResponse := getEnv("AUTO_RESPONSE_ENABLED", "true") == "true"
	aiEnabled := getEnv("AI_ANALYSIS_ENABLED", "true") == "true"
	baseURL := getEnv("EDR_BASE_URL", "http://localhost")

	// ─── Database ─────────────────────────────────────────────
	// Prefer the non-superuser edr_app runtime role when APP_DATABASE_URL is
	// set (RLS tenant isolation — migration 325). The detection engine sets no
	// app.tenant_id, so the RLS escape clause grants it cross-tenant access as
	// intended. Falls back to DATABASE_URL when unset.
	appDBURL := getEnv("APP_DATABASE_URL", dbURL)
	db, err := store.Connect(ctx, appDBURL)
	if err != nil {
		slog.Error("データベース接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("データベースに接続しました")

	// ─── NATS ─────────────────────────────────────────────────
	nc, err := nats.Connect(natsURL,
		nats.ReconnectWait(5*time.Second),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		slog.Error("NATS接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer nc.Close()

	// ─── Ensure NATS JetStream streams exist ──────────────────
	if err := ensureStreams(nc); err != nil {
		slog.Error("NATSストリームの初期化に失敗しました", "error", err)
		os.Exit(1)
	}

	// ─── Stores ───────────────────────────────────────────────
	alertStore := store.NewAlertStore(db)
	playbookStore := store.NewPlaybookStore(db)
	incidentStore := store.NewIncidentStore(db)
	pool := db.Pool()

	// Wrap alertStore with the adapter to satisfy detection interfaces
	storeAdp := newStoreAdapter(alertStore, pool)

	// ─── Notification ─────────────────────────────────────────
	dispatcher := notification.NewDispatcher(baseURL)
	channels, _ := store.NewNotificationStore(db).ListChannels(ctx)
	notifChannels := make([]notification.ChannelConfig, len(channels))
	for i, ch := range channels {
		notifChannels[i] = notification.ChannelConfig{
			ID:          ch.ID,
			Name:        ch.Name,
			Type:        ch.Type,
			Config:      ch.Config,
			Enabled:     ch.Enabled,
			MinSeverity: ch.MinSeverity,
		}
	}
	dispatcher.LoadChannels(notifChannels)

	// Subscribe to channel config changes so the dispatcher stays in sync
	// when notification channels are added/updated via the settings API.
	go func() {
		sub, err := nc.Subscribe("settings.channels.updated", func(_ *nats.Msg) {
			chs, _ := store.NewNotificationStore(db).ListChannels(ctx)
			updated := make([]notification.ChannelConfig, len(chs))
			for i, ch := range chs {
				updated[i] = notification.ChannelConfig{
					ID: ch.ID, Name: ch.Name, Type: ch.Type,
					Config: ch.Config, Enabled: ch.Enabled, MinSeverity: ch.MinSeverity,
				}
			}
			dispatcher.LoadChannels(updated)
			slog.Info("通知チャンネル設定をリロードしました", "count", len(updated))
		})
		if err != nil {
			slog.Warn("通知チャンネル更新購読に失敗しました", "error", err)
			return
		}
		<-ctx.Done()
		sub.Unsubscribe()
	}()

	// ─── Agent Commander ──────────────────────────────────────
	commander := store.NewCommandStore(db, nc)

	// ─── AI Agent ─────────────────────────────────────────────
	var aiAgent *detection.AIAgent
	if aiEnabled && claudeAPIKey != "" {
		aiAgent = detection.NewAIAgent(claudeAPIKey, storeAdp, commander)
		aiAgent.SetModel(claudeModel)
		slog.Info("Claude AIエージェントを有効化しました", "model", claudeModel)
	} else if aiEnabled {
		slog.Warn("CLAUDE_API_KEYが設定されていないため、AI分析は無効です")
	}

	// ─── Rule Engine ──────────────────────────────────────────
	ruleStore := store.NewRuleStore(db)
	ruleEngine := detectionrules.NewRuleEngine()
	// The OS-scoping gate is on by default (a Windows/Linux/MacOS-only rule is not
	// evaluated against another OS's telemetry). EDR_RULE_PLATFORM_GATE=0 disables
	// it as an escape hatch if a mislabeled platform ever suppresses a detection.
	if v := os.Getenv("EDR_RULE_PLATFORM_GATE"); v == "0" || strings.EqualFold(v, "false") {
		ruleEngine.SetPlatformGate(false)
		slog.Warn("ルールのプラットフォーム・ゲートを無効化しました (EDR_RULE_PLATFORM_GATE)")
	}
	dbRules, err := ruleStore.ListEnabled(ctx)
	if err != nil {
		slog.Warn("ルールの読み込みに失敗しました", "error", err)
	} else {
		detRules := make([]*detectionrules.DetectionRule, len(dbRules))
		for i, r := range dbRules {
			detRules[i] = &detectionrules.DetectionRule{
				ID:          r.ID,
				Name:        r.Name,
				Type:        r.Type,
				Platform:    r.Platform,
				Severity:    r.Severity,
				Content:     r.Content,
				Enabled:     r.Enabled,
				AutoIsolate: r.AutoIsolate,
				AutoKill:    r.AutoKill,
				MITRETags:   r.MITRETags,
			}
		}
		ruleEngine.LoadRules(detRules)
		metrics.RulesLoaded.Store(int64(len(detRules)))
		slog.Info("検知ルールを読み込みました", "count", len(detRules))
	}

	// ─── Rule Reloader ────────────────────────────────────────
	// Reload rules when the API publishes "rules.invalidate" (instant),
	// and also poll every 5 minutes as a safety net.
	go startRuleReloader(ctx, nc, ruleStore, ruleEngine)

	// ─── IOC Matcher ──────────────────────────────────────────
	iocMatcher := detection.NewIOCMatcher(storeAdp)
	iocMatcher.Start(ctx)
	// Reload IOC cache when ioc.invalidate is published (e.g. after IOC add/delete via API)
	go func() {
		sub, err := nc.Subscribe("ioc.invalidate", func(_ *nats.Msg) {
			iocMatcher.RefreshNow(ctx)
			slog.Info("IOCキャッシュをリフレッシュしました (NATS シグナル)")
		})
		if err != nil {
			slog.Warn("ioc.invalidate購読に失敗しました", "error", err)
			return
		}
		<-ctx.Done()
		sub.Unsubscribe()
	}()
	slog.Info("IOCマッチャーを起動しました", "cached", iocMatcher.CacheSize())

	// ─── Suppression Matcher ───────────────────────────────────
	suppressionMatcher := detection.NewSuppressionMatcher(storeAdp)
	suppressionMatcher.Start(ctx)
	// Reload suppression cache when suppressions.invalidate is published
	go func() {
		sub, err := nc.Subscribe("suppressions.invalidate", func(_ *nats.Msg) {
			suppressionMatcher.RefreshNow(ctx)
			slog.Info("抑制ルールキャッシュをリフレッシュしました (NATS シグナル)")
		})
		if err != nil {
			slog.Warn("suppressions.invalidate購読に失敗しました", "error", err)
			return
		}
		<-ctx.Done()
		sub.Unsubscribe()
	}()
	slog.Info("抑制マッチャーを起動しました", "rules", suppressionMatcher.Count())

	// ─── Detection Engine ─────────────────────────────────────
	autoIsolateThreshold := 9
	if v := os.Getenv("AUTO_ISOLATE_MIN_SEVERITY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10 {
			autoIsolateThreshold = n
		} else {
			slog.Warn("AUTO_ISOLATE_MIN_SEVERITY の値が無効です。デフォルト(9)を使用します", "value", v)
		}
	}

	engineConfig := detection.EngineConfig{
		AutoResponseEnabled:          autoResponse,
		AIAnalysisMinSeverity:        5,
		AIAnalysisMinAnomalyScore:    0.6,
		AIAnalysisConcurrency:        5,
		AutoIsolateSeverityThreshold: autoIsolateThreshold,
	}

	// ─── Playbook Runner ──────────────────────────────────────
	playbookRunner := detection.NewPlaybookRunner(playbookStore, incidentStore, commander, dispatcher, autoResponse)

	engine, err := detection.NewEngine(nc, storeAdp, aiAgent, commander, ruleEngine, dispatcher, playbookRunner, iocMatcher, suppressionMatcher, engineConfig)
	if err != nil {
		slog.Error("検知エンジンの初期化に失敗しました", "error", err)
		os.Exit(1)
	}
	engine.SetSuppressionHitCounter(store.NewSuppressionStore(db))
	engine.SetBehavioralEngine(ml.NewBehavioralEngine())

	// Per-agent behavioral baseline (live unknown-process detection). Build
	// in-memory baselines for active agents on start + every 6h so the engine can
	// flag processes never seen in an agent's own history. Gated by
	// EDR_BASELINE_ALERTS (default on); independent of the API server's rebuilder.
	baselineEngine := behavioral.NewEngine(pool)
	go func() {
		build := func() {
			rows, err := pool.Query(ctx, `SELECT id::text FROM agents WHERE last_seen >= NOW() - INTERVAL '7 days' OR status = 'online'`)
			if err != nil {
				slog.Warn("ベースライン構築: エージェント一覧取得失敗", "error", err)
				return
			}
			var ids []string
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				_, _ = baselineEngine.BuildBaseline(ctx, id, 14)
			}
			slog.Info("行動ベースライン構築完了", "agents", len(ids))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		build()
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				build()
			}
		}
	}()
	baselineEnabled := os.Getenv("EDR_BASELINE_ALERTS") != "0"
	engine.SetBaselineEngine(baselineEngine, baselineEnabled)
	slog.Info("行動ベースライン検知を設定しました", "enabled", baselineEnabled)
	slog.Info("行動分析エンジン(チェーン検知)起動済み")

	// ─── SIEM Forwarder ───────────────────────────────────────
	siemStore := store.NewSIEMStore(db)
	siemForwarder := siem.NewForwarder()
	if targets, err := siemStore.List(ctx); err == nil && len(targets) > 0 {
		siemTargets := make([]*siem.Target, len(targets))
		for i, t := range targets {
			siemTargets[i] = &siem.Target{
				ID:          t.ID,
				Name:        t.Name,
				Type:        t.Type,
				Host:        t.Host,
				Port:        t.Port,
				Protocol:    t.Protocol,
				Token:       t.Token,
				TLSEnabled:  t.TLSEnabled,
				IndexName:   t.IndexName,
				Enabled:     t.Enabled,
				MinSeverity: t.MinSeverity,
			}
		}
		siemForwarder.LoadTargets(siemTargets)
		slog.Info("SIEMターゲットを読み込みました", "count", len(siemTargets))
	}
	engine.SetSIEMForwarder(&siemForwarderAdapter{f: siemForwarder})

	// Reload SIEM targets when the API signals a config change
	go func() {
		sub, err := nc.Subscribe("siem.targets.updated", func(_ *nats.Msg) {
			targets, err := siemStore.List(ctx)
			if err != nil {
				slog.Warn("SIEMターゲットのリロードに失敗しました", "error", err)
				return
			}
			updated := make([]*siem.Target, len(targets))
			for i, t := range targets {
				updated[i] = &siem.Target{
					ID:          t.ID,
					Name:        t.Name,
					Type:        t.Type,
					Host:        t.Host,
					Port:        t.Port,
					Protocol:    t.Protocol,
					Token:       t.Token,
					TLSEnabled:  t.TLSEnabled,
					IndexName:   t.IndexName,
					Enabled:     t.Enabled,
					MinSeverity: t.MinSeverity,
				}
			}
			siemForwarder.LoadTargets(updated)
			slog.Info("SIEMターゲットをリロードしました", "count", len(updated))
		})
		if err != nil {
			slog.Warn("siem.targets.updated購読に失敗しました", "error", err)
			return
		}
		<-ctx.Done()
		sub.Unsubscribe()
	}()

	// ─── ML Anomaly Detector ──────────────────────────────────
	anomalyDetector := detection.NewAnomalyDetector(pool, storeAdp)
	go anomalyDetector.Run(ctx)
	slog.Info("ML異常検知エンジンを起動しました")

	// ─── Risk Score Auto-Action Monitor ───────────────────────
	riskMonitor := detection.NewRiskActionMonitor(pool, storeAdp)
	go riskMonitor.Run(ctx)
	slog.Info("リスクスコア自動アクションモニターを起動しました")

	// ─── Heartbeat Monitor ────────────────────────────────────
	hbTimeout := getEnvInt("HEARTBEAT_TIMEOUT_MINUTES", 5)
	hbInterval := getEnvInt("HEARTBEAT_INTERVAL_MINUTES", 2)
	heartbeatMonitor := detection.NewHeartbeatMonitorWithConfig(pool, storeAdp, hbTimeout, hbInterval)
	go heartbeatMonitor.Run(ctx)
	slog.Info("ハートビート監視を起動しました",
		"timeout_minutes", hbTimeout,
		"interval_minutes", hbInterval,
	)

	// ─── Alert Correlation Engine ─────────────────────────────
	storeAdp.setIncidentStore(incidentStore)
	corrThreshold := getEnvInt("CORRELATION_THRESHOLD", 3)
	corrWindowMin := getEnvInt("CORRELATION_WINDOW_MINUTES", 60)
	corrWindow := time.Duration(corrWindowMin) * time.Minute
	correlationEngine := detection.NewCorrelationEngineWithConfig(pool, storeAdp, corrThreshold, corrWindow)
	go correlationEngine.Run(ctx)
	slog.Info("アラート相関エンジンを起動しました",
		"threshold", corrThreshold,
		"window_minutes", corrWindowMin,
	)

	// Retroactive rule hunter: re-evaluate recent process history against rules
	// enabled AFTER those events happened, so a newly-added detection catches
	// attacks that predate it. Advances a watermark over rule-creation time.
	go scheduler.NewRetroRuleHunter(pool, ruleEngine, 24, time.Hour).Run(ctx)
	slog.Info("レトロルールハンターを起動しました", "lookback_hours", 24)

	// ─── Insider-Threat & Network-Anomaly Detectors (batch) ───
	// Real detectors that were implemented but never started. Each guards on its
	// source table (audit_logs / network_connections) existing, so they no-op
	// gracefully where the data isn't present (migration 270 adds alerts.source).
	go scheduler.NewInsiderThreatDetector(pool, nc).Run(ctx)
	go scheduler.NewNetworkAnomalyDetector(pool, nc).Run(ctx)
	slog.Info("インサイダー脅威・ネットワーク異常検知スケジューラーを起動しました")

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("シャットダウン中...")
		cancel()
	}()

	slog.Info("検知エンジンを起動中",
		"auto_response", autoResponse,
		"ai_enabled", aiEnabled,
	)

	// Start metrics HTTP server on :8081
	metricsPort := getEnv("METRICS_PORT", "8081")
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", metrics.Handler())
		// Liveness (process alive) vs readiness (DB + NATS reachable). /health stays
		// a liveness alias for backward compatibility with existing healthchecks.
		mux.HandleFunc("/health", health.LivenessHandler())
		mux.HandleFunc("/healthz", health.LivenessHandler())
		mux.HandleFunc("/readyz", health.ReadinessHandler(pool, nc))
		if err := http.ListenAndServe(":"+metricsPort, mux); err != nil {
			slog.Warn("メトリクスサーバーエラー", "error", err)
		}
	}()

	// Start detection engine (blocks)
	if err := engine.Start(ctx); err != nil && ctx.Err() == nil {
		slog.Error("検知エンジンエラー", "error", err)
		os.Exit(1)
	}

	slog.Info("検知エンジンを停止しました")
}

// startRuleReloader reloads detection rules from DB both on NATS signal
// and on a periodic 5-minute poll, so in-flight rule edits take effect quickly.
func startRuleReloader(
	ctx context.Context,
	nc *nats.Conn,
	ruleStore *store.RuleStore,
	engine *detectionrules.RuleEngine,
) {
	reload := func(reason string) {
		dbRules, err := ruleStore.ListEnabled(ctx)
		if err != nil {
			slog.Warn("ルールのリロードに失敗しました", "reason", reason, "error", err)
			return
		}
		detRules := make([]*detectionrules.DetectionRule, len(dbRules))
		for i, r := range dbRules {
			detRules[i] = &detectionrules.DetectionRule{
				ID:          r.ID,
				Name:        r.Name,
				Type:        r.Type,
				Platform:    r.Platform,
				Severity:    r.Severity,
				Content:     r.Content,
				Enabled:     r.Enabled,
				AutoIsolate: r.AutoIsolate,
				AutoKill:    r.AutoKill,
				MITRETags:   r.MITRETags,
			}
		}
		engine.LoadRules(detRules)
		slog.Info("検知ルールをリロードしました", "reason", reason, "count", len(detRules))
	}

	// Subscribe to invalidation signal from the API server
	invalidateCh := make(chan struct{}, 1)
	sub, err := nc.Subscribe("rules.invalidate", func(_ *nats.Msg) {
		select {
		case invalidateCh <- struct{}{}:
		default: // already pending
		}
	})
	if err != nil {
		slog.Warn("rules.invalidate購読に失敗しました (ポーリングのみ)", "error", err)
	} else {
		defer sub.Unsubscribe()
	}

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-invalidateCh:
			reload("rules.invalidate")
		case <-ticker.C:
			reload("periodic")
		}
	}
}

func ensureStreams(nc *nats.Conn) error {
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	ctx := context.Background()

	streams := []struct {
		name     string
		subjects []string
		maxAge   time.Duration
	}{
		{"EVENTS", []string{"events.>"}, 7 * 24 * time.Hour},
		{"ALERTS", []string{"alerts.>"}, 30 * 24 * time.Hour},
		{"COMMANDS", []string{"commands.>"}, 1 * time.Hour},
	}

	for _, s := range streams {
		cfg := jetstream.StreamConfig{
			Name:      s.name,
			Subjects:  s.subjects,
			Storage:   jetstream.FileStorage,
			Retention: jetstream.LimitsPolicy,
			MaxAge:    s.maxAge,
			MaxBytes:  -1, // no per-stream limit; server manages storage
			Replicas:  1,
			// ingestion (internal/ingestion/handler.go) declares the same three
			// streams. The two configs must stay identical, or whichever service
			// starts second tries to mutate the first one's stream.
			Duplicates: 5 * time.Minute,
		}
		_, err := js.CreateOrUpdateStream(ctx, cfg)
		// CreateOrUpdateStream is Update-then-Create, so two services bootstrapping
		// the same stream at once race: this one sees ErrStreamNotFound from the
		// update, ingestion creates the stream in between, and the create leg comes
		// back ErrStreamNameAlreadyInUse. That is not a failure — the stream we
		// wanted now exists — but treating it as one crashed detection on startup
		// and took the whole detection engine down whenever ingestion won the race.
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			_, err = js.UpdateStream(ctx, cfg)
		}
		if err != nil {
			return fmt.Errorf("stream %s: %w", s.name, err)
		}
		slog.Info("NATSストリームを確認/作成しました", "name", s.name)
	}
	return nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("環境変数が設定されていません", "key", key)
		os.Exit(1)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		slog.Warn("環境変数が不正な整数値です。デフォルトを使用します", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return n
}
