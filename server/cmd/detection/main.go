// EDR Platform - Detection Engine Server
package main

import (
	"context"
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
	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/natsstream"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/scheduler"
	"github.com/edr-platform/server/internal/siem"
	"github.com/edr-platform/server/internal/store"
	"github.com/edr-platform/server/internal/tick"
	"github.com/nats-io/nats.go"
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
	if err := natsstream.Ensure(context.Background(), nc); err != nil {
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

	// ─── 隔離のゲートキーパー ─────────────────────────────────
	// 隔離を実行できるのはこれだけ。安全弁（冷却期間・時間あたり上限・ドライラン）と
	// response_actions への記録はここに集約されている。ルールベース・プレイブック・
	// AI トリアージはいずれもこれを通る。
	//   AUTO_ISOLATE_COOLDOWN       同じ端末を再隔離するまでの最短間隔（既定 30m）
	//   AUTO_ISOLATE_HOURLY_BUDGET  1 時間あたりに隔離を許す台数（既定 3）
	//   AUTO_ISOLATE_DRY_RUN        true なら隔離せず記録だけ（段階的に有効化する用）
	isoCooldown := isolation.DefaultCooldown
	if v := os.Getenv("AUTO_ISOLATE_COOLDOWN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			isoCooldown = d
		} else {
			slog.Warn("AUTO_ISOLATE_COOLDOWN の値が無効です。既定(30m)を使用します", "value", v)
		}
	}
	isoBudget := isolation.DefaultHourlyBudget
	if v := os.Getenv("AUTO_ISOLATE_HOURLY_BUDGET"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			isoBudget = n
		} else {
			slog.Warn("AUTO_ISOLATE_HOURLY_BUDGET の値が無効です。既定(3)を使用します", "value", v)
		}
	}
	isoDryRun := os.Getenv("AUTO_ISOLATE_DRY_RUN") == "true"
	if isoDryRun {
		slog.Warn("自動隔離はドライランです。隔離は実行されず、記録だけ残ります")
	}
	if !autoResponse {
		slog.Warn("AUTO_RESPONSE_ENABLED=false のため、無人経路からの隔離は行いません")
	}
	// 除外リストはエンジン側でも見ているが、Gatekeeper にも渡す。エンジンの
	// 検査は「どのルールが隔離しようとしたか」を含む詳しい記録を残せる位置に
	// あり、Gatekeeper の検査はそこを通らない経路（プレイブック・自動修復・
	// API 呼び出し）に対する最後の関門になる。判定そのものは
	// isolation.IsExempt に一本化してあるので、二つが食い違うことはない。
	var autoIsolateExempt []string
	for _, h := range strings.Split(os.Getenv("AUTO_ISOLATE_EXEMPT"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			autoIsolateExempt = append(autoIsolateExempt, h)
		}
	}
	if len(autoIsolateExempt) > 0 {
		slog.Info("自動隔離の除外対象を設定しました", "entries", len(autoIsolateExempt),
			"対象", autoIsolateExempt)
	}
	gatekeeper := isolation.New(commander, store.NewResponseActionStore(db), isolation.Config{
		UnattendedEnabled: autoResponse,
		Cooldown:          isoCooldown,
		HourlyBudget:      isoBudget,
		DryRun:            isoDryRun,
		Exempt:            autoIsolateExempt,
	})

	// ─── AI Agent ─────────────────────────────────────────────
	var aiAgent *detection.AIAgent
	if aiEnabled && claudeAPIKey != "" {
		aiAgent = detection.NewAIAgent(claudeAPIKey, storeAdp, commander, gatekeeper)
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

	// Who evaluates the `rules` table's Sigma rules.
	//
	// Since P4-6 the api server's AlertPipeline loads that table too, so leaving it
	// on here means BOTH processes evaluate every DB Sigma rule and one event
	// becomes two alert rows. Dedup merges them but does not delete them.
	//
	// The switch is EDR_SIGMA_DB_RULES, the SAME variable the api reads, with the
	// opposite sense — so the two processes cannot both own the rules and cannot
	// both skip them. Unset (the default) means the api owns them, because this
	// service's JetStream consumer lags chronically and a late alert is worse than
	// a prompt one elsewhere. Setting it to 0 sheds the load from the api and hands
	// ownership back here.
	//
	// Evidence for the default: internal/detection's
	// TestMigrationSigmaFieldSupportInAPIEvaluator (the api resolves every field
	// the DB rules select on, bar three that are dead in both engines) and
	// TestBothEnginesAgreeOnDBRules (215 of 242 rules driven through both engines
	// with events built from their own selectors — no disagreements).
	dbSigmaHere := false
	if v := os.Getenv("EDR_SIGMA_DB_RULES"); v == "0" || strings.EqualFold(v, "false") ||
		strings.EqualFold(v, "no") || strings.EqualFold(v, "off") {
		dbSigmaHere = true
	}
	ruleEngine.SetDBSigmaEvaluation(dbSigmaHere)
	if dbSigmaHere {
		slog.Warn("DB Sigma ルールを本サービスが評価します (EDR_SIGMA_DB_RULES=0) — " +
			"api 側は読み込みません")
	} else {
		slog.Info("DB Sigma ルールは api サーバ (AlertPipeline) が評価します — " +
			"本サービスはスキップします (二重評価の回避)")
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

	// Hosts that must never be auto-isolated. Isolation cuts every connection except
	// the EDR server, so isolating the box that RUNS the platform (or an operator's
	// jump host) is an outage plus a lockout that needs out-of-band access to undo.
	// Detection and alerting on these hosts are unaffected — only the response is.
	//
	// これは gatekeeper の安全弁（冷却期間・時間あたり上限・ドライラン、上部参照）とは
	// 別の軸である。安全弁は「隔離の総量」を抑えるが、こちらは「この端末は何があっても
	// 隔離しない」を表す。総量の上限に余裕があっても除外対象は隔離されない。
	// autoIsolateExempt は gatekeeper の構築時に読み込み済み（上部参照）。

	engineConfig := detection.EngineConfig{
		AutoResponseEnabled:          autoResponse,
		AIAnalysisMinSeverity:        5,
		AIAnalysisMinAnomalyScore:    0.6,
		AIAnalysisConcurrency:        5,
		AutoIsolateSeverityThreshold: autoIsolateThreshold,
		AutoIsolateExempt:            autoIsolateExempt,
		GeoIPEnrichEnabled:           getEnv("GEOIP_ENRICH_ENABLED", "false") == "true",
		UEBAAnomalyThreshold:         getEnvFloat("UEBA_ANOMALY_THRESHOLD", 0),
	}

	// ─── Playbook Runner ──────────────────────────────────────
	playbookRunner := detection.NewPlaybookRunner(playbookStore, incidentStore, alertStore, gatekeeper, dispatcher)

	engine, err := detection.NewEngine(nc, storeAdp, aiAgent, gatekeeper, ruleEngine, dispatcher, playbookRunner, iocMatcher, suppressionMatcher, engineConfig)
	if err != nil {
		slog.Error("検知エンジンの初期化に失敗しました", "error", err)
		os.Exit(1)
	}
	engine.SetSuppressionHitCounter(store.NewSuppressionStore(db))
	// 自分の封じ込め操作が端末のファイアウォールを変え、それをファイアウォール改変の
	// ルールが検知する自己検知ループを止める。detection/self_remediation_suppression.go
	engine.SetSelfRemediationSuppressor(detection.NewSelfRemediationSuppressor(store.NewResponseActionStore(db)))
	engine.SetBehavioralEngine(ml.NewBehavioralEngine())

	// Per-agent behavioral baseline (live unknown-process detection). Build
	// in-memory baselines for active agents on start + every 6h so the engine can
	// flag processes never seen in an agent's own history. Gated by
	// EDR_BASELINE_ALERTS (default on); independent of the API server's rebuilder.
	baselineEngine := behavioral.NewEngine(pool)
	go func() {
		build := func(ctx context.Context) {
			rows, err := pool.Query(ctx, `SELECT id::text FROM agents WHERE last_seen >= NOW() - INTERVAL '7 days' OR status = 'online'`)
			if err != nil {
				// **1つもベースラインを作れていません。** 未知プロセスの
				// 検知は、古いベースラインか空のまま動き続けます。
				tick.Fail(ctx, err, "ベースライン構築: エージェント一覧を取得できませんでした")
				return
			}
			var ids []string
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rowsErr := rows.Err()
			rows.Close()
			if rowsErr != nil {
				// pgx は Scan が失敗した時点で結果セットを終えるので、
				// **ここまでに読めた端末しかベースラインを作りません。**
				tick.Fail(ctx, rowsErr, "ベースライン構築: エージェント一覧を読み切れませんでした",
					"read", len(ids))
			}
			built := 0
			for _, id := range ids {
				if _, err := baselineEngine.BuildBaseline(ctx, id, 14); err != nil {
					tick.Fail(ctx, err, "ベースラインを構築できませんでした", "agent_id", id)
					continue
				}
				built++
			}
			slog.Info("行動ベースライン構築完了", "agents", len(ids), "built", built)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		tick.Run(ctx, "behavioral_baseline_builder", build)
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				tick.Run(ctx, "behavioral_baseline_builder", build)
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
			tick.Run(ctx, "detection_rule_reload", func(context.Context) { reload("periodic") })
		}
	}
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

// getEnvFloat reads a non-negative float env var (e.g. UEBA_ANOMALY_THRESHOLD, a
// 0-100 risk score), returning fallback when unset or invalid.
func getEnvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		slog.Warn("環境変数が不正な数値です。デフォルトを使用します", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return f
}
