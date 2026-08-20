// EDR Platform - REST API Server
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/agentconfig"
	"github.com/edr-platform/server/internal/api"
	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/apikeys"
	"github.com/edr-platform/server/internal/audit"
	"github.com/edr-platform/server/internal/auth"
	"github.com/edr-platform/server/internal/backup"
	"github.com/edr-platform/server/internal/behavioral"
	"github.com/edr-platform/server/internal/cache"
	"github.com/edr-platform/server/internal/cert"
	"github.com/edr-platform/server/internal/cloud"
	compliancepkg "github.com/edr-platform/server/internal/compliance"
	edrconfig "github.com/edr-platform/server/internal/config"
	"github.com/edr-platform/server/internal/correlation"
	"github.com/edr-platform/server/internal/dedup"
	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/enrichment"
	"github.com/edr-platform/server/internal/hunting"
	"github.com/edr-platform/server/internal/investigation"
	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/license"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/netanalysis"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/notify"
	"github.com/edr-platform/server/internal/remediation"
	"github.com/edr-platform/server/internal/reports"
	"github.com/edr-platform/server/internal/scheduler"
	"github.com/edr-platform/server/internal/scorecard"
	"github.com/edr-platform/server/internal/shipper"
	"github.com/edr-platform/server/internal/siem"
	"github.com/edr-platform/server/internal/store"
	"github.com/edr-platform/server/internal/support"
	edrsync "github.com/edr-platform/server/internal/sync"
	"github.com/edr-platform/server/internal/telemetry"
	"github.com/edr-platform/server/internal/threatintel"
	"github.com/edr-platform/server/internal/tick"
	"github.com/edr-platform/server/internal/watchlist"
	"github.com/edr-platform/server/internal/webhooks"
	"github.com/edr-platform/server/internal/xdr"
	"github.com/edr-platform/server/internal/zerotrust"
	"github.com/nats-io/nats.go"
)

// Version, BuildDate, and Commit are injected at build time via:
//
//	-ldflags "-X main.Version=1.0.0 -X main.BuildDate=2026-04-13 -X main.Commit=abc1234"
var (
	Version   = "dev"
	BuildDate = "unknown"
	Commit    = "unknown"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── OpenTelemetry Tracing ────────────────────────────────
	shutdown, err := telemetry.InitTracer(ctx, "edr-api")
	if err != nil {
		slog.Warn("トレーサーの初期化に失敗しました", "error", err)
	} else {
		defer shutdown(ctx)
	}

	// ─── Config from environment ──────────────────────────────
	dbURL := mustEnv("DATABASE_URL")
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	apiPort := getEnv("API_PORT", "8080")

	// ─── Validate secrets ─────────────────────────────────────
	secretCfg, err := edrconfig.LoadAndValidate()
	if err != nil {
		slog.Error("設定の検証に失敗しました", "error", err)
		os.Exit(1)
	}
	jwtSecret := secretCfg.JWTSecret
	baseURL := getEnv("EDR_BASE_URL", "http://localhost")
	frontendURL := getEnv("FRONTEND_URL", baseURL)
	if strings.HasPrefix(baseURL, "http://") && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		slog.Warn("EDR_BASE_URL が HTTP を使用しています。本番環境では HTTPS を推奨します", "base_url", baseURL)
	}
	// Warn at startup if ADMIN_PASSWORD is missing — login will return 503 until it's set.
	if getEnv("ADMIN_PASSWORD", "") == "" {
		slog.Warn("ADMIN_PASSWORD 環境変数が設定されていません。管理者アカウントへのログインは ADMIN_PASSWORD が設定されるまで利用できません")
	}

	// ─── SSO stub safety guard ────────────────────────────────
	// EDR_SSO_STUB=true は SSO 認証を完全にバイパスしてデモ JWT を発行する開発専用
	// バックドア。本番での誤設定（デバッグ用設定の置き忘れ等）を防ぐため二重 opt-in を
	// 要求し、EDR_SSO_STUB だけが true で確認用変数が無い場合はフェイルクローズで起動を拒否する。
	if getEnv("EDR_SSO_STUB", "") == "true" && getEnv("EDR_SSO_STUB_CONFIRM_INSECURE", "") != "true" {
		slog.Error("EDR_SSO_STUB=true は SSO 認証をバイパスする開発専用バックドアです。" +
			"本番での誤設定を防ぐため起動を拒否しました。" +
			"開発環境で意図的に使う場合は EDR_SSO_STUB_CONFIRM_INSECURE=true も設定してください。" +
			"本番環境では EDR_SSO_STUB を削除してください")
		os.Exit(1)
	}
	anthropicKey := getEnv("ANTHROPIC_API_KEY", "")

	// ─── Database ─────────────────────────────────────────────
	// Runtime application connection. When APP_DATABASE_URL is set it should
	// point at the non-superuser edr_app role so PostgreSQL RLS actually
	// enforces multi-tenant isolation (migration 325 /
	// docs/security/マルチテナント分離ハードニング.md). When empty it falls back
	// to DATABASE_URL (the owner role), preserving current behavior.
	appDBURL := getEnv("APP_DATABASE_URL", dbURL)
	db, err := store.Connect(ctx, appDBURL)
	if err != nil {
		slog.Error("データベース接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("データベースに接続しました")

	// ─── Migrations ───────────────────────────────────────────
	// Migrations require owner/DDL privileges, so they ALWAYS run via
	// DATABASE_URL (the edr owner role) — never via the least-privilege
	// APP_DATABASE_URL runtime connection. When the two are identical
	// (APP_DATABASE_URL unset) we reuse the app pool to avoid a second connect.
	if getEnv("RUN_MIGRATIONS", "false") == "true" {
		migrationsDir := getEnv("MIGRATIONS_DIR", "migrations")
		if appDBURL == dbURL {
			if err := store.RunMigrations(ctx, db.Pool(), migrationsDir); err != nil {
				slog.Error("マイグレーションに失敗しました", "error", err)
				os.Exit(1)
			}
		} else {
			ownerDB, oerr := store.Connect(ctx, dbURL)
			if oerr != nil {
				slog.Error("マイグレーション用の所有者接続に失敗しました", "error", oerr)
				os.Exit(1)
			}
			merr := store.RunMigrations(ctx, ownerDB.Pool(), migrationsDir)
			ownerDB.Close()
			if merr != nil {
				slog.Error("マイグレーションに失敗しました", "error", merr)
				os.Exit(1)
			}
		}
	}

	// Say out loud, once, which build this is and how far the database schema has
	// been taken. A deployment ran for days on an image whose migrations stopped 20+
	// files short of the repository (2026-08-03) and nothing surfaced it: the API was
	// healthy, the version string was plausible, and the missing files were rule
	// definitions whose absence only shows up as detections that never fire. The
	// applied count comes from the database, so it cannot be faked by a stale build
	// context the way a version string can.
	if count, latest, merr := store.MigrationState(ctx, db.Pool()); merr == nil {
		slog.Info("ビルドとスキーマの状態",
			"version", Version, "commit", Commit, "build_date", BuildDate,
			"migrations_applied", count, "migrations_latest", latest)
	} else {
		slog.Warn("マイグレーション適用状況を取得できませんでした", "error", merr)
	}

	// ─── Seed initial admin user ──────────────────────────────
	if adminPwd := getEnv("ADMIN_PASSWORD", ""); adminPwd != "" {
		if err := store.SeedAdminUser(ctx, db.Pool(), adminPwd); err != nil {
			slog.Warn("管理者ユーザーのシードに失敗しました", "error", err)
		}
	}

	// ─── Seed E2E MFA test user (test/CI only) ────────────────
	// Gated by SEED_E2E_MFA_USER so production never creates this user.
	if getEnv("SEED_E2E_MFA_USER", "") == "true" {
		mfaPwd := getEnv("E2E_MFA_PASSWORD", "Password123!")
		if err := store.SeedTestMFAUser(ctx, db.Pool(), "mfa@example.com", mfaPwd); err != nil {
			slog.Warn("MFAテストユーザーのシードに失敗しました", "error", err)
		} else {
			slog.Info("E2E MFAテストユーザーをシードしました", "email", "mfa@example.com")
		}
	}

	// ─── NATS ─────────────────────────────────────────────────
	nc, err := nats.Connect(natsURL,
		nats.ReconnectWait(5*time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("NATS接続が切断されました", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			slog.Info("NATSに再接続しました")
		}),
	)
	if err != nil {
		slog.Error("NATS接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer nc.Close()
	slog.Info("NATSに接続しました")

	// ─── 保管時暗号化 ─────────────────────────────────────────
	//
	// raw_event を AES-256-GCM でテナント鍵により暗号化します。テナント鍵は
	// tenant_encryption_keys（マイグレーション 029）に置き、TENANT_MASTER_KEY
	// でラップします。MDM の鍵とは分けています —— 守る対象が違うものを
	// 同じ鍵に載せる理由がありません。
	//
	// 未設定なら暗号化は無効です。**そのことを起動時に必ず言います。**
	// 以前は黙って平文に落ちていて、docs は「保管時暗号化」を事実として
	// 書いていました。設定し忘れと、そう決めたことの区別がつきませんでした。
	//
	// 鍵が設定されているのに使えない（base64 でない、長さが違う）ときは
	// 起動しません。暗号化するつもりで平文に落ちるのが、いちばん悪い形です。
	var tenantEncryptor *tenantcrypto.Encryptor
	if raw := os.Getenv("TENANT_MASTER_KEY"); raw != "" {
		masterKey, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			slog.Error("TENANT_MASTER_KEY を base64 として読めません。"+
				"暗号化するつもりで平文に落ちるのを避けるため、起動しません", "error", err)
			os.Exit(1)
		}
		ks, err := tenantcrypto.NewDBKeyStore(db.Pool(), masterKey)
		if err != nil {
			slog.Error("テナント鍵ストアを作れません。起動しません", "error", err)
			os.Exit(1)
		}
		tenantEncryptor = tenantcrypto.NewEncryptor(ks)
		slog.Info("アラートの保管時暗号化を有効にしました (AES-256-GCM, テナント鍵)")
	} else {
		slog.Warn("TENANT_MASTER_KEY が未設定です。" +
			"アラートの raw_event は平文で保存されます")
	}

	// ─── Stores ───────────────────────────────────────────────
	alertStore := store.NewAlertStore(db).WithPublisher(nc).WithEncryptor(tenantEncryptor)
	agentStore := store.NewAgentStore(db)
	ruleStore := store.NewRuleStore(db)
	userStore := store.NewUserStore(db)
	auditStore := store.NewAuditStore(db)
	reportStore := store.NewReportStore(db)
	responseActionStore := store.NewResponseActionStore(db)
	commander := store.NewCommandStore(db, nc)

	// ─── 隔離のゲートキーパー ─────────────────────────────────
	// このプロセスで隔離を実行できるのはこれだけ（手動隔離・隔離アクション API・
	// 自動修復エンジン）。安全弁と response_actions への記録はここに集約されている。
	//
	// AUTO_RESPONSE_ENABLED は server-detect だけの設定ではない。自動修復エンジンは
	// この api プロセスにあり、以前はこのスイッチを一切見ずに隔離していた。
	// 2026-08-13 に、detection 側を AUTO_ISOLATE_DRY_RUN=true にした環境で
	// この経路が端末を実際に隔離している。両プロセスに同じ値を渡すこと。
	autoResponse := getEnv("AUTO_RESPONSE_ENABLED", "true") == "true"
	isoDryRun := getEnv("AUTO_ISOLATE_DRY_RUN", "") == "true"
	if !autoResponse {
		slog.Warn("AUTO_RESPONSE_ENABLED=false のため、無人経路からの隔離は行いません")
	}
	if isoDryRun {
		slog.Warn("自動隔離はドライランです。隔離は実行されず、記録だけ残ります")
	}
	// AUTO_ISOLATE_EXEMPT はこれまで detection にしか実装が無く、api 経由の
	// 隔離（プレイブック・自動修復・API 呼び出し）には安全弁が一つも無かった。
	// 環境変数だけが両方に配られていたので、外形上は効いているように見える。
	// 判定は isolation.IsExempt に一本化してある。
	var isoExempt []string
	for _, h := range strings.Split(os.Getenv("AUTO_ISOLATE_EXEMPT"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			isoExempt = append(isoExempt, h)
		}
	}
	if len(isoExempt) > 0 {
		slog.Info("自動隔離の除外リストを読み込みました", "件数", len(isoExempt),
			"対象", isoExempt)
	}
	// ホスト名で指定できるようにするための解決手段。呼び出し側の記入に頼ると
	// 記入し忘れた経路だけ除外が効かなくなる。
	exemptResolver := func(ctx context.Context, agentID string) string {
		if agentID == "" {
			return ""
		}
		a, err := agentStore.GetAgentByID(ctx, agentID)
		if err != nil || a == nil {
			return ""
		}
		return a.Hostname
	}
	gatekeeper := isolation.New(commander, responseActionStore, isolation.Config{
		UnattendedEnabled: autoResponse,
		DryRun:            isoDryRun,
		Exempt:            isoExempt,
		HostnameResolver:  exemptResolver,
	})
	quarantineStore := store.NewQuarantineStore(db)
	iocStore := store.NewIOCStore(db)
	ipBlockStore := store.NewIPBlockStore(db)
	suppressionStore := store.NewSuppressionStore(db)
	incidentStore := store.NewIncidentStore(db)
	playbookStore := store.NewPlaybookStore(db)
	reportScheduleStore := store.NewReportScheduleStore(db)
	pool := db.Pool()

	// ─── Notification ─────────────────────────────────────────
	dispatcher := notification.NewDispatcher(baseURL)
	notifStore := store.NewNotificationStore(db)
	channels, _ := notifStore.ListChannels(ctx)
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

	// 通知チャンネルの変更を取り込む。
	//
	// これが無いと、api プロセスの通知先は**起動時のまま固定**される。
	// 画面からチャンネルを足しても、api を再起動するまで送信先に入らない。
	// しかも送信先が 0 件でも Notify は静かに何もしないので、
	// 「設定したのに届かない、エラーも出ない」状態になる。
	// cmd/detection には同じ購読が元からあり、api 側だけ抜けていた。
	//
	// api は複数レプリカで動くので、自分が変更を publish した場合も
	// 含めて NATS 経由で揃える (変更を受けたレプリカだけが新しい設定を
	// 持つ状態を避ける)。
	go func() {
		sub, err := nc.Subscribe("settings.channels.updated", func(_ *nats.Msg) {
			chs, err := notifStore.ListChannels(ctx)
			if err != nil {
				slog.Warn("通知チャンネルの再読み込みに失敗しました", "error", err)
				return
			}
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
			slog.Warn("通知チャンネル更新の購読に失敗しました", "error", err)
			return
		}
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()

	// ─── WebSocket Hub ────────────────────────────────────────
	wsHub := notification.NewWebSocketHub(nc)

	// ─── AI Auto-Investigation ────────────────────────────────
	openAIKey := getEnv("OPENAI_API_KEY", "")
	investigator := investigation.NewInvestigator(pool, investigation.InvestigatorConfig{
		OpenAIKey:    openAIKey,
		AnthropicKey: anthropicKey,
	})
	investigationSubscriber := investigation.NewSubscriber(investigator, nc)
	go investigationSubscriber.Start(ctx)
	if investigator.IsConfigured() {
		slog.Info("AI自動調査を有効化しました")
	} else {
		slog.Info("AI自動調査: OPENAI_API_KEY/ANTHROPIC_API_KEY が未設定 — 調査はスキップされます")
	}
	investigationHandler := handlers.NewInvestigationHandler(investigator)

	// ─── Auth security components ─────────────────────────────
	tokenBlocklist := auth.NewTokenBlocklist()
	tokenBlocklist.StartCleanup()
	userCache := auth.NewUserStatusCache(pool)

	// ─── 対応アクションの期限切れ監視 ─────────────────────────
	// エージェントへ送ったコマンドの結果が返らないと、行は dispatched のまま
	// 残り、UI では「実行中」に見え続ける。操作者が隔離は効いていると
	// 思い込むのを防ぐため、期限を過ぎた行を timeout に畳む。
	// RESPONSE_ACTION_TIMEOUT で調整可（既定 15m、下限 2m）。
	respTimeout := 15 * time.Minute
	if v := getEnv("RESPONSE_ACTION_TIMEOUT", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			respTimeout = d
		} else {
			slog.Warn("RESPONSE_ACTION_TIMEOUT を解釈できませんでした。既定値を使います",
				"値", v, "既定", respTimeout)
		}
	}
	go scheduler.NewResponseActionTimeoutWorker(responseActionStore, respTimeout).Run(ctx)

	// ─── Handlers ─────────────────────────────────────────────
	agentHandler := handlers.NewAgentHandler(agentStore, commander)
	agentHandler.ResponseActions = responseActionStore
	agentHandler.Isolator = gatekeeper
	agentHandler.Alerts = alertStore
	agentHandler.Quarantine = quarantineStore
	agentHandler.Pool = pool
	alertHandler := handlers.NewAlertHandler(alertStore, agentStore)
	alertHandler.Pool = pool
	eventHandler := handlers.NewEventHandler(pool)
	ruleHandler := handlers.NewRuleHandler(ruleStore)
	ruleHandler.Publisher = nc // signal detection engine on rule changes
	if ghToken := getEnv("GITHUB_TOKEN", ""); ghToken != "" || getEnv("SIGMAHQ_SYNC_ENABLED", "") == "true" {
		ruleHandler.Syncer = edrsync.NewSigmaHQSyncer(ruleStore, ghToken)
		slog.Info("SigmaHQコミュニティルール同期を有効化しました")
		// 週次自動同期スケジューラ（YARA同型）。手動トリガのみだったSigmaHQ同期を
		// 自動化し検知コンテンツを継続拡充。DefaultSyncPaths（対応カテゴリ）+ stable/test
		// のみenable。同期後に rules.invalidate を発行して検知エンジンへ反映。
		sigmaSyncInterval := 7 * 24 * time.Hour
		go scheduler.NewSigmaSyncScheduler(ruleStore, ghToken, nc, sigmaSyncInterval).Run(ctx)
		slog.Info("SigmaHQルール週次自動同期スケジューラを有効化しました")

		// Staged curate (roadmap P1): synced rules are imported disabled; this
		// scheduler turns a bounded, field-supported batch on each round and the FP
		// monitor quarantines any that turn noisy — so coverage grows on its own
		// without flooding the engine. autoAdvance defaults on (operator chose
		// scheduler auto-advance); set CURATE_AUTO_ENABLE=false to keep the FP
		// monitor but drive rounds manually via the curate API.
		curateSvc := detection.NewCurateService(pool, nc)
		curateAuto := getEnv("CURATE_AUTO_ENABLE", "true") == "true"
		curateScheduler := scheduler.NewCurateScheduler(
			curateSvc,
			time.Duration(getEnvInt("CURATE_ROUND_INTERVAL_MIN", 360))*time.Minute,
			getEnvInt("CURATE_PER_CATEGORY_CAP", 20),
			time.Duration(getEnvInt("CURATE_FP_WINDOW_HOURS", 24))*time.Hour,
			getEnvInt("CURATE_FP_THRESHOLD", 50),
			curateAuto,
		)
		go curateScheduler.Run(ctx)
		slog.Info("curate(段階有効化)スケジューラを有効化しました", "auto_advance", curateAuto)
	}
	reportHandler := handlers.NewReportHandlerWithAgents(alertStore, agentStore, reportStore)
	authHandler := handlers.NewAuthHandler(jwtSecret, userStore)
	authHandler.Blocklist = tokenBlocklist
	authHandler.UserCache = userCache
	settingsHandler := handlers.NewSettingsHandler(pool, dispatcher)
	settingsHandler.Publisher = nc // signal detection engine on channel config changes
	usersHandler := handlers.NewUsersHandler(userStore)
	usersHandler.UserCache = userCache
	quarantineHandler := handlers.NewQuarantineHandler(quarantineStore, commander)
	iocHandler := handlers.NewIOCHandler(iocStore)
	iocHandler.Publisher = nc // signal detection engine to reload IOC cache
	suppressionHandler := handlers.NewSuppressionHandler(suppressionStore)
	suppressionHandler.Publisher = nc // signal detection engine on suppression changes
	suppressionHandler.Pool = pool    // for suppression candidate queries
	incidentHandler := handlers.NewIncidentHandler(incidentStore)
	playbookHandler := handlers.NewPlaybookHandler(playbookStore)
	reportScheduleHandler := handlers.NewReportScheduleHandler(reportScheduleStore)
	vulnStore := store.NewVulnStore(db)
	vulnHandler := handlers.NewVulnHandler(vulnStore)
	threatFeedStore := store.NewThreatFeedStore(db)
	threatFeedHandler := handlers.NewThreatFeedHandler(threatFeedStore, iocStore)
	threatFeedHandler.Publisher = nc // signal detection engine to reload IOC cache after feed sync
	softwareStore := store.NewSoftwareInventoryStore(db)
	softwareHandler := handlers.NewSoftwareInventoryHandler(softwareStore)
	searchHandler := handlers.NewSearchHandler(pool)
	complianceHandler := handlers.NewComplianceHandler(pool)
	uebaHandler := handlers.NewUEBAHandler(pool)
	notifHistoryStore := store.NewNotificationHistoryStore(db)
	notifHistoryHandler := handlers.NewNotificationHistoryHandler(notifHistoryStore)
	socMetricsHandler := handlers.NewSOCMetricsHandler(pool)
	socQueueHandler := handlers.NewSOCQueueHandler(pool)
	campaignsHandler := handlers.NewCampaignsHandler(pool)

	// ─── Live Response ────────────────────────────────────────
	liveResponseStore := store.NewLiveResponseStore(db)
	// エージェントがセッションのポーリングと結果報告に使う URL。EDR_BASE_URL は
	// 利用者向けの公開 URL (リバースプロキシ経由の HTTPS) を指すため、エージェント
	// 側のネットワークからそこへ到達できない構成では Live Response が無反応になる。
	// コマンドの配送自体は成功するので原因が見えにくく、到達可能な URL を
	// LIVE_RESPONSE_CALLBACK_URL で明示的に指定できるようにする。
	liveResponseCallbackURL := getEnv("LIVE_RESPONSE_CALLBACK_URL", baseURL)
	if liveResponseCallbackURL != baseURL {
		slog.Info("Live Response のコールバック URL を上書きしました", "callback_url", liveResponseCallbackURL)
	}
	liveResponseHandler := handlers.NewLiveResponseHandler(liveResponseStore, pool, nc, commander, liveResponseCallbackURL)

	// ─── Live Response Command Queue ──────────────────────────
	cmdQueueStore := store.NewCmdQueueStore(pool)
	cmdQueueHandler := handlers.NewLiveResponseCmdHandler(cmdQueueStore)

	// ─── SIEM Forwarding ──────────────────────────────────────
	siemStore := store.NewSIEMStore(db)
	siemForwarder := siem.NewForwarder()
	// Pre-load SIEM targets from DB at startup
	if siemTargets, err := siemStore.List(ctx); err == nil {
		targets := make([]*siem.Target, len(siemTargets))
		for i, t := range siemTargets {
			targets[i] = &siem.Target{
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
		siemForwarder.LoadTargets(targets)
		slog.Info("SIEMターゲットを読み込みました", "count", len(targets))
	}
	siemHandler := handlers.NewSIEMHandler(siemStore, siemForwarder)
	siemHandler.Publisher = nc

	// ─── VirusTotal ───────────────────────────────────────────
	vtAPIKey := getEnv("VIRUSTOTAL_API_KEY", "")
	vtHandler := handlers.NewVirusTotalHandler(vtAPIKey)
	if vtAPIKey != "" {
		slog.Info("VirusTotal統合を有効化しました")
	}

	// ─── Threat Hunting ───────────────────────────────────────
	huntStore := store.NewHuntStore(db)
	huntHandler := handlers.NewHuntHandler(huntStore)
	huntHandler.Pool = pool

	// ─── Saved Hunt Queries (rich query library) ──────────────
	savedHuntStore := store.NewSavedHuntStore(pool)
	savedHuntHandler := handlers.NewSavedHuntHandler(savedHuntStore)

	// ─── Agent Auto-Update ────────────────────────────────────
	// latestVersion/URL/checksum can be overridden via environment variables
	// or loaded from settings. Defaults are empty (no update offered) until
	// an operator configures a release.
	updateLatestVersion := getEnv("AGENT_LATEST_VERSION", "")

	// ─── Forensics ────────────────────────────────────────────
	forensicsHandler := handlers.NewForensicsHandler(pool, nc)

	// ─── Compliance Framework Reports ─────────────────────────
	complianceReportHandler := handlers.NewComplianceReportHandler(pool)

	// ─── Compliance Export (JSON / CSV download) ──────────────
	complianceExportHandler := handlers.NewComplianceExportHandler(pool)

	// ─── Tenant Management ────────────────────────────────────
	tenantHandler := handlers.NewTenantHandler(pool)
	tenantRoleStore := store.NewTenantRoleStore(pool)
	tenantRolesHandler := handlers.NewTenantRolesHandler(tenantRoleStore)

	// ─── TI Feed Sync History ─────────────────────────────────
	tiSyncHandler := handlers.NewTIFeedSyncHandler(pool)

	// ─── Cloud Workload Monitoring ────────────────────────────
	cloudMonitorHandler := handlers.NewCloudMonitorHandler(pool)

	// ─── Agent Binary Downloads ───────────────────────────────
	downloadHandler := handlers.NewDownloadHandler(getEnv("AGENT_BIN_DIR", "./downloads"))

	// ─── Session Management ───────────────────────────────────
	sessionStore := store.NewSessionStore(pool)
	authHandler.Sessions = sessionStore // enable login session recording
	sessionHandler := handlers.NewSessionHandler(pool)

	// ─── Agent Policies ───────────────────────────────────────
	agentPolicyStore := store.NewAgentPolicyStore(pool)
	agentPolicyHandler := handlers.NewAgentPolicyHandlerWithCommander(agentPolicyStore, agentStore, commander)

	// ─── YARA Rule Engine ─────────────────────────────────────
	// NOTE: Server-side stores and distributes YARA rule content only.
	// Actual YARA matching on the agent side requires the go-yara library
	// (github.com/hillu/go-yara) which uses cgo against libyara. That is
	// not included in this pure-Go build; the agent stub scanner simulates
	// matches for build compatibility.
	yaraStore := store.NewYARAStore(pool)
	yaraHandler := handlers.NewYARAHandler(yaraStore)
	yaraHandler.Pool = pool
	// YARAコミュニティルール同期は常に有効（Yara-Rules/rulesはパブリックリポジトリ）
	// GITHUB_TOKENが設定されている場合はレート制限が60→5000 req/hrに向上する
	ghToken := getEnv("GITHUB_TOKEN", "")
	yaraHandler.Syncer = edrsync.NewYARAHQSyncer(yaraStore, ghToken)
	slog.Info("YARAコミュニティルール同期を有効化しました")
	// 週次自動同期スケジューラー（初回は起動時に実行、以降7日ごと）
	yaraSyncInterval := 7 * 24 * time.Hour
	go scheduler.NewYARASyncScheduler(yaraStore, ghToken, yaraSyncInterval).Run(ctx)

	// ─── Dashboard Widget Preferences ────────────────────────
	dashboardPrefsStore := store.NewDashboardPrefsStore(pool)
	dashboardPrefsHandler := handlers.NewDashboardPrefsHandler(dashboardPrefsStore)

	// ─── Dashboard Widget Layout Persistence ─────────────────
	dashboardStore := store.NewDashboardStore(pool)
	dashboardHandler := handlers.NewDashboardHandler(dashboardStore)

	// ─── CIS Benchmark Compliance Auto-Scoring ───────────────
	complianceScoreHandler := handlers.NewComplianceScoreHandler(pool)

	// ─── SOAR (Jira / ServiceNow) ─────────────────────────────
	soarHandler := handlers.NewSOARHandler(pool)

	// ─── Webhook Notifications ────────────────────────────────
	webhookStore := store.NewWebhookStore(pool)
	webhookNotifier := notification.NewWebhookNotifier(webhookStore, nc)
	webhookHandler := handlers.NewWebhookHandler(webhookStore, webhookNotifier)
	go webhookNotifier.Start(ctx)
	slog.Info("Webhookノーティファイアを開始しました")

	// ─── NATS Event → Webhook Forwarder ──────────────────────
	eventForwarder := handlers.NewEventForwarder(pool, nc)
	go eventForwarder.Start(ctx)
	slog.Info("NATSイベント→Webhookフォワーダーを開始しました")

	// ─── NATS alert.created → SIEM Forwarder bridge ──────────
	// siemForwarder は上部で初期化済み。alert.created を受信したら
	// DB から完全なアラートデータを取得して SIEM へ転送する。
	startSIEMAlertBridge(ctx, nc, pool, siemForwarder)

	// ─── Email MFA ────────────────────────────────────────────
	emailOTPStore := store.NewEmailOTPStore(db)
	// Build SMTP OTP sender from environment variables (falls back to stub logger if not configured)
	var otpEmailSender handlers.EmailSender
	if smtpHost := getEnv("SMTP_HOST", ""); smtpHost != "" {
		otpEmailSender = handlers.NewSMTPOTPSender(handlers.SMTPOTPSenderConfig{
			SMTPHost: smtpHost,
			SMTPPort: getEnv("SMTP_PORT", "587"),
			Username: getEnv("SMTP_USER", ""),
			Password: getEnv("SMTP_PASS", ""),
			From:     getEnv("SMTP_FROM", getEnv("SMTP_USER", "")),
		})
		slog.Info("Email MFA SMTP送信を有効化しました", "host", smtpHost)
	}
	emailMFAHandler := handlers.NewEmailMFAHandler(emailOTPStore, userStore, otpEmailSender, authHandler)

	// ─── Email Alert Notification Preferences ─────────────────
	notifPrefStore := store.NewNotificationPrefStore(db)
	notifPrefsHandler := handlers.NewNotificationPrefsHandler(notifPrefStore)
	emailNotifier := notification.NewEmailNotifier(notifPrefStore, nc)
	go emailNotifier.Start(ctx)

	// ─── Password Policy ──────────────────────────────────────
	passwordPolicyStore := store.NewPasswordPolicyStore(db)
	passwordPolicyHandler := handlers.NewPasswordPolicyHandler(passwordPolicyStore)
	usersHandler.PolicyStore = passwordPolicyStore // enforce policy on password changes

	// ─── Email Sender (centralised SMTP) ──────────────────────
	mailer := email.NewSenderFromEnv()
	if mailer != nil {
		slog.Info("SMTP メール送信を有効化しました")
	} else {
		slog.Info("SMTP_HOST が未設定のためメール送信はスタブ出力にフォールバックします")
	}

	// ─── User Invitations ─────────────────────────────────────
	invitationStore := store.NewInvitationStore(db)
	invitationHandler := handlers.NewInvitationHandler(invitationStore, userStore, frontendURL, mailer)

	// ─── Password Reset ───────────────────────────────────────
	passwordResetStore := store.NewPasswordResetStore(db)
	passwordResetHandler := handlers.NewPasswordResetHandler(passwordResetStore, userStore, baseURL, mailer)

	// ─── FIM Rules ────────────────────────────────────────────
	fimRuleStore := store.NewFIMRuleStore(pool)
	fimHandler := handlers.NewFIMHandler(fimRuleStore)

	// ─── Device Events ────────────────────────────────────────
	deviceEventStore := store.NewDeviceEventStore(pool)
	deviceEventHandler := handlers.NewDeviceHandler(deviceEventStore)

	// ─── Risk Action Rules ────────────────────────────────────
	riskActionHandler := handlers.NewRiskActionHandler(pool)

	// ─── API Keys ─────────────────────────────────────────────
	apiKeyStore := store.NewAPIKeyStore(pool)
	apiKeyHandler := handlers.NewAPIKeyHandler(apiKeyStore)

	// ─── Process Execution Block Rules ───────────────────────
	processBlockStore := store.NewProcessBlockRuleStore(pool)
	processBlockHandler := handlers.NewProcessBlockHandler(processBlockStore)

	// ─── SSO / SAML 2.0 Configuration ────────────────────────
	// Production: add github.com/crewjam/saml for real XML signature verification.
	// The callback is currently a stub that issues a demo JWT.

	// ─── Wazuh Integration ────────────────────────────────────
	wazuhURL := getEnv("WAZUH_MANAGER_URL", "")
	wazuhUser := getEnv("WAZUH_USERNAME", "wazuh-wui")
	wazuhPass := getEnv("WAZUH_PASSWORD", "")
	wazuhSkipTLS := getEnv("WAZUH_SKIP_TLS", "true") == "true"
	ingestToken := getEnv("WAZUH_INGEST_TOKEN", "")
	ingestHandler := handlers.NewIngestHandler(pool, ingestToken)

	if wazuhURL != "" && wazuhPass != "" {
		wazuhCfg := edrsync.WazuhConfig{
			ManagerURL: wazuhURL,
			Username:   wazuhUser,
			Password:   wazuhPass,
			MinLevel:   7,
			SkipTLS:    wazuhSkipTLS,
		}
		wazuhSyncer := edrsync.NewWazuhSyncer(wazuhCfg, pool)
		go wazuhSyncer.Run(ctx)
		slog.Info("Wazuh同期を開始しました", "url", wazuhURL)
	} else {
		slog.Info("WAZUH_MANAGER_URL/WAZUH_PASSWORDが未設定のためWazuh同期はスキップします")
	}

	h := api.NewHandlers(
		agentHandler,
		alertHandler,
		eventHandler,
		ruleHandler,
		reportHandler,
		authHandler,
		settingsHandler,
		usersHandler,
		quarantineHandler,
		iocHandler,
		suppressionHandler,
		incidentHandler,
		playbookHandler,
		reportScheduleHandler,
		vulnHandler,
		threatFeedHandler,
		softwareHandler,
		searchHandler,
		complianceHandler,
		uebaHandler,
		notifHistoryHandler,
		socMetricsHandler,
		socQueueHandler,
		campaignsHandler,
		ingestHandler,
		liveResponseHandler,
		siemHandler,
		vtHandler,
		huntHandler,
		forensicsHandler,
		complianceReportHandler,
		tenantHandler,
		tenantRolesHandler,
		tiSyncHandler,
		cloudMonitorHandler,
		downloadHandler,
		sessionHandler,
		agentPolicyHandler,
		soarHandler,
		emailMFAHandler,
		notifPrefsHandler,
		webhookHandler,
		yaraHandler,
		dashboardPrefsHandler,
		riskActionHandler,
		complianceScoreHandler,
		passwordPolicyHandler,
		invitationHandler,
		passwordResetHandler,
		fimHandler,
		deviceEventHandler,
		apiKeyHandler,
		processBlockHandler,
	)

	// ─── WebSocket Real-Time Feed ─────────────────────────────
	h.WebSocket = handlers.NewWebSocketHandler()

	// ─── IOC Enrichment ───────────────────────────────────────
	h.IOCEnrichment = handlers.NewIOCEnrichmentHandler(pool)

	// ─── Packet Captures ──────────────────────────────────────
	packetCaptureStore := store.NewPacketCaptureStore(pool)
	h.PacketCapture = handlers.NewPacketCaptureHandler(packetCaptureStore)

	// ─── Unified Data Export ───────────────────────────────────
	h.Export = handlers.NewExportHandler(pool).WithEncryptor(tenantEncryptor)

	// ─── Saved Hunt Queries Handler ───────────────────────────
	h.SavedHunt = savedHuntHandler

	// ─── Live Response Command Queue Handler ─────────────────
	h.LiveResponseCmdQueue = cmdQueueHandler

	// ─── LDAP / Active Directory ─────────────────────────────

	// ─── Detection Rule Dry-Run / Test ────────────────────────
	h.RuleTest = handlers.NewRuleTestHandler(pool)

	// ─── Alert Bulk Operations ────────────────────────────────
	h.AlertBulk = handlers.NewAlertBulkHandler(pool)

	// ─── Alert Action Endpoints (status / enrich) ─────────────
	h.AlertAction = handlers.NewAlertActionHandler(pool)

	// ─── Alert MITRE ATT&CK Auto-Classifier ───────────────────
	h.AlertClassifier = handlers.NewAlertClassifierHandler(pool)

	// ─── Elasticsearch Log Shipping ───────────────────────────
	esShipper := shipper.NewElasticsearchShipper(
		getEnv("ES_URL", ""),
		getEnv("ES_USERNAME", ""),
		getEnv("ES_PASSWORD", ""),
		getEnv("ES_INDEX", "edr-events"),
	)
	go esShipper.Run(ctx)
	h.ES = handlers.NewESHandler(esShipper)

	// ─── Dashboard Widget Layout ──────────────────────────────
	h.Dashboard = dashboardHandler

	// ─── Dashboard Statistics (time-series KPIs) ──────────────
	h.DashboardStats = handlers.NewDashboardStatsHandler(pool)

	// ─── Rule Import/Export ───────────────────────────────────
	rulesIEHandler := handlers.NewRulesIEHandler(ruleStore, processBlockStore)
	h.RulesIE = rulesIEHandler

	// ─── Agent Installer Scripts ──────────────────────────────
	installerHandler := handlers.NewInstallerHandler(
		getEnv("SERVER_URL", "http://localhost:8080"),
		getEnv("AGENT_BIN_DIR", "./downloads"),
		pool,
	)
	h.Installer = installerHandler

	// ─── IP Block/Allow List ──────────────────────────────────
	h.IPBlock = handlers.NewIPBlockHandler(ipBlockStore)

	// ─── Incident Comments ────────────────────────────────────
	incidentCommentStore := store.NewIncidentCommentStore(pool)
	incidentCommentHandler := handlers.NewIncidentCommentHandler(incidentCommentStore)
	h.IncidentComments = incidentCommentHandler

	// ─── Alert Comments ───────────────────────────────────────
	alertCommentStore := store.NewAlertCommentStore(pool)
	alertCommentHandler := handlers.NewAlertCommentsHandler(alertCommentStore)
	h.AlertComments = alertCommentHandler

	// ─── Agent Tags ───────────────────────────────────────────
	agentTagStore := store.NewAgentTagStore(pool)
	h.AgentTags = handlers.NewAgentTagHandler(agentTagStore)

	// ─── Report CSV Export ────────────────────────────────────
	reportExportHandler := handlers.NewReportExportHandler(pool)
	h.ReportExport = reportExportHandler

	// ─── Report Templates ─────────────────────────────────────
	reportTemplateStore := store.NewReportTemplateStore(pool)
	h.ReportTemplates = handlers.NewReportTemplateHandler(reportTemplateStore, pool)

	// ─── HTML/PDF Report Generation ───────────────────────────
	h.PDFReport = handlers.NewPDFReportHandler(pool)

	// ─── Backup & Restore ─────────────────────────────────────
	backupHandler := handlers.NewBackupHandler(dbURL, getEnv("BACKUP_DIR", "./backups"))
	h.Backup = backupHandler

	// ─── Audit Log SIEM Export ────────────────────────────────
	auditExportHandler := handlers.NewAuditExportHandler(pool)
	h.AuditExport = auditExportHandler

	// ─── Compliance Export ────────────────────────────────────
	h.ComplianceExport = complianceExportHandler

	// ─── Sigma Rule Import ────────────────────────────────────
	h.Sigma = handlers.NewSigmaHandler(pool)

	// ─── Agent mTLS Certificate Authority ────────────────────
	caManager, err := cert.NewCAManager(getEnv("CERT_DIR", "./certs"))
	if err != nil {
		slog.Warn("CA初期化に失敗しました", "error", err)
		caManager = nil
	}
	var certHandler *handlers.CertHandler
	if caManager != nil {
		certHandler = handlers.NewCertHandler(caManager)
		slog.Info("エージェントmTLS CAを初期化しました")
	}
	h.Cert = certHandler

	// ─── VirusTotal 自動エンリッチメント ──────────────────────
	if vtAPIKey != "" {
		vtEnricher := enrichment.NewVTEnricher(nc, pool, vtAPIKey)
		go vtEnricher.Run(ctx)
		slog.Info("VirusTotal自動エンリッチメントを開始しました")
	}

	// ─── OpenAPI / Swagger UI Docs ────────────────────────────
	docsHandler := handlers.NewDocsHandler("./docs/openapi.yaml")
	h.Docs = docsHandler

	// ─── Alert Notification Channels ─────────────────────────
	alertNotifStore := store.NewAlertNotifStore(pool)
	alertNotifier := notify.NewNotifier(alertNotifStore, getEnv("SERVER_URL", "http://localhost:8080"))
	h.Notification = handlers.NewNotificationHandler(alertNotifStore, alertNotifier)

	// ─── Custom Notification Templates ───────────────────────
	h.NotifTemplate = handlers.NewNotificationTemplateHandler(pool)

	// ─── Email Verification ───────────────────────────────────
	h.EmailVerify = handlers.NewEmailVerificationHandler(pool, baseURL, mailer)

	// ─── User Preferences ─────────────────────────────────────
	userPrefsStore := store.NewUserPreferencesStore(pool)
	h.UserPreferences = handlers.NewUserPreferencesHandler(userPrefsStore)
	h.Favorites = handlers.NewFavoritesHandler(userPrefsStore)

	// ─── Metrics: agent / alert count poller ──────────────────
	//
	// Also feeds the gauges the Prometheus alert rules key on. AgentsOffline and the
	// open-alert gauges had no writer at all, so AgentOffline and
	// CriticalAlertsUnacknowledged could never fire — a silent alerting gap that
	// looks exactly like "nothing is wrong". See metrics.OpenAlerts.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("online agent poller panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "agent_gauge_poller", func(ctx context.Context) {
					if _, total, err := agentStore.ListAgents(ctx, store.AgentFilter{
						Status: "online", Limit: 1, Offset: 0,
					}); err != nil {
						// **数えられなかったとき、gauge は前の値のまま
						// 残ります。** 0 になるより悪い形です —— 画面は
						// 動いているように見えます。
						tick.Fail(ctx, err, "オンライン端末数を数えられませんでした")
					} else {
						metrics.AgentsOnline.Store(int64(total))
						metrics.ActiveAgents.Set(float64(total))
					}
					// 'offline' only — 'inactive' is a retired host and must not alert
					// (P5-10: readers that treated inactive as offline produced endless
					// alerts for decommissioned machines).
					if _, off, err := agentStore.ListAgents(ctx, store.AgentFilter{
						Status: "offline", Limit: 1, Offset: 0,
					}); err != nil {
						tick.Fail(ctx, err, "オフライン端末数を数えられませんでした")
					} else {
						metrics.AgentsOffline.Set(float64(off))
					}
					if _, open, err := alertStore.ListAlerts(ctx, store.AlertFilter{
						Status: "open", Limit: 1, Offset: 0,
					}); err != nil {
						tick.Fail(ctx, err, "未対応アラート数を数えられませんでした")
					} else {
						metrics.OpenAlerts.Set(float64(open))
					}
					if _, crit, err := alertStore.ListAlerts(ctx, store.AlertFilter{
						Status: "open", Severity: 10, Limit: 1, Offset: 0,
					}); err != nil {
						tick.Fail(ctx, err, "重大アラート数を数えられませんでした")
					} else {
						metrics.OpenAlertsCritical.Set(float64(crit))
					}
				})
			}
		}
	}()

	// ─── Threat Feed Auto-Sync ────────────────────────────────
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("threat feed auto-sync panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "threat_feed_autosync", func(ctx context.Context) {
					due, err := threatFeedStore.GetDueForSync(ctx)
					if err != nil {
						// **どのフィードが期限なのか読めていません。**
						// この回は1本も同期していないので、Warn では
						// なくこの回の失敗です。
						tick.Fail(ctx, err, "期限の来た脅威フィードを読めませんでした")
						return
					}
					for _, feed := range due {
						feed := feed
						go func() {
							defer func() {
								if r := recover(); r != nil {
									slog.Error("threat feed sync panic", "feed", feed.Name, "panic", r)
								}
							}()
							slog.Info("脅威フィード同期開始", "feed", feed.Name)
							count, err := handlers.SyncFeedExternal(ctx, feed, iocStore)
							if err != nil {
								// **この回の外です**（別の goroutine で、
								// 回はもう終わっています）。部品ごとの
								// 件数が残せる跡です。
								metrics.BackgroundFailed("threat_feed_sync", err,
									"脅威フィードを同期できませんでした", "feed", feed.Name)
								return
							}
							if err := threatFeedStore.MarkSynced(ctx, feed.ID, count); err != nil {
								// **記録できないと、次の周回も同じ
								// フィードが「期限切れ」で挙がります。**
								metrics.BackgroundFailed("threat_feed_sync", err,
									"脅威フィードの同期完了を記録できませんでした",
									"feed", feed.Name, "imported", count)
							}
							if count > 0 {
								if err := nc.Publish("ioc.invalidate", []byte("{}")); err != nil {
									// **取り込んだ IOC が検知に効きません。**
									metrics.BackgroundFailed("threat_feed_sync", err,
										"IOC キャッシュの更新を通知できませんでした",
										"feed", feed.Name, "imported", count)
									return
								}
								slog.Info("フィードスケジューラ: IOCキャッシュを更新しました", "feed", feed.Name, "imported", count)
							}
						}()
					}
				})
			}
		}
	}()

	// ─── Scheduled Report Runner ──────────────────────────────
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("scheduled report runner panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "scheduled_report_runner", func(ctx context.Context) {
					due, err := reportScheduleStore.GetDue(ctx)
					if err != nil {
						// **どのレポートが期限なのか読めていません。**
						// この回は1本も送っていません。
						tick.Fail(ctx, err, "期限の来たスケジュールレポートを読めませんでした")
						return
					}
					for _, sc := range due {
						sc := sc // capture
						go func() {
							defer func() {
								if r := recover(); r != nil {
									slog.Error("scheduled report panic", "name", sc.Name, "panic", r)
								}
							}()
							slog.Info("スケジュールレポートを実行中", "name", sc.Name, "type", sc.ReportType)
							msg := "[スケジュールレポート] " + sc.Name + " (" + sc.ReportType + ") を実行しました"
							if err := dispatcher.NotifyText(ctx, msg, 2); err != nil {
								// **通知が届いていません。** 回の外なので
								// 部品ごとの件数に出します。
								metrics.BackgroundFailed("scheduled_report", err,
									"スケジュールレポートの通知を送れませんでした", "name", sc.Name)
							}
							next := store.ComputeNextRun(sc, time.Now().UTC())
							if err := reportScheduleStore.MarkRun(ctx, sc.ID, next); err != nil {
								// **次回実行が進まないので、同じレポートが
								// 毎分挙がり続けます。**
								metrics.BackgroundFailed("scheduled_report", err,
									"スケジュールレポートの実行を記録できませんでした",
									"id", sc.ID, "name", sc.Name)
							}
						}()
					}
				})
			}
		}
	}()

	// ─── Report Email Delivery Scheduler ─────────────────────
	reportEmailScheduler := scheduler.NewReportScheduler(reportScheduleStore, pool)
	go reportEmailScheduler.Run(ctx)
	slog.Info("レポートメール配信スケジューラーを開始しました")

	// ─── Threat Feed Auto-Update Scheduler ───────────────────
	feedScheduler := scheduler.NewFeedScheduler(pool, threatFeedStore, 6*time.Hour)
	go feedScheduler.Run(ctx)
	slog.Info("脅威フィード自動更新スケジューラーを開始しました")

	// ─── IOC Expiry Sweeper ───────────────────────────────────
	// Deactivate IOCs whose STIX valid_until (expires_at) has passed.
	iocExpirySweeper := scheduler.NewIOCExpirySweeper(pool, time.Hour)
	go iocExpirySweeper.Run(ctx)
	slog.Info("IOC失効スイーパーを開始しました")

	// ─── Agent Offline Detection ──────────────────────────────
	heartbeatMonitor := scheduler.NewHeartbeatMonitor(pool)
	go heartbeatMonitor.Run(ctx)
	slog.Info("ハートビートモニターを開始しました")

	// ─── Alert Deduplication ──────────────────────────────────
	alertDeduplicator := dedup.NewAlertDeduplicator(pool)
	go alertDeduplicator.Run(ctx)

	// ─── Incident Auto-Escalation ─────────────────────────────
	incidentEscalator := scheduler.NewIncidentEscalator(pool)
	go incidentEscalator.Run(ctx)
	slog.Info("インシデントエスカレーターを開始しました")

	// ─── Daily Security Digest Scheduler ─────────────────────
	digestRecipients := []string{}
	if r := getEnv("DIGEST_RECIPIENTS", ""); r != "" {
		for _, addr := range strings.Split(r, ",") {
			if addr = strings.TrimSpace(addr); addr != "" {
				digestRecipients = append(digestRecipients, addr)
			}
		}
	}
	digestScheduler := scheduler.NewDigestScheduler(pool, digestRecipients)
	go digestScheduler.Run(ctx)
	slog.Info("日次セキュリティダイジェストスケジューラーを開始しました")

	// ─── Security Metrics Collector ───────────────────────────────
	// Snapshots security KPIs (agents, alerts, incidents) into
	// security_metrics_history hourly so the metrics/trend dashboard has real
	// data instead of an empty table.
	go scheduler.NewSecurityMetricsCollector(pool, time.Hour).Run(ctx)
	slog.Info("セキュリティメトリクス収集スケジューラーを開始しました")

	// ─── Security KPI Collector ───────────────────────────────────
	// Seeds the built-in KPI definitions and records a daily measurement for each
	// (agent uptime, open critical alerts, MTTR, …) so the KPI dashboard shows
	// real, self-updating data instead of an empty table.
	go scheduler.NewSecurityKPICollector(pool, 24*time.Hour).Run(ctx)
	slog.Info("セキュリティKPI収集スケジューラーを開始しました")

	// ─── Automatic Database Backups ───────────────────────────────
	backupInterval := 24 * time.Hour
	if os.Getenv("BACKUP_INTERVAL_HOURS") != "" {
		if h, err := strconv.Atoi(os.Getenv("BACKUP_INTERVAL_HOURS")); err == nil {
			backupInterval = time.Duration(h) * time.Hour
		}
	}
	backupScheduler := scheduler.NewBackupScheduler(pool, getEnv("BACKUP_DIR", "./backups"), backupInterval)
	go backupScheduler.Run(ctx)
	slog.Info("自動バックアップスケジューラーを開始しました", "interval", backupInterval)

	agentHealthAlerter := scheduler.NewAgentHealthAlerter(pool, nc)
	go agentHealthAlerter.Run(ctx)
	slog.Info("エージェントヘルスアラーターを開始しました")

	// ─── Live Response Session Expiry ────────────────────────
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("live response session expiry panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "live_response_session_expiry", liveResponseStore.ExpireOldSessions)
			}
		}
	}()

	// ─── Live Response Command Queue Timeout ─────────────────
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("live response command queue timeout panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "live_response_command_timeout", func(ctx context.Context) {
					n, err := cmdQueueStore.TimeoutStale(ctx)
					if err != nil {
						// **期限切れのコマンドが `pending` のまま残ります**
						// —— 画面では、担当者が出したコマンドが端末に
						// 届いていないのか、まだ実行中なのか分かりません。
						tick.Fail(ctx, err, "期限切れコマンドをタイムアウトできませんでした")
						return
					}
					if n > 0 {
						slog.Info("期限切れコマンドをタイムアウトしました", "count", n)
					}
				})
			}
		}
	}()

	// ─── Cloud Workload Monitoring Poller ─────────────────────
	cloudPoller := cloud.NewPollerWithNATS(pool, nc)
	go cloudPoller.Run(ctx)

	// ─── Session Cleanup ──────────────────────────────────────
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("session cleanup panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick.Run(ctx, "session_cleanup", func(ctx context.Context) {
					if err := sessionStore.CleanupExpired(ctx); err != nil {
						// **期限切れのセッションが残り続けます。**
						tick.Fail(ctx, err, "期限切れセッションを掃除できませんでした")
					}
				})
			}
		}
	}()
	slog.Info("クラウドワークロード監視ポーラーを開始しました")

	// ─── 2FA Recovery Codes ───────────────────────────────────
	h.RecoveryCodes = handlers.NewRecoveryCodeHandler(pool)

	// ─── Network Map ──────────────────────────────────────────
	h.NetworkMap = handlers.NewNetworkMapHandler(pool)

	// ─── Detailed Health Check Handler ───────────────────────
	h.DetailedHealth = handlers.NewDetailedHealthHandler(pool, nc, Version)

	// ─── Platform Upgrade Handler ─────────────────────────────
	natsVer := ""
	if nc != nil {
		natsVer = nc.ConnectedServerVersion()
	}
	platformUpgradeHandler := handlers.NewPlatformUpgradeHandler(pool, Version, BuildDate, Commit, natsVer, updateLatestVersion)
	h.PlatformUpgrade = platformUpgradeHandler
	h.UserProfile = handlers.NewUserProfileHandler(auditStore, notifPrefStore)
	// Record this deployment to platform_versions on startup (idempotent)
	go platformUpgradeHandler.RecordStartup(ctx)

	// ─── Agent Config Schema & Overrides ─────────────────────
	h.AgentConfig = handlers.NewAgentConfigHandler(pool)

	// ─── Alert Auto-Assignment Rules ──────────────────────────
	alertAssignStore := store.NewAlertAssignRuleStore(pool)
	h.AlertAssign = handlers.NewAlertAssignHandler(alertAssignStore)

	// ─── Alert Escalation Rules ───────────────────────────────
	escalationRuleStore := store.NewEscalationRuleStore(pool)
	h.EscalationRules = handlers.NewEscalationRuleHandler(escalationRuleStore)

	// ─── Correlation Rules ────────────────────────────────────
	h.Correlation = handlers.NewCorrelationHandler(pool)

	// ─── Correlation Engine Rules ─────────────────────────────
	h.CorrelationEngine = handlers.NewCorrelationEngineHandler(pool)

	// ─── Agent Version Checker ────────────────────────────────
	versionChecker := scheduler.NewVersionChecker(pool)
	go versionChecker.Run(ctx)
	slog.Info("エージェントバージョンチェッカーを開始しました")

	// ─── TLS Certificate Expiry Checker ───────────────────────
	go scheduler.NewCertExpiryChecker(pool, nc).Run(ctx)
	slog.Info("TLS証明書有効期限チェッカーを開始しました")

	// ─── Agent mTLS Certificate Renewer ───────────────────────
	go scheduler.NewAgentCertRenewer(agentStore, nc).Run(ctx)
	slog.Info("エージェントmTLS証明書更新チェッカーを開始しました")

	// ─── MDM Credential Expiry Checker ────────────────────────
	go scheduler.NewMDMCredentialExpiryChecker(pool, nc).Run(ctx)
	slog.Info("MDM資格情報有効期限チェッカーを開始しました")

	// ─── Retroactive IOC Hunter ───────────────────────────────
	// detection.IOCMatcher (in cmd/detection) covers "new events × all IOCs";
	// this covers "historical events × newly-added IOCs" so a freshly-synced
	// feed (e.g. ThreatFox) surfaces intrusions that already happened.
	// 30-day lookback, 6h cadence.
	go scheduler.NewRetroIOCHunter(pool, nc, 30, 6*time.Hour).Run(ctx)
	slog.Info("レトロアクティブIOCハンターを開始しました")

	// ─── Remediation Engine (早期初期化: Detection Pipeline が参照するため) ──
	earlyRemediationEngine := remediation.NewEngine(pool, nc)
	earlyRemediationEngine.SetIsolator(gatekeeper)
	remediation.LoadBuiltins(earlyRemediationEngine)
	if err := earlyRemediationEngine.LoadExclusionsFromDB(ctx); err != nil {
		slog.Warn("自動修復エンジン: 除外リストの読み込みに失敗しました", "error", err)
	}
	slog.Info("自動修復エンジンを初期化しました (早期)")

	// ─── Correlation Engine (早期初期化: Detection Pipeline が参照するため) ──
	correlationEngine := correlation.NewEngine(pool)
	correlation.LoadBuiltins(correlationEngine)
	slog.Info("相関エンジンを初期化しました", "builtin_rules", len(correlationEngine.ListRules()))

	// ─── Detection Pipeline (Sigma + UEBA Anomaly) ────────────
	pipeline := detection.NewAlertPipeline(pool, nc)
	pipeline.SetRemediationEngine(earlyRemediationEngine)
	pipeline.SetCorrelationEngine(correlationEngine)

	// ─── 抑制ルール (運用者が UI で作るもの) ──────────────────
	//
	// ★ ここが繋がっていないと、抑制ルールを作ってもアラートが止まらない。
	//
	// 抑制エンジンは前からあり server-detect は起動時から見ていたが、P4-6 (#647)
	// で DB Sigma ルールの所有権が server-api に移り、リアルタイムのアラートは
	// ほぼ全部この AlertPipeline が作るようになった。**アラートを作る側が
	// 入れ替わったのに結線が移らなかった**ため、UI 上は有効に見える抑制ルールが
	// 実際には何も抑えていない、という状態が残っていた。
	//
	// 読み込みは 5 分ごと + 起動時。ローダは server-detect と同じ実装
	// (PoolSuppressionLoader) なので、両プロセスが同じ行を同じ解釈で見る。
	suppressionMatcher := detection.NewSuppressionMatcher(detection.NewPoolSuppressionLoader(pool))
	suppressionMatcher.Start(ctx)
	pipeline.SetSuppressionMatcher(suppressionMatcher, suppressionStore)
	// 自分の封じ込め操作が端末のファイアウォールを変え、それをファイアウォール改変の
	// ルールが検知する自己検知ループを止める。detection/self_remediation_suppression.go
	pipeline.SetSelfRemediationSuppressor(detection.NewSelfRemediationSuppressor(responseActionStore))
	slog.Info("抑制ルールを AlertPipeline に結線しました", "count", suppressionMatcher.Count())
	// UI から抑制ルールを作った直後に効かせる。suppressions_handler.go が
	// suppressions.invalidate を publish しており、server-detect は最初から
	// 購読していた。こちらだけ 5 分待たされると、「作ったのに止まらない」を
	// 運用者が結線漏れと区別できない。
	if nc != nil {
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
			_ = sub.Unsubscribe()
		}()
	}
	sigmaEval := pipeline.GetSigmaEvaluator()
	// Load built-in MITRE ATT&CK-aligned Sigma rules first
	builtinCount := detection.LoadBuiltinRules(sigmaEval)
	slog.Info("組み込みSigmaルールを読み込みました", "count", builtinCount)
	if err := sigmaEval.LoadRulesFromDB(pool); err != nil {
		slog.Warn("Sigmaルールの読み込みに失敗しました", "error", err)
	} else {
		slog.Info("Sigmaルールを読み込みました", "count", sigmaEval.RuleCount())
	}
	if err := pipeline.GetAnomalyDetector().LoadBaselinesFromDB(pool); err != nil {
		slog.Warn("UEBAベースラインの読み込みに失敗しました", "error", err)
	}
	// ユーザー定義ルール (custom_alert_rules)。UI から作れるのに評価する側が
	// 無く、ずっと何も起きていなかった経路。
	if err := pipeline.ReloadCustomRules(ctx); err != nil {
		slog.Warn("ユーザー定義アラートルールの読み込みに失敗しました", "error", err)
	}
	go pipeline.Start(ctx)
	slog.Info("検知パイプラインを開始しました")

	// ─── Vulnerability Scanner ────────────────────────────────
	go scheduler.NewVulnerabilityScanner(pool, nc).Run(ctx)
	slog.Info("脆弱性スキャナーを開始しました")

	// ─── Auto Response Handler ────────────────────────────────
	autoResponseStore := store.NewAutoResponseStore(pool)
	h.AutoResponse = handlers.NewAutoResponseHandler(autoResponseStore)

	// ─── Custom Alert Rules Handler ───────────────────────────
	customAlertRuleStore := store.NewCustomAlertRuleStore(pool)
	h.CustomAlertRules = handlers.NewCustomAlertRulesHandler(customAlertRuleStore)
	// 書き込みのたびに検知パイプラインへ反映する。これが無いと UI で作った
	// ルールが API 再起動まで効かない。
	h.CustomAlertRules.SetReloadFunc(func() {
		if err := pipeline.ReloadCustomRules(ctx); err != nil {
			slog.Warn("ユーザー定義アラートルールの再読み込みに失敗しました", "error", err)
		}
	})

	// ─── Maintenance Windows ───────────────────────────────────
	maintenanceWindowStore := store.NewMaintenanceWindowStore(pool)
	h.MaintenanceWindow = handlers.NewMaintenanceWindowHandler(maintenanceWindowStore)

	// ─── Metrics API Handler ──────────────────────────────────
	h.MetricsAPI = handlers.NewMetricsAPIHandler(pool)

	// ─── Global Security Timeline Handler ────────────────────
	h.Timeline = handlers.NewTimelineHandler(pool)

	// ─── System Settings Handler ──────────────────────────────
	h.SystemSettings = handlers.NewSystemSettingsHandler(pool)

	// ─── SOC デイリーブリーフィング（毎朝8時）────────────────
	var natsPub func(string, []byte) error
	if nc != nil {
		natsPub = func(subject string, data []byte) error {
			return nc.Publish(subject, data)
		}
	}
	briefingSlackURL := os.Getenv("BRIEFING_SLACK_WEBHOOK_URL")
	briefingWebhookURL := os.Getenv("BRIEFING_WEBHOOK_URL")
	briefingSched := scheduler.NewDailyBriefingScheduler(pool, 8, natsPub, briefingSlackURL, briefingWebhookURL).
		WithEmail(
			os.Getenv("BRIEFING_SMTP_HOST"),
			func() string {
				if v := os.Getenv("BRIEFING_SMTP_PORT"); v != "" {
					return v
				}
				return "587"
			}(),
			os.Getenv("BRIEFING_SMTP_USER"),
			os.Getenv("BRIEFING_SMTP_PASS"),
			os.Getenv("BRIEFING_EMAIL_FROM"),
			os.Getenv("BRIEFING_EMAIL_TO"),
		)
	go briefingSched.Run(ctx)
	slog.Info("SOCデイリーブリーフィングスケジューラーを開始しました（毎朝8時）",
		"slack_enabled", briefingSlackURL != "",
		"webhook_enabled", briefingWebhookURL != "",
		"email_enabled", os.Getenv("BRIEFING_EMAIL_TO") != "",
	)

	// ─── Dark Web Monitor ─────────────────────────────────────
	darkwebEnabled := os.Getenv("DARKWEB_MONITOR_ENABLED") != "false"
	torProxy := os.Getenv("TOR_PROXY_URL")
	darkwebSched := scheduler.NewDarkWebScheduler(pool, torProxy, darkwebEnabled)
	// 即時通知設定（検知時に別途 Slack/Webhook へ緊急通知）
	darkwebSlack := os.Getenv("DARKWEB_ALERT_SLACK_WEBHOOK_URL")
	darkwebWebhook := os.Getenv("DARKWEB_ALERT_WEBHOOK_URL")
	darkwebEmailTo := os.Getenv("DARKWEB_ALERT_EMAIL_TO")
	if darkwebSlack != "" || darkwebWebhook != "" || darkwebEmailTo != "" {
		var ec *scheduler.EmailConfig
		if darkwebEmailTo != "" {
			ec = &scheduler.EmailConfig{
				Host: os.Getenv("BRIEFING_SMTP_HOST"),
				Port: func() string {
					if v := os.Getenv("BRIEFING_SMTP_PORT"); v != "" {
						return v
					}
					return "587"
				}(),
				User: os.Getenv("BRIEFING_SMTP_USER"),
				Pass: os.Getenv("BRIEFING_SMTP_PASS"),
				From: os.Getenv("BRIEFING_EMAIL_FROM"),
				To:   darkwebEmailTo,
			}
		}
		darkwebSched = darkwebSched.WithAlertNotify(darkwebSlack, darkwebWebhook, ec)
	}
	go darkwebSched.Run(ctx)
	slog.Info("ダークウェブ監視スケジューラーを開始しました",
		"enabled", darkwebEnabled,
		"tor_proxy", torProxy,
	)

	// ─── Alert Enrichment Pipeline ────────────────────────────
	go handlers.NewAlertEnrichmentPipeline(pool).Run(ctx)
	slog.Info("アラートエンリッチメントパイプラインを開始しました")

	// スケジュールレポートの実行は reports.Scheduler が担当する (下方で起動)。
	// ここには scheduler.ReportGenerator という 2 つめのループが存在していたが、
	// 同じ scheduled_reports テーブルを、存在しない列名 (next_run_at) で読み書き
	// していた。次回実行時刻の絞り込みが効かず、有効なレポートを 5 分ごとに
	// 無条件で再生成し続けていた (実測: 3 tick で 3 本、next_run が翌日でも生成)。
	// 生成物の記録先も存在しない reports テーブルで、recipients も未使用だった。

	// ─── Dead Agent Cleanup Scheduler ─────────────────────────
	go scheduler.NewDeadAgentCleanup(pool, nc).Run(ctx)
	slog.Info("デッドエージェントクリーンアップスケジューラーを開始しました")

	// ─── Data Retention Cleaner ───────────────────────────────
	// 保持日数は環境変数で調整可能（デフォルト: alerts=90日, playbook=180日）
	alertRetainDays := getEnvInt("ALERT_RETAIN_DAYS", 90)
	playbookRetainDays := getEnvInt("PLAYBOOK_RETAIN_DAYS", 180)
	go scheduler.NewDataRetentionCleaner(pool, alertRetainDays, playbookRetainDays, 365).Run(ctx)
	slog.Info("データ保持クリーナーを開始しました",
		"alert_retain_days", alertRetainDays,
		"playbook_retain_days", playbookRetainDays,
	)

	// ─── API Key Rotator Scheduler ────────────────────────────
	go scheduler.NewAPIKeyRotator(pool, nc).Run(ctx)
	slog.Info("APIキーローテーターを開始しました")

	// ─── Hunt Scheduler ───────────────────────────────────────
	go scheduler.NewHuntScheduler(pool, nc).Run(ctx)
	slog.Info("ハントスケジューラーを開始しました")

	// ─── Compliance Scorer Scheduler ──────────────────────────
	go scheduler.NewComplianceScorer(pool).Run(ctx)
	slog.Info("コンプライアンススコアラーを開始しました")

	// ─── CSPM 定期スキャン ─────────────────────────────────────
	// 引受情報 (ロール ARN + 外部 ID) が設定済みの AWS アカウントだけを
	// 対象にするので、未設定の環境では何もしない。
	//
	// EDR_CSPM_SCAN_INTERVAL_HOURS=0 で停止できる。顧客の AWS に対する
	// API 呼び出しなので、止める手段を rebuild 無しで用意しておく。
	cspmScanHours := getEnvInt("EDR_CSPM_SCAN_INTERVAL_HOURS", 24)
	if os.Getenv("EDR_CSPM_SCAN_INTERVAL_HOURS") == "0" {
		slog.Info("CSPM 定期スキャンは無効化されています (EDR_CSPM_SCAN_INTERVAL_HOURS=0)")
	} else {
		// 通知先は既存のアラート通知チャンネル (Slack / メール / Webhook /
		// Teams) を共有する。CSPM 専用の設定を増やさないのは、送り先が
		// 分かれていると片方だけ設定されていない状態に気づけないため。
		go scheduler.NewCSPMScanner(
			store.NewCSPMStore(pool),
			15*time.Minute,
			time.Duration(cspmScanHours)*time.Hour,
		).WithNotifier(dispatcher, baseURL).Run(ctx)
		slog.Info("CSPM 定期スキャンを開始しました", "interval_hours", cspmScanHours)
	}

	// ─── Asset Criticality Scorer Scheduler ───────────────────
	go scheduler.NewAssetCriticalityScorer(pool).Run(ctx)
	slog.Info("資産重要度スコアラーを開始しました")

	// ─── Compliance Posture Alerter ───────────────────────────
	// Turns collected encryption/hardening posture into open alerts.
	go scheduler.NewComplianceAlerter(pool, nc).Run(ctx)
	slog.Info("コンプライアンスアラーターを開始しました")

	// ─── Threat Feed Auto-Import Scheduler ───────────────────
	go scheduler.NewThreatFeedImporter(pool, nc).Run(ctx)
	slog.Info("脅威フィード自動インポートスケジューラーを開始しました")

	// ─── Log Ingestion Handler ────────────────────────────────
	h.LogIngestion = handlers.NewLogIngestionHandler(pool)

	// ─── Onboarding Wizard ────────────────────────────────────
	h.Onboarding = handlers.NewOnboardingHandler(pool)

	// ─── Session Management v2 ────────────────────────────────
	h.Session = handlers.NewSessionHandler(pool)

	// ─── SIEM Connector (outbound syslog/CEF) ─────────────────
	h.SIEMConnector = handlers.NewSIEMConnectorHandler(pool)

	// ─── Software Inventory Diff Tracker ─────────────────────
	h.SoftwareDiff = handlers.NewSoftwareDiffHandler(pool)

	// ─── EDR Policy Management ────────────────────────────────
	h.EDRPolicy = handlers.NewEDRPolicyHandler(pool)

	// ─── Audit Log Digital Signing ────────────────────────────
	h.AuditSign = handlers.NewAuditSignHandler(pool, os.Getenv("JWT_SECRET"))

	// ─── Incident Playbook Management (Task #372) ─────────────
	h.IncidentPlaybook = handlers.NewIncidentPlaybookHandler(pool)

	// ─── Cloud Asset Inventory (Task #373) ────────────────────
	h.CloudAsset = handlers.NewCloudAssetHandler(pool)

	// ─── DLP Rules Management (Task #374) ────────────────────
	h.DLP = handlers.NewDLPHandler(pool)

	// ─── Asset Criticality Scoring (Task #378) ────────────────
	h.AssetCriticality = handlers.NewAssetCriticalityHandler(pool)

	// ─── Realtime Alert Correlation Engine (Task #379) ────────
	go scheduler.NewRealtimeCorrelator(pool, nc).Run(ctx)
	slog.Info("リアルタイム相関エンジンを開始しました")

	// ─── GeoIP Lookup ─────────────────────────────────────────
	h.Geolocation = handlers.NewGeolocationHandler(pool)

	// ─── SSE Event Stream ─────────────────────────────────────
	h.EventStream = handlers.NewEventStreamHandler(nc)

	// ─── Honeypot/Deception Management (Task #380) ────────────
	h.Honeypot = handlers.NewHoneypotHandler(pool)

	// ─── Container/Kubernetes Workload Monitoring (Task #381) ─
	h.Container = handlers.NewContainerHandler(pool)

	// ─── Malware Sandbox Integration (Task #382) ──────────────
	h.Sandbox = handlers.NewSandboxHandler(pool)

	// ─── SOC Workflow Automation (Task #387) ──────────────────
	h.SOCTicket = handlers.NewSOCTicketHandler(pool)

	// ─── Network Anomaly Detection (Task #388) ────────────────
	go scheduler.NewNetworkAnomalyDetector(pool, nc).Run(ctx)
	slog.Info("ネットワーク異常検知スケジューラーを開始しました")

	// ─── Zero Trust Access Policy Management (Task #389) ──────
	h.ZeroTrust = handlers.NewZeroTrustHandler(pool)

	// ─── Privileged Access Management (Task #394) ─────────────
	h.PAM = handlers.NewPAMHandler(pool)

	// ─── Email Security Integration (Task #397) ───────────────
	h.EmailSecurity = handlers.NewEmailSecurityHandler(pool)

	// ─── Insider Threat Detection Scheduler (Task #396) ───────
	go scheduler.NewInsiderThreatDetector(pool, nc).Run(ctx)
	slog.Info("インサイダー脅威検知スケジューラーを開始しました")

	// ─── Asset Discovery (Task #403) ──────────────────────────
	h.AssetDiscovery = handlers.NewAssetDiscoveryHandler(pool)

	// ─── Security Awareness Training (Task #404) ──────────────
	h.Training = handlers.NewTrainingHandler(pool)

	// ─── Vulnerability Remediation Tracking (Task #407) ───────
	h.VulnRemediation = handlers.NewVulnRemediationHandler(pool)

	// ─── Third-Party/Supply Chain Risk Management (Task #411) ─
	h.VendorRisk = handlers.NewVendorRiskHandler(pool)

	// ─── Wireless/IoT Security Monitoring (Task #413) ─────────
	h.Wireless = handlers.NewWirelessHandler(pool)

	// ─── Incident Response Automation / SOAR-lite (Task #414) ─
	h.SOARWorkflow = handlers.NewSOARWorkflowHandler(pool, nc)

	// ─── SOC Shift Handover System (Task #417) ────────────────
	h.Shift = handlers.NewShiftHandler(pool)

	// ─── Patch Management System (Task #421) ──────────────────
	h.Patch = handlers.NewPatchHandler(pool, nc)

	// ─── Security Knowledge Base (Task #423) ──────────────────
	h.KnowledgeBase = handlers.NewKnowledgeBaseHandler(pool)

	// ─── Privacy/GDPR Compliance Management (Task #427) ───────
	h.GDPR = handlers.NewGDPRHandler(pool)

	// ─── Agent Auto-Remediation Engine (Task #430) ────────────
	h.AutoRemediation = handlers.NewAutoRemediationHandler(pool, nc)

	// ─── Security Metrics Historical API (Task #431) ──────────
	h.MetricsHistory = handlers.NewMetricsHistoryHandler(pool)

	// ─── Password Policy Management pool-based (Task #432) ────
	h.PasswordPolicy = handlers.NewPasswordPolicyHandlerWithPool(pool)

	// ─── OAuth2/OIDC Client Management (Task #433) ────────────
	h.OAuth2 = handlers.NewOAuth2Handler(pool)

	// ─── PagerDuty/OpsGenie Alerting Integration (Task #440) ──
	h.OnCall = handlers.NewOnCallHandler(pool, nc)

	// ─── Service Account Management (Task #441) ───────────────
	h.ServiceAccount = handlers.NewServiceAccountHandler(pool)

	// ─── Feature Flags Management (Task #442) ─────────────────
	h.FeatureFlag = handlers.NewFeatureFlagHandler(pool)

	// ─── Endpoint Tagging System (Task #443) ──────────────────
	h.EndpointTag = handlers.NewEndpointTagHandler(pool)

	// ─── Alert Digest Sender (Task #450) ──────────────────────
	digestSender := scheduler.NewAlertDigestSender(pool, nc)
	go digestSender.Run(ctx)
	slog.Info("アラートダイジェストセンダーを開始しました")
	h.Digest = handlers.NewDigestHandler(digestSender, pool)

	// ─── TAXII 2.1 Server (Task #451) ─────────────────────────
	h.TAXII = handlers.NewTAXIIHandler(pool)

	// ─── STIX 2.1 bundle import/export ─────────────────────────
	h.STIX = handlers.NewSTIXHandler(pool)

	// ─── Threat actor intel store (STIX-imported + manual) ─────
	h.ThreatActors = handlers.NewThreatActorHandler(pool)

	// ─── TI fusion views (sources + stats) ─────────────────────
	h.ThreatFusion = handlers.NewThreatFusionHandler(pool)

	// ─── Agent Auto-Enrollment Workflow (Task #452) ────────────
	h.Enrollment = handlers.NewEnrollmentHandler(pool, nc)

	// ─── Multi-Tenant Enhanced Management ────────────────────
	h.MultiTenant = handlers.NewMultiTenantHandler(pool)

	// ─── Log Analysis ─────────────────────────────────────────
	h.LogAnalysis = handlers.NewLogAnalysisHandler(pool)

	// ─── Deception Technology (Migration 116) ─────────────────
	h.Deception = handlers.NewDeceptionHandler(pool)

	// ─── Ransomware Protection (Migration 117) ────────────────
	h.Ransomware = handlers.NewRansomwareHandler(pool)

	// ─── Data Classification (Migration 118) ──────────────────
	h.DataClassification = handlers.NewDataClassificationHandler(pool)

	// ─── Security KPIs (Migration 119) ────────────────────────
	h.SecurityKPI = handlers.NewSecurityKPIHandler(pool)

	// ─── Adversary Emulation (Migration 254) ──────────────────
	h.AdversaryEmulation = handlers.NewAdversaryEmulationHandler(pool)

	// ─── Network Segmentation (Migration 255) ─────────────────
	h.NetworkSegmentation = handlers.NewNetworkSegmentationHandler(pool)

	// ─── Data Retention Policies (Migration 259) ──────────────
	h.DataRetention = handlers.NewDataRetentionHandler(pool)

	// ─── Endpoint Groups (Migration 260) ──────────────────────
	h.EndpointGroups = handlers.NewEndpointGroupsHandler(pool)

	// ─── Attack Surface Management (Migration 120) ────────────
	h.AttackSurface = handlers.NewAttackSurfaceHandler(pool)

	// ─── UEBA extended endpoints (Migration 121) ──────────────
	h.UEBA = handlers.NewUEBAHandler(pool)

	// ─── AI Alert Triage (Migration 122) ──────────────────────

	// ─── Capacity Planning (Migration 229) ────────────────────
	h.CapacityPlanning = handlers.NewCapacityPlanningHandler(pool)

	// ─── Incident Response Drills (Migration 261) ─────────────
	h.IncidentDrills = handlers.NewIncidentDrillsHandler(pool)

	// ─── Phishing Simulator (Migration 262) ───────────────────
	h.Phishing = handlers.NewPhishingHandler(pool)

	// ─── Penetration Testing (Migration 263) ──────────────────
	h.Pentest = handlers.NewPentestHandler(pool)

	// ─── Chaos Engineering (Migration 264) ────────────────────
	h.Chaos = handlers.NewChaosHandler(pool)

	// ─── Container Security Policies (Migration 123) ──────────
	h.ContainerSecurity = handlers.NewContainerSecurityHandler(pool)

	// ─── API Security (Migration 124) ─────────────────────────
	h.APISecurity = handlers.NewAPISecurityHandler(pool)

	// ─── Cloud-Native SIEM (Migration 125) ────────────────────
	h.CloudSIEM = handlers.NewCloudSIEMHandler(pool)

	// ─── Compliance Evidence (Migration 126) ──────────────────
	h.ComplianceEvidence = handlers.NewComplianceEvidenceHandler(pool)

	// ─── Security Metrics Reports (Migration 127) ─────────────
	h.MetricsReport = handlers.NewMetricsReportHandler(pool)

	// ─── Cloud Identity Federation (Migration 128) ────────────
	h.CloudIdentity = handlers.NewCloudIdentityHandler(pool)

	// ─── Deception Network / Honeynet (Migration 129) ─────────
	h.Honeynet = handlers.NewHoneynetHandler(pool)

	// ─── Incident Pattern Recognition (Migration 130) ─────────
	h.IncidentPattern = handlers.NewIncidentPatternHandler(pool)

	// ─── Breach & Attack Simulation (Migration 131) ────────────
	h.BAS = handlers.NewBASHandler(pool)

	// ─── Threat Context Enrichment (Migration 132) ─────────────
	h.ContextEnrichment = handlers.NewContextEnrichmentHandler(pool)

	// ─── Autonomous Response Policies (Migration 133) ──────────
	h.AutonomousPolicy = handlers.NewAutonomousPolicyHandler(pool)

	// ─── Compliance Workflows (Migration 134) ──────────────────
	h.ComplianceWorkflow = handlers.NewComplianceWorkflowHandler(pool)

	// ─── Predictive Analytics (Migration 135) ──────────────────
	h.PredictiveAnalytics = handlers.NewPredictiveAnalyticsHandler(pool)

	// ─── Forensics Automation (Migration 136) ──────────────────
	h.ForensicsAutomation = handlers.NewForensicsAutomationHandler(pool)

	// ─── Supply Chain Risk (Migration 137) ─────────────────────
	h.SupplyChainRisk = handlers.NewSupplyChainRiskHandler(pool)

	// ─── Enhanced Orchestration (Migration 138) ────────────────
	h.OrchestrationEnhanced = handlers.NewOrchestrationEnhancedHandler(pool)

	// ─── Threat Hunting Campaigns (Migration 139) ──────────────
	h.HuntingCampaign = handlers.NewHuntingCampaignHandler(pool)

	// ─── Compliance Auto-Remediation (Migration 140) ───────────
	h.ComplianceRemediation = handlers.NewComplianceRemediationHandler(pool)

	// ─── Zero Trust Network Access (Migration 141) ──────────────
	h.ZTNA = handlers.NewZTNAHandler(pool)

	// ─── Security Data Warehouse (Migration 142) ────────────────
	h.SecurityDW = handlers.NewSecurityDWHandler(pool)

	// ─── Endpoint Encryption Management (Migration 143) ─────────
	h.EncryptionMgmt = handlers.NewEncryptionMgmtHandler(pool)

	// ─── Patch Automation (Migration 144) ───────────────────────
	h.PatchAutomation = handlers.NewPatchAutomationHandler(pool)

	// ─── Security Governance (Migration 145) ────────────────────
	h.SecurityGovernance = handlers.NewSecurityGovernanceHandler(pool)

	// ─── NTA (Migration 146) ────────────────────────────────────
	h.NTA = handlers.NewNTAHandler(pool)

	// ─── ITDR (Migration 148) ───────────────────────────────────
	h.ITDR = handlers.NewITDRHandler(pool)

	// ─── CSPM Enhanced (Migration 149) ──────────────────────────
	h.CSPMEnhanced = handlers.NewCSPMEnhancedHandler(pool)

	// ─── Risk Scoring (Migration 150) ───────────────────────────
	h.RiskScoring = handlers.NewRiskScoringHandler(pool)

	// ─── Automation Enhanced (Migration 151) ─────────────────────
	h.AutomationEnhanced = handlers.NewAutomationEnhancedHandler(pool)

	// ─── Alert Routing (Migration 152) ───────────────────────────
	h.AlertRouting = handlers.NewAlertRoutingHandler(pool)

	// ─── Security Assessment (Migration 153) ─────────────────────
	h.SecurityAssessment = handlers.NewSecurityAssessmentHandler(pool)

	// ─── Digital Risk Protection (Migration 154) ──────────────────
	h.DRP = handlers.NewDRPHandler(pool)

	// ─── Training Management (Migration 155) ──────────────────────
	h.TrainingMgmt = handlers.NewTrainingMgmtHandler(pool)

	// ─── Quarantine Actions (Migration 156) ───────────────────────
	h.QuarantineActions = handlers.NewQuarantineActionsHandlerWithIsolator(pool, gatekeeper)

	// ─── Security SLA (Migration 157) ─────────────────────────────
	h.SecuritySLA = handlers.NewSecuritySLAHandler(pool)

	// ─── Threat Simulation (Migration 158) ────────────────────────
	h.ThreatSimulation = handlers.NewThreatSimulationHandler(pool)

	// ─── Vulnerability Findings (Migration 161) ────────────────────
	h.Vulnerability = handlers.NewVulnerabilityHandler(pool)

	// ─── Network Topology (Migration 164) ───────────────────────────
	h.NetworkTopology = handlers.NewNetworkTopologyHandler(pool)

	// ─── Security Metrics History (Migration 166) ────────────────────
	h.SecurityMetricsHistory = handlers.NewSecurityMetricsHistoryHandler(pool)

	// ─── Mobile Device Management (Migration 167) ─────────────────────

	// ─── Full MDM: profiles / commands / apps / integrations (Migration 231) ─

	// ─── MDM Enrollment (Migration 232): token → .mobileconfig / AE QR /
	//     iOS CheckIn / APNs push. The base URL is taken from
	//     MDM_SERVER_BASE_URL so the .mobileconfig ServerURL field
	//     resolves absolutely (iOS rejects relative URLs here).

	// ─── Endpoint Hardening (Migration 171) ────────────────────────────
	h.EndpointHardening = handlers.NewEndpointHardeningHandler(pool)

	// ─── Security Awareness Training (Migration 172) ───────────────────
	h.SecurityAwareness = handlers.NewSecurityAwarenessHandler(pool)

	// ─── Threat Hunting Query Engine ─────────────────────────────────
	huntEngine := hunting.NewEngine(pool)
	h.HuntingQuery = handlers.NewHuntingQueryHandler(huntEngine)

	// ─── ML-based Behavioral Analysis ────────────────────────
	mlEngine := ml.NewBehavioralEngine()
	go mlEngine.RunPeriodicTraining(ctx, 1*time.Hour)
	h.MLAnalytics = ml.NewMLHandler(mlEngine)
	h.MLSeed = handlers.NewMLSeedHandler(mlEngine)
	slog.Info("ML行動分析エンジンを開始しました")

	// ─── Behavioral Baseline Engine ───────────────────────────
	behavioralEngine := behavioral.NewEngine(pool)
	h.EndpointBaseline = handlers.NewEndpointBaselineHandler(pool)
	slog.Info("ベースラインエンジンを初期化しました")

	// ─── Ops Report ────────────────────────────────────────────
	h.OpsReport = handlers.NewOpsReportHandler(pool)

	// ─── Behavioral Baseline Rebuilder ───────────────────────
	go scheduler.NewBaselineRebuilder(pool, behavioralEngine).Run(ctx)
	slog.Info("ベースライン再構築ワーカーを開始しました（6時間ごと）")

	// Auto-seed ML training data on first start so the Isolation Forest has a
	// baseline.  We delay briefly to let the server finish initialising.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("ML training panic", "panic", r)
			}
		}()
		// Wait for the server to finish initialising, respecting context cancellation.
		select {
		case <-time.After(2 * time.Second):
			mlEngine.UEBA.TrainOnProfiles()
		case <-ctx.Done():
			return
		}
	}()

	// ─── Production Readiness: Health Probes ─────────────────
	h.Health = handlers.NewHealthHandler(pool, Version).WithBuildInfo(Commit, BuildDate)

	// ─── Threat Intelligence Feed Manager (Migration 177) ────
	tiManager := threatintel.NewFeedManager(pool)
	tiManager.LoadFromDB(ctx)
	threatintel.LoadBuiltinIOCs(tiManager)
	go tiManager.RunPeriodicSync(ctx)
	h.ThreatIntel = handlers.NewThreatIntelHandler(tiManager)
	slog.Info("脅威インテリジェンスフィードマネージャーを開始しました")

	// ─── Report Generator ────────────────────────────────────
	reportGenerator := reports.NewGenerator(pool)
	h.ReportGenerator = handlers.NewReportGeneratorHandler(reportGenerator)
	slog.Info("レポートジェネレーターハンドラーを初期化しました")

	// ─── Agent Configuration Profiles ────────────────────────
	agentConfigStore := agentconfig.NewStore(pool)
	h.AgentProfiles = handlers.NewAgentProfilesHandler(agentConfigStore, nc)
	slog.Info("エージェント設定プロファイルストアを初期化しました")

	// ─── Security Scorecard (NIST CSF / ISO 27001) ────────────
	scorecardScorer := scorecard.NewScorer(pool)
	h.Scorecard = handlers.NewScorecardHandler(scorecardScorer)
	slog.Info("セキュリティスコアカードスコアラーを初期化しました")

	// Multi-tenant management is wired through TenantHandler and
	// MultiTenantHandler, which read the `tenants` table every tenant_id
	// foreign key points at. The organization store that used to be here read a
	// parallel `organizations` table nothing referenced; migration 380 dropped
	// it along with its handler and routes.

	// ─── GeoIP Threat Map ─────────────────────────────────────
	h.GeoIP = handlers.NewGeoIPHandler(pool)
	slog.Info("GeoIPスレッドマップハンドラーを初期化しました")

	// ─── Structured Audit Log v2 ──────────────────────────────
	auditLogger := audit.NewLogger(pool)
	auditLogger.Start(ctx)
	h.AuditV2 = handlers.NewAuditHandler(auditLogger)
	slog.Info("構造化監査ログ v2 を開始しました")

	// ─── Migration 179: Sigma Rules Management API ────────────
	h.SigmaRules = handlers.NewSigmaRulesHandler(pool)
	h.SigmaRules.SetReloadFunc(pipeline.ReloadSigmaRules)
	slog.Info("Sigmaルール管理ハンドラーを初期化しました")

	// ─── Migration 181: SIEM Webhook Connector ────────────────
	siemConnector := siem.NewConnector(pool)
	if siemConnLoadErr := siemConnector.LoadFromDB(ctx); siemConnLoadErr != nil {
		slog.Warn("SIEMコネクターDBロード失敗", "error", siemConnLoadErr)
	}
	h.SIEMWebhook = handlers.NewSIEMWebhookHandler(siemConnector)
	slog.Info("SIEMウェブフックコネクターを初期化しました")

	// ─── Query Cache ──────────────────────────────────────────
	queryCache := cache.New(5 * time.Minute)
	slog.Info("クエリキャッシュを初期化しました")

	// ─── Alert Watchlist (Migration 189) ──────────────────────
	watchlistStore := watchlist.NewStore(pool)
	if err := watchlistStore.LoadCache(ctx); err != nil {
		slog.Warn("ウォッチリストキャッシュの読み込みに失敗しました", "error", err)
	}
	h.Watchlist = handlers.NewWatchlistHandler(watchlistStore)
	slog.Info("アラートウォッチリストを初期化しました")

	// ─── License Manager (Migration 190) ──────────────────────
	licenseMgr := license.NewManager(pool)
	if _, err := licenseMgr.GetCurrentLicense(ctx); err != nil {
		slog.Warn("ライセンス情報の読み込みに失敗しました", "error", err)
	}
	slog.Info("ライセンスマネージャーを初期化しました")

	// AI usage audit log handler — admin-only read of ai_usage_logs
	// (see server/migrations/238_ai_usage_logs.sql + aiassist.PgRecorder).

	// ─── System Updates (Migration 236, Phase 1-3) ────────────
	// Phase 3 onwards: poller has moved to the standalone updater container
	// (server/cmd/updater). The api container only owns the read API + admin
	// UI. The check endpoint falls back to its Phase 1 stub when no poller
	// is wired here, which is the intended state — the updater container
	// inserts new rows that the UI surfaces via list/current.

	// ─── License Expiry Notifier ──────────────────────────────
	go scheduler.NewLicenseExpiryNotifier(pool).Run(ctx)
	slog.Info("ライセンス期限切れ通知スケジューラーを開始しました")

	// ─── Support Tickets (Phase 5) ────────────────────────────
	{
		supportStore := support.NewStore(pool)
		h.Support = handlers.NewSupportHandler(supportStore)
		slog.Info("サポートチケットハンドラーを初期化しました")
	}

	// ─── System Handler ───────────────────────────────────────
	h.System = handlers.NewSystemHandler(pool, queryCache, nc)
	slog.Info("システムハンドラーを初期化しました")

	// ─── Network Analysis Handler (Migration 191) ─────────────
	netAnalyzer := netanalysis.NewAnalyzer(pool)
	h.NetAnalysis = handlers.NewNetAnalysisHandler(netAnalyzer)
	slog.Info("ネットワーク分析ハンドラーを初期化しました")

	// ─── Migration 185: Enhanced User Management ──────────────
	h.UserMgmt = handlers.NewUserManagementHandler(pool, jwtSecret)
	slog.Info("ユーザー管理ハンドラーを初期化しました")

	// ─── Migration 186: API Keys Manager ──────────────────────
	apiKeysMgr := apikeys.NewManager(pool)
	h.APIKeysMgr = handlers.NewAPIKeysHandler(apiKeysMgr)
	slog.Info("APIキーマネージャーを初期化しました")

	// ─── Migration 187: Webhook Dispatcher ────────────────────
	webhookDispatcher := webhooks.NewDispatcher(pool)
	// Pre-load existing webhook_configs from DB at startup
	if wbRows, wbErr := pool.Query(ctx, `
		SELECT id, name, url, COALESCE(secret,''), COALESCE(events,'{}'),
		       COALESCE(platform,'generic'), enabled, COALESCE(retry_count,3),
		       COALESCE(last_status,''), last_fired_at,
		       COALESCE(delivery_count,0), COALESCE(failure_count,0),
		       created_at
		FROM webhook_configs WHERE enabled = true`); wbErr == nil {
		var wbCfgs []*webhooks.WebhookConfig
		for wbRows.Next() {
			cfg := &webhooks.WebhookConfig{}
			if err := wbRows.Scan(
				&cfg.ID, &cfg.Name, &cfg.URL, &cfg.Secret, &cfg.Events,
				&cfg.Platform, &cfg.Enabled, &cfg.RetryCount,
				&cfg.LastStatus, &cfg.LastFiredAt,
				&cfg.DeliveryCount, &cfg.FailureCount,
				&cfg.CreatedAt,
			); err == nil {
				wbCfgs = append(wbCfgs, cfg)
			}
		}
		wbRows.Close()
		webhookDispatcher.LoadConfigs(wbCfgs)
		slog.Info("Webhookディスパッチャーに設定をロードしました", "count", len(wbCfgs))
	}
	h.WebhooksMgr = handlers.NewWebhooksHandler(webhookDispatcher, pool)
	slog.Info("Webhookディスパッチャーハンドラーを初期化しました")

	// ─── Migration 188: Config Backup & Restore ───────────────
	configBackupMgr := backup.NewManager(pool, getEnv("BACKUP_DIR", "./backups"))
	h.ConfigBackup = handlers.NewConfigBackupHandler(configBackupMgr)
	slog.Info("設定バックアップマネージャーを初期化しました")

	// ─── Migration 194: Memory Forensics ──────────────────────
	h.MemForensics = handlers.NewMemForensicsHandler(pool)
	slog.Info("メモリフォレンジックスハンドラーを初期化しました")

	// ─── Cloud Workload Runtime Protection ────────────────────
	h.CloudRuntime = handlers.NewCloudRuntimeHandler(pool)
	slog.Info("クラウドランタイム保護ハンドラーを初期化しました")

	// ─── Detection Performance Metrics ────────────────────────
	h.DetectionMetrics = handlers.NewDetectionMetricsHandler(pool)
	slog.Info("検知パフォーマンスメトリクスハンドラーを初期化しました")

	// ─── Staged curate of SigmaHQ-synced rules ────────────────
	h.Curate = handlers.NewCurateHandler(pool, nc)
	slog.Info("curate(段階有効化)ハンドラーを初期化しました")

	// ─── Mobile Threat Defense (MTD) verdict ingest ───────────
	slog.Info("モバイル脅威検知(MTD)verdict取り込みハンドラーを初期化しました")

	// ─── Endpoint Compliance Checker ──────────────────────────
	h.ComplianceChecker = handlers.NewComplianceCheckerHandler(pool)
	slog.Info("エンドポイントコンプライアンスチェッカーを初期化しました")

	// ─── Admin Compliance Status (NIST CSF + ISO 27001) ───────
	h.ComplianceStatus = handlers.NewComplianceStatusHandler(pool)
	slog.Info("準拠状況管理ハンドラーを初期化しました")

	// ─── Migration 192: Process Tree API ──────────────────────
	h.ProcessTree = handlers.NewProcessTreeHandler(pool)
	slog.Info("プロセスツリーハンドラーを初期化しました")

	// ─── Migration 192: Attack Timeline API ───────────────────
	h.AttackTimeline = handlers.NewAttackTimelineHandler(pool)
	slog.Info("アタックタイムラインハンドラーを初期化しました")

	// ─── Migration 192: AD/LDAP Identity Integration ──────────
	slog.Info("IDアイデンティティ統合ハンドラーを初期化しました")

	// ─── Migration 193: Scheduled Reports ─────────────────────
	reportScheduler := reports.NewScheduler(pool, reportGenerator, mailer)
	reportScheduler.LoadFromDB(ctx)
	go reportScheduler.Run(ctx)
	h.AdminReportSchedules = handlers.NewAdminReportSchedulesHandler(reportScheduler)
	slog.Info("スケジュールレポートスケジューラーを初期化しました")

	// ─── Migration 192: Public TI Feed Sync ───────────────────
	go threatintel.ScheduledSync(ctx, tiManager, 6)
	slog.Info("パブリック脅威インテリジェンスフィードの定期同期を開始しました")

	// ─── L-6: AI Auto-Investigation Handler ───────────────────
	h.Investigation = investigationHandler
	slog.Info("AI自動調査ハンドラーを初期化しました")

	// ─── L-7: Compliance Auto-Evaluation (CIS/NIST/SOC2) ───────
	h.ComplianceEval = handlers.NewComplianceEvalHandler(pool)
	complianceScheduler := compliancepkg.NewScheduler(pool)
	complianceScheduler.Start(ctx)
	slog.Info("コンプライアンス自動評価スケジューラーを起動しました（毎日 02:00 UTC）")

	// ─── Zero Trust Engine ────────────────────────────────────
	ztEngine := zerotrust.NewEngine(pool)
	h.ZeroTrustEngine = handlers.NewZeroTrustEngineHandler(ztEngine)
	slog.Info("Zero Trustエンジンを初期化しました")

	// ─── XDR Cross-Domain Detection Engine ───────────────────
	xdrEngine := xdr.NewEngine(pool)
	xdrEngine.SeedFromDB(ctx)
	h.XDR = handlers.NewXDRHandler(xdrEngine)
	slog.Info("XDRエンジンを初期化しました")

	// ─── B-01: RBAC Roles & Permissions ──────────────────────
	h.RBAC = handlers.NewRBACHandler(pool)
	slog.Info("RBACハンドラーを初期化しました")

	// ─── B-02: Access Review ──────────────────────────────────
	h.AccessReview = handlers.NewAccessReviewHandler(pool)
	slog.Info("アクセスレビューハンドラーを初期化しました")

	// ─── B-03: Risk Register ──────────────────────────────────
	h.RiskRegister = handlers.NewRiskRegisterHandler(pool)
	slog.Info("リスクレジスターハンドラーを初期化しました")

	// ─── B-05: Automation Workflows ──────────────────────────
	h.AutomationWorkflows = handlers.NewAutomationWorkflowsHandler(pool)
	slog.Info("自動化ワークフローハンドラーを初期化しました")

	// ─── B-07: Feed Analytics ────────────────────────────────
	h.FeedAnalytics = handlers.NewFeedAnalyticsHandler(pool)
	slog.Info("フィード分析ハンドラーを初期化しました")

	// ─── B-04: Insider Threat ─────────────────────────────────
	h.InsiderThreat = handlers.NewInsiderThreatHandler(pool)
	slog.Info("インサイダー脅威ハンドラーを初期化しました")

	// ─── B-06: IoT/OT Security ───────────────────────────────
	h.IoTOT = handlers.NewIoTOTHandler(pool)
	slog.Info("IoT/OTセキュリティハンドラーを初期化しました")

	// ─── B-08: Network Anomalies ─────────────────────────────
	h.NetworkAnomalies = handlers.NewNetworkAnomaliesHandler(pool)
	slog.Info("ネットワーク異常ハンドラーを初期化しました")

	// ─── B-09: Cloud Workload Security ───────────────────────
	h.CloudWorkload = handlers.NewCloudWorkloadHandler(pool)
	slog.Info("クラウドワークロードハンドラーを初期化しました")

	// ─── C-02: TIP Integration ───────────────────────────────
	h.TIPIntegration = handlers.NewTIPIntegrationHandler(pool)
	slog.Info("TIP統合ハンドラーを初期化しました")

	// ─── C: Integration Config Settings ──────────────────────
	h.IntegrationConfig = handlers.NewIntegrationConfigHandler(pool)
	slog.Info("統合設定ハンドラーを初期化しました")

	// ─── A: DNS Security page ─────────────────────────────────
	h.DNSSecurity = handlers.NewDNSSecurityHandler(pool)
	slog.Info("DNSセキュリティハンドラーを初期化しました")

	// ─── A: Cloud Security Posture page ──────────────────────
	h.CloudPosture = handlers.NewCloudPostureHandler(pool)
	slog.Info("クラウドセキュリティポスチャーハンドラーを初期化しました")

	// ─── A: Network Traffic stats ─────────────────────────────
	h.NetworkTraffic = handlers.NewNetworkTrafficHandler(pool)
	slog.Info("ネットワークトラフィックハンドラーを初期化しました")

	// ─── A: FIM page handler ──────────────────────────────────
	h.FIMPage = handlers.NewFIMPageHandler(pool)
	slog.Info("FIMページハンドラーを初期化しました")

	// ─── A: Dark Web monitoring page ──────────────────────────
	h.DarkWeb = handlers.NewDarkWebHandler(pool)
	slog.Info("ダークウェブ監視ハンドラーを初期化しました")

	// ─── A: Software Vulnerability inventory ─────────────────
	h.SoftwareVulnerability = handlers.NewSoftwareVulnerabilityHandler(pool)
	slog.Info("ソフトウェア脆弱性ハンドラーを初期化しました")

	// ─── Remediation Engine (auto-rollback, exclusions, webhook) ──
	// earlyRemediationEngine は Detection Pipeline との結線のため上部で初期化済み。
	h.Remediation = handlers.NewRemediationHandler(earlyRemediationEngine)
	slog.Info("自動修復エンジンをハンドラーに登録しました")

	// ─── API Server ───────────────────────────────────────────
	server := api.NewServer(h, wsHub, auditStore, pool, licenseMgr, apiKeyStore)

	slog.Info("REST API サーバーを起動中", "port", apiPort)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("シャットダウン中...")
		cancel()
	}()

	if err := server.Run(":" + apiPort); err != nil {
		slog.Error("REST APIサーバーエラー", "error", err)
		os.Exit(1)
	}

	slog.Info("REST APIサーバーを停止しました")
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
		return fallback
	}
	return n
}

// startSIEMAlertBridge subscribes to NATS "alert.created" and forwards each
// new alert to all enabled SIEM targets via siemForwarder.
// Runs as a goroutine; returns immediately if NATS or pool is nil.
func startSIEMAlertBridge(ctx context.Context, nc *nats.Conn, pool *pgxpool.Pool, fwd *siem.Forwarder) {
	if nc == nil || pool == nil || fwd == nil {
		return
	}

	sub, err := nc.Subscribe("alert.created", func(msg *nats.Msg) {
		var payload struct {
			AlertID string `json:"alert_id"`
		}
		if err := json.Unmarshal(msg.Data, &payload); err != nil || payload.AlertID == "" {
			return
		}

		// Fetch full alert from DB; join with agents for hostname / OS.
		var alert siem.AlertPayload
		err := pool.QueryRow(ctx, `
			SELECT a.id::text,
			       COALESCE(a.agent_id::text, ''),
			       COALESCE(ag.hostname, ''),
			       COALESCE(ag.os_type, ''),
			       COALESCE(a.title, ''),
			       a.severity,
			       a.status,
			       COALESCE(a.mitre_technique, ''),
			       COALESCE(a.ai_threat_name, ''),
			       COALESCE(a.ai_summary, ''),
			       a.created_at
			FROM alerts a
			LEFT JOIN agents ag ON ag.id = a.agent_id
			WHERE a.id = $1::uuid`,
			payload.AlertID,
		).Scan(
			&alert.ID, &alert.AgentID, &alert.Hostname, &alert.OS,
			&alert.RuleName, &alert.Severity, &alert.Status,
			&alert.MITRETechnique, &alert.AIThreatName, &alert.AISummary,
			&alert.CreatedAt,
		)
		if err != nil {
			slog.Debug("SIEM bridge: alert lookup failed", "alert_id", payload.AlertID, "error", err)
			return
		}

		fwd.Forward(ctx, &alert)
	})
	if err != nil {
		slog.Warn("SIEM bridge: NATS subscribe失敗", "error", err)
		return
	}

	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()

	slog.Info("SIEM alert bridge 起動 (subject=alert.created)")
}
