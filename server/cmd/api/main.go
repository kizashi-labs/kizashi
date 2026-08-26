// EDR Platform - REST API Server
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edr-platform/server/internal/api"
	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/edr-platform/server/internal/auth"
	"github.com/edr-platform/server/internal/behavioral"
	"github.com/edr-platform/server/internal/cache"
	edrconfig "github.com/edr-platform/server/internal/config"
	"github.com/edr-platform/server/internal/correlation"
	"github.com/edr-platform/server/internal/dedup"
	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/license"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/remediation"
	"github.com/edr-platform/server/internal/rulepack"
	"github.com/edr-platform/server/internal/scheduler"
	"github.com/edr-platform/server/internal/store"
	"github.com/edr-platform/server/internal/telemetry"
	"github.com/edr-platform/server/internal/tick"
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

	// このプロセスの ctx は、**背景の仕事だけ**が使います。検知・相関・
	// 保持削除・集計・通知はテナントを跨ぐので、全テナントを名乗ります。
	//
	// **HTTP の要求はここを継ぎません。** gin は `http.ListenAndServe` を
	// BaseContext 無しで呼ぶので、要求ごとの ctx は `context.Background()`
	// から生えます。認証前の経路に全テナントが要るぶんは、router 側で
	// 経路ごとに張ります（internal/api/system_access_ledger_test.go が
	// その一覧を留めます）。
	//
	// 名乗らないと、抜け道を落としたあと**背景の仕事が全部 0 行**に
	// なります。いまは抜け道が残っているので挙動は変わりません。
	ctx = store.WithSystemAccess(ctx)

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
	claudeKey := getEnv("CLAUDE_API_KEY", "")
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

	// Load detection content that ships outside the schema.
	//
	// The comment above describes a deployment whose missing migrations were
	// rule definitions, and whose absence showed up only as detections that
	// never fired. That is a symptom of shipping content as schema: the rules
	// can only move when the schema does, and a stale image is indistinguishable
	// from a healthy one. Packs separate the two — see internal/rulepack.
	//
	// Startup fails on a broken pack, matching how a failed migration is
	// treated. The loader is atomic, so nothing is half-applied and the previous
	// content survives; the risk being guarded against is the other one, an API
	// that comes up healthy with no detection content and says nothing. An
	// operator who just deployed a pack should learn it is malformed now.
	if packDir := os.Getenv("EDR_RULEPACK_DIR"); packDir != "" {
		// ★ **検知コンテンツの不備で API を落としてはいけない。**
		//
		// ここは以前 os.Exit(1) だった。実機で core パックを初めて読ませたとき、
		// DB に同名の未所有ルールが2件あった1ルールで LoadDir が失敗し、api が
		// 起動できずクラッシュループに入った——コンソールも API も全て止まる。
		//
		// パックは「あると検知が増える」ものであって、管理面の前提条件ではない。
		// 読めなければ組み込みルールで動く（公開版はパック無しで動く構成が既定）。
		// 失敗は残すが、それは**画面が見えている状態で**残す必要がある。
		res, lerr := rulepack.LoadDir(ctx, store.NewRuleStore(db), packDir)
		if lerr != nil {
			metrics.BackgroundFailed("rulepack_load", lerr,
				"ルールパックを読み込めませんでした（組み込みルールで続行します）", "dir", packDir)
		}
		slog.Info("ルールパックを読み込みました",
			"dir", packDir, "packs", res.Packs, "rules", res.Rules,
			"inserted", res.Inserted, "updated", res.Updated,
			"skipped", len(res.Skipped))
		for _, sk := range res.Skipped {
			// 取り込めなかったルールは1件ずつ残す。まとめて件数だけにすると、
			// 「どのルールが効いていないのか」が分からないまま運用が続く。
			metrics.BackgroundFailed("rulepack_rule_skipped", fmt.Errorf("%s", sk.Reason),
				"ルールパック: 取り込めなかったルール", "pack", sk.Pack, "rule", sk.Rule)
		}
	}

	// ─── Seed initial admin user ──────────────────────────────
	if adminPwd := getEnv("ADMIN_PASSWORD", ""); adminPwd != "" {
		if err := store.SeedAdminUser(ctx, db.Pool(), adminPwd); err != nil {
			slog.Warn("管理者ユーザーのシードに失敗しました", "error", err)
		}

		// ─── 管理者パスワードの復旧（明示的に頼まれたときだけ） ───
		//
		// SeedAdminUser は users が空のときしか動かないので、運用が始まった環境で
		// `.env` の ADMIN_PASSWORD を変えても DB のハッシュは変わりません。
		// 締め出されたときの唯一の復旧口なので、**やったこと・やらなかったことを
		// 必ずログに出します**（黙って何もしないと、効かない設定を疑えません）。
		if getEnv("ADMIN_PASSWORD_RESET", "") == "true" {
			n, err := store.ResetAdminPassword(ctx, db.Pool(), adminPwd)
			switch {
			case err != nil:
				slog.Error("ADMIN_PASSWORD_RESET=true ですが管理者パスワードを再設定できませんでした", "error", err)
			case n == 0:
				slog.Warn("ADMIN_PASSWORD_RESET=true ですが admin@example.com が見つからず、何も変更していません")
			default:
				slog.Warn("ADMIN_PASSWORD_RESET=true のため admin@example.com のパスワードを .env の値で上書きし、ロックを解除しました。復旧後は ADMIN_PASSWORD_RESET を外してください", "rows", n)
			}
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
	userStore := store.NewUserStore(db)
	auditStore := store.NewAuditStore(db)
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
	suppressionStore := store.NewSuppressionStore(db)
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

	// Wrap alert store for the AIHandler's AlertQueryStore interface

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
	authHandler := handlers.NewAuthHandler(jwtSecret, userStore)
	// login_failed の監査行（insider_threat_detector の総当たり検知が読む）
	authHandler.Audit = auditStore
	authHandler.Blocklist = tokenBlocklist
	authHandler.UserCache = userCache
	settingsHandler := handlers.NewSettingsHandler(pool, dispatcher)
	settingsHandler.Publisher = nc // signal detection engine on channel config changes
	usersHandler := handlers.NewUsersHandler(userStore)
	// role_change の監査行（insider_threat_detector の権限昇格検知が読む）
	usersHandler.Audit = auditStore
	usersHandler.UserCache = userCache

	// ─── Agent Auto-Update ────────────────────────────────────
	// latestVersion/URL/checksum can be overridden via environment variables
	// or loaded from settings. Defaults are empty (no update offered) until
	// an operator configures a release.
	updateLatestVersion := getEnv("AGENT_LATEST_VERSION", "")

	// ─── Agent Binary Downloads ───────────────────────────────
	downloadHandler := handlers.NewDownloadHandler(getEnv("AGENT_BIN_DIR", "./downloads"))

	// ─── Session Management ───────────────────────────────────
	sessionStore := store.NewSessionStore(pool)
	authHandler.Sessions = sessionStore // enable login session recording
	sessionHandler := handlers.NewSessionHandler(pool)

	slog.Info("YARAコミュニティルール同期を有効化しました")

	// ─── Dashboard Widget Layout Persistence ─────────────────
	dashboardStore := store.NewDashboardStore(pool)
	dashboardHandler := handlers.NewDashboardHandler(dashboardStore)

	slog.Info("Webhookノーティファイアを開始しました")

	// ─── NATS Event → Webhook Forwarder ──────────────────────
	slog.Info("NATSイベント→Webhookフォワーダーを開始しました")

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

	// ─── Password Reset ───────────────────────────────────────
	passwordResetStore := store.NewPasswordResetStore(db)
	passwordResetHandler := handlers.NewPasswordResetHandler(passwordResetStore, userStore, baseURL, mailer)

	// ─── API Keys ─────────────────────────────────────────────
	apiKeyStore := store.NewAPIKeyStore(pool)

	ingestToken := getEnv("WAZUH_INGEST_TOKEN", "")
	ingestHandler := handlers.NewIngestHandler(pool, ingestToken)

	// ─── License Manager (Migration 190) ──────────────────────
	licenseMgr := license.NewManager(pool)
	if _, err := licenseMgr.GetCurrentLicense(ctx); err != nil {
		slog.Warn("ライセンス情報の読み込みに失敗しました", "error", err)
	}
	slog.Info("ライセンスマネージャーを初期化しました")

	h := api.NewHandlers(
		agentHandler,
		alertHandler,
		eventHandler,
		authHandler,
		settingsHandler,
		usersHandler,
		ingestHandler,
		downloadHandler,
		sessionHandler,
		emailMFAHandler,
		passwordPolicyHandler,
		passwordResetHandler,
	)

	// 有償版だけのハンドラをここで結線する。公開版ではこの呼び出しは何もしない
	// （internal/api/wire_commercial.go が overlay で空実装に差し替わる）。
	// ルート登録より前であればよく、NewHandlers の直後がその最も早い時点。
	h.WireCommercial(ctx, api.CommercialDeps{
		Pool:                pool,
		NATS:                nc,
		AlertStore:          alertStore,
		AgentStore:          agentStore,
		LicenseMgr:          licenseMgr,
		Mailer:              mailer,
		JWTSecret:           jwtSecret,
		FrontendURL:         frontendURL,
		IngestToken:         ingestToken,
		ClaudeKey:           claudeKey,
		AnthropicKey:        anthropicKey,
		Version:             Version,
		AgentLatestVersion:  updateLatestVersion,
		AgentLatestURL:      getEnv("AGENT_LATEST_URL", ""),
		AgentLatestChecksum: getEnv("AGENT_LATEST_CHECKSUM", ""),
		AgentBinDir:         getEnv("AGENT_BIN_DIR", "./downloads"),
	})

	// ─── WebSocket Real-Time Feed ─────────────────────────────
	h.WebSocket = handlers.NewWebSocketHandler()

	// ─── Alert Action Endpoints (status / enrich) ─────────────
	h.AlertAction = handlers.NewAlertActionHandler(pool)

	// ─── Dashboard Widget Layout ──────────────────────────────
	h.Dashboard = dashboardHandler

	// ─── Dashboard Statistics (time-series KPIs) ──────────────
	h.DashboardStats = handlers.NewDashboardStatsHandler(pool)

	// ─── Agent Installer Scripts ──────────────────────────────
	installerHandler := handlers.NewInstallerHandler(
		getEnv("SERVER_URL", "http://localhost:8080"),
		getEnv("AGENT_BIN_DIR", "./downloads"),
		pool,
	)
	h.Installer = installerHandler

	// ─── OpenAPI / Swagger UI Docs ────────────────────────────
	docsHandler := handlers.NewDocsHandler("./docs/openapi.yaml")
	h.Docs = docsHandler

	// ─── Email Verification ───────────────────────────────────
	h.EmailVerify = handlers.NewEmailVerificationHandler(pool, baseURL, mailer)

	// ─── User Preferences ─────────────────────────────────────
	userPrefsStore := store.NewUserPreferencesStore(pool)
	h.UserPreferences = handlers.NewUserPreferencesHandler(userPrefsStore)

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

	slog.Info("レポートメール配信スケジューラーを開始しました")

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

	agentHealthAlerter := scheduler.NewAgentHealthAlerter(pool, nc)
	go agentHealthAlerter.Run(ctx)
	slog.Info("エージェントヘルスアラーターを開始しました")

	// ─── Cloud Workload Monitoring Poller ─────────────────────

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

	// ─── Detailed Health Check Handler ───────────────────────
	h.DetailedHealth = handlers.NewDetailedHealthHandler(pool, nc, Version)

	h.UserProfile = handlers.NewUserProfileHandler(auditStore, notifPrefStore)

	// ─── Agent Config Schema & Overrides ─────────────────────
	h.AgentConfig = handlers.NewAgentConfigHandler(pool)

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
	// Start は JetStream → core NATS の順に降格し、どちらも張れなかった場合だけ
	// エラーを返す。つまり非 nil = 検知が 1 件も動いていない。goroutine で
	// 投げっぱなしにしていたため、その状態でも直後の Info だけが出て
	// 「開始しました」に見えていた。
	go func() {
		if err := pipeline.Start(ctx); err != nil && ctx.Err() == nil {
			slog.Error("検知パイプラインが起動できませんでした(アラートは生成されません)",
				"error", err)
		}
	}()
	slog.Info("検知パイプラインを開始しました")

	// ─── Vulnerability Scanner ────────────────────────────────
	go scheduler.NewVulnerabilityScanner(pool, nc).Run(ctx)
	slog.Info("脆弱性スキャナーを開始しました")

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
	// オプトイン。有効にすると起動直後に ransomwatch / ransomware.live へ
	// 外向き HTTPS が出るため、明示的に true を設定した場合だけ動かす。
	// 「既定では何も外に出ない」を実装側で保証するのはここ。
	darkwebEnabled := scheduler.DarkWebEnabled(os.Getenv("DARKWEB_MONITOR_ENABLED"))
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
	go scheduler.NewDataRetentionCleaner(pool, alertRetainDays, playbookRetainDays, 365).
		WithAuditRetention(getEnvInt("AUDIT_RETAIN_DAYS", 0)).Run(ctx)
	slog.Info("データ保持クリーナーを開始しました",
		"alert_retain_days", alertRetainDays,
		"playbook_retain_days", playbookRetainDays,
	)

	// ─── API Key Rotator Scheduler ────────────────────────────
	slog.Info("APIキーローテーターを開始しました")

	// ─── Hunt Scheduler ───────────────────────────────────────
	go scheduler.NewHuntScheduler(pool, nc).Run(ctx)
	slog.Info("ハントスケジューラーを開始しました")

	// ─── Compliance Scorer Scheduler ──────────────────────────
	slog.Info("コンプライアンススコアラーを開始しました")

	// ─── CSPM 定期スキャン ─────────────────────────────────────
	// 引受情報 (ロール ARN + 外部 ID) が設定済みの AWS アカウントだけを
	// 対象にするので、未設定の環境では何もしない。
	//
	// EDR_CSPM_SCAN_INTERVAL_HOURS=0 で停止できる。顧客の AWS に対する
	// API 呼び出しなので、止める手段を rebuild 無しで用意しておく。

	// ─── Asset Criticality Scorer Scheduler ───────────────────
	go scheduler.NewAssetCriticalityScorer(pool).Run(ctx)
	slog.Info("資産重要度スコアラーを開始しました")

	// ─── Compliance Posture Alerter ───────────────────────────
	// Turns collected encryption/hardening posture into open alerts.
	go scheduler.NewComplianceAlerter(pool, nc).Run(ctx)
	slog.Info("コンプライアンスアラーターを開始しました")

	// ─── Session Management v2 ────────────────────────────────
	h.Session = handlers.NewSessionHandler(pool)

	// ─── Alert Suppression Rules (pattern-based) ─────────────

	// ─── Realtime Alert Correlation Engine (Task #379) ────────
	go scheduler.NewRealtimeCorrelator(pool, nc).Run(ctx)
	slog.Info("リアルタイム相関エンジンを開始しました")

	// ─── Network Anomaly Detection (Task #388) ────────────────
	slog.Info("ネットワーク異常検知スケジューラーを開始しました")

	// ─── Insider Threat Detection Scheduler (Task #396) ───────
	slog.Info("インサイダー脅威検知スケジューラーを開始しました")

	// ─── Password Policy Management pool-based (Task #432) ────
	h.PasswordPolicy = handlers.NewPasswordPolicyHandlerWithPool(pool)

	slog.Info("アラートダイジェストセンダーを開始しました")

	// ─── Agent Auto-Enrollment Workflow (Task #452) ────────────
	h.Enrollment = handlers.NewEnrollmentHandler(pool, nc)

	// ─── ML-based Behavioral Analysis ────────────────────────
	mlEngine := ml.NewBehavioralEngine()
	go mlEngine.RunPeriodicTraining(ctx, 1*time.Hour)
	h.MLAnalytics = ml.NewMLHandler(mlEngine)
	slog.Info("ML行動分析エンジンを開始しました")

	// ─── Behavioral Baseline Engine ───────────────────────────
	behavioralEngine := behavioral.NewEngine(pool)
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

	slog.Info("脅威インテリジェンスフィードマネージャーを開始しました")

	slog.Info("レポートジェネレーターハンドラーを初期化しました")

	slog.Info("エージェント設定プロファイルストアを初期化しました")

	slog.Info("セキュリティスコアカードスコアラーを初期化しました")

	// Multi-tenant management is wired through TenantHandler and
	// MultiTenantHandler, which read the `tenants` table every tenant_id
	// foreign key points at. The organization store that used to be here read a
	// parallel `organizations` table nothing referenced; migration 380 dropped
	// it along with its handler and routes.

	// Wire the audit recorder so every Claude API call lands in
	// ai_usage_logs (compliance series step 4, v1.3.9). Best-effort —
	// recorder failures don't break the user-visible AI flow.
	// Start the APPI §6 retention cleaner: deletes ai_usage_logs rows
	// older than 1 year. Runs daily; errors are logged, never fatal.

	slog.Info("GeoIPスレッドマップハンドラーを初期化しました")

	slog.Info("構造化監査ログ v2 を開始しました")

	slog.Info("Sigmaルール管理ハンドラーを初期化しました")

	slog.Info("SIEMウェブフックコネクターを初期化しました")

	slog.Info("エージェント自動アップデートマネージャーを初期化しました")

	// ─── Query Cache ──────────────────────────────────────────
	queryCache := cache.New(5 * time.Minute)
	slog.Info("クエリキャッシュを初期化しました")

	slog.Info("アラートウォッチリストを初期化しました")

	slog.Info("システム更新トラッキングハンドラーを初期化しました (poller は updater container)")

	// ─── License Expiry Notifier ──────────────────────────────
	slog.Info("ライセンス期限切れ通知スケジューラーを開始しました")

	slog.Info("課金猶予期間ワーカーを開始しました")

	slog.Info("課金猶予期間通知スケジューラーを開始しました")

	// ─── System Handler ───────────────────────────────────────
	h.System = handlers.NewSystemHandler(pool, queryCache, nc)
	slog.Info("システムハンドラーを初期化しました")

	slog.Info("ネットワーク分析ハンドラーを初期化しました")

	slog.Info("ユーザー管理ハンドラーを初期化しました")

	slog.Info("APIキーマネージャーを初期化しました")

	slog.Info("Webhookディスパッチャーハンドラーを初期化しました")

	slog.Info("設定バックアップマネージャーを初期化しました")

	slog.Info("メモリフォレンジックスハンドラーを初期化しました")

	slog.Info("クラウドランタイム保護ハンドラーを初期化しました")

	slog.Info("検知パフォーマンスメトリクスハンドラーを初期化しました")

	slog.Info("curate(段階有効化)ハンドラーを初期化しました")

	// ─── Mobile Threat Defense (MTD) verdict ingest ───────────
	slog.Info("モバイル脅威検知(MTD)verdict取り込みハンドラーを初期化しました")

	slog.Info("エンドポイントコンプライアンスチェッカーを初期化しました")

	slog.Info("準拠状況管理ハンドラーを初期化しました")

	slog.Info("プロセスツリーハンドラーを初期化しました")

	slog.Info("アタックタイムラインハンドラーを初期化しました")

	// ─── Migration 192: AD/LDAP Identity Integration ──────────
	slog.Info("IDアイデンティティ統合ハンドラーを初期化しました")

	slog.Info("スケジュールレポートスケジューラーを初期化しました")

	slog.Info("パブリック脅威インテリジェンスフィードの定期同期を開始しました")

	slog.Info("AI自動調査ハンドラーを初期化しました")

	slog.Info("コンプライアンス自動評価スケジューラーを起動しました（毎日 02:00 UTC）")

	// ─── M-3: Mobile Push Token ────────────────────────────────
	slog.Info("モバイルプッシュトークンハンドラーを初期化しました")

	slog.Info("Zero Trustエンジンを初期化しました")

	slog.Info("XDRエンジンを初期化しました")

	slog.Info("RBACハンドラーを初期化しました")

	slog.Info("アクセスレビューハンドラーを初期化しました")

	slog.Info("リスクレジスターハンドラーを初期化しました")

	slog.Info("自動化ワークフローハンドラーを初期化しました")

	slog.Info("フィード分析ハンドラーを初期化しました")

	slog.Info("インサイダー脅威ハンドラーを初期化しました")

	slog.Info("IoT/OTセキュリティハンドラーを初期化しました")

	slog.Info("ネットワーク異常ハンドラーを初期化しました")

	slog.Info("クラウドワークロードハンドラーを初期化しました")

	slog.Info("TIP統合ハンドラーを初期化しました")

	slog.Info("統合設定ハンドラーを初期化しました")

	slog.Info("DNSセキュリティハンドラーを初期化しました")

	slog.Info("クラウドセキュリティポスチャーハンドラーを初期化しました")

	slog.Info("ネットワークトラフィックハンドラーを初期化しました")

	slog.Info("FIMページハンドラーを初期化しました")

	slog.Info("ダークウェブ監視ハンドラーを初期化しました")

	slog.Info("ソフトウェア脆弱性ハンドラーを初期化しました")

	slog.Info("自動修復エンジンをハンドラーに登録しました")

	// ─── API Server ───────────────────────────────────────────

	// Free 版が同梱しない配線（公開版は wire_noncore.go を no-op に差し替える）
	h.WireNoncore(ctx, api.NoncoreDeps{
		EarlyRemediationEngine: earlyRemediationEngine,
		JwtSecret:              jwtSecret,
		MlEngine:               mlEngine,
		Gatekeeper:             gatekeeper,
		Pipeline:               pipeline,
		BuildDate:              BuildDate,
		Commit:                 Commit,
		Version:                Version,
		UpdateLatestVersion:    updateLatestVersion,
		Dispatcher:             dispatcher,
		UserPrefsStore:         userPrefsStore,
		DbURL:                  dbURL,
		TenantEncryptor:        tenantEncryptor,
		UserStore:              userStore,
		Mailer:                 mailer,
		FrontendURL:            frontendURL,
		ApiKeyStore:            apiKeyStore,
		NotifPrefStore:         notifPrefStore,
		BaseURL:                baseURL,
		SuppressionStore:       suppressionStore,
		QuarantineStore:        quarantineStore,
		IocStore:               iocStore,
		Commander:              commander,
		AlertStore:             alertStore,
		AgentStore:             agentStore,
		Db:                     db,
		AnthropicKey:           anthropicKey,
		Nc:                     nc,
		Pool:                   pool,
	})

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
