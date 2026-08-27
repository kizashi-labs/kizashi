// EDR Platform - gRPC Ingestion Server
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/edr-platform/server/internal/health"
	"github.com/edr-platform/server/internal/ingestion"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/natsstream"
	"github.com/edr-platform/server/internal/store"
	"github.com/edr-platform/server/internal/telemetry"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/credentials"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── OpenTelemetry Tracing ────────────────────────────────
	if shutdown, err := telemetry.InitTracer(ctx, "edr-ingestion"); err != nil {
		slog.Warn("トレーサーの初期化に失敗しました", "error", err)
	} else {
		defer shutdown(ctx)
	}
	if shutdownMetrics, err := telemetry.InitMetrics(ctx, "edr-ingestion"); err != nil {
		slog.Warn("メトリクスプロバイダーの初期化に失敗しました", "error", err)
	} else {
		defer shutdownMetrics(ctx)
	}

	// ─── Config ───────────────────────────────────────────────
	dbURL := mustEnv("DATABASE_URL")
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	grpcPort := getEnv("GRPC_PORT", "9090")

	// ─── TLS (mTLS for agent communication) ───────────────────
	var creds credentials.TransportCredentials
	if getEnv("TLS_ENABLED", "true") == "true" {
		tlsCert := mustEnv("TLS_CERT_FILE")
		tlsKey := mustEnv("TLS_KEY_FILE")
		caCertFile := mustEnv("CA_CERT_FILE")

		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			slog.Error("TLS証明書の読み込みに失敗しました", "error", err)
			os.Exit(1)
		}

		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			slog.Error("CA証明書の読み込みに失敗しました", "error", err)
			os.Exit(1)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			slog.Error("CA証明書のパースに失敗しました")
			os.Exit(1)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}
		creds = credentials.NewTLS(tlsCfg)
		slog.Info("mTLS有効")
	} else {
		slog.Info("TLS無効 — 平文gRPC")
	}

	// ─── Database ─────────────────────────────────────────────
	// Prefer the non-superuser edr_app runtime role when APP_DATABASE_URL is
	// set (RLS tenant isolation — migration 325). Falls back to DATABASE_URL
	// when unset.
	//
	// 取り込みは全テナントの端末からイベントを受けるので、**全テナントを
	// 名乗ります**（migration 450）。以前は「app.tenant_id を張らないので
	// エスケープ節が通す」形でした —— **設定し忘れと同じ形**だったので、
	// 名乗る側に変えています。挙動は変わりません（抜け道はまだ残って
	// います）。
	ctx = store.WithSystemAccess(ctx)
	appDBURL := getEnv("APP_DATABASE_URL", dbURL)
	db, err := store.Connect(ctx, appDBURL)
	if err != nil {
		slog.Error("データベース接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer db.Close()

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

	// ─── JetStream streams ────────────────────────────────────
	if err := natsstream.Ensure(context.Background(), nc); err != nil {
		slog.Warn("JetStreamストリームのセットアップに失敗しました（NATS JetStream未対応環境の可能性）", "error", err)
		// Non-fatal: fallback to plain NATS publish in the server
	} else {
		slog.Info("NATSストリームを確認/作成しました")
	}

	// ─── Command Dispatcher ───────────────────────────────────
	dispatcher := ingestion.NewInMemoryCommandDispatcher()

	// ─── NATS → Dispatcher bridge ─────────────────────────────
	// API server publishes commands to NATS; relay them into the dispatcher
	// so the gRPC streaming handler can deliver them to connected agents.
	startNATSCommandBridge(nc, dispatcher)

	// ─── Ingestion Server ─────────────────────────────────────
	agentStore := store.NewAgentStore(db)
	server := ingestion.NewServer(&agentStoreAdapter{agentStore}, db.Pool(), nc, dispatcher, creds)

	// 隔離中も到達させるアドレス。proto の allow_ips は最初からあったが、
	// **サーバがここを一度も詰めていなかった**ので、隔離された端末から届くのは
	// EDR サーバとループバックだけだった。踏み台や DC を残す手段が運用側に無い。
	//
	// 起動時に弾く。受け側の agent も解釈できない項目は落としてログに出すが、
	// それが読まれるのは端末が隔離されたあとで、そのときには「除外したはずの
	// セグメントが遮断されている」状態になっている。隔離は外から取り消せない。
	allowIPs, rejected := ingestion.ParseAllowIPs(os.Getenv("ISOLATION_ALLOW_IPS"))
	for _, r := range rejected {
		// **警告で済ませて続行する。** ここで停止すると、1 行の書き間違いで
		// ingestion が上がらなくなり、隔離どころかイベントの受け口ごと落ちる。
		// ただし黙って捨てはしない —— 捨てられた項目は「除外したはずの
		// セグメントが遮断される」として現れ、隔離を解くまで気づけない。
		slog.Error("ISOLATION_ALLOW_IPS に解釈できない項目があります。この項目は許可されません",
			"entry", r)
	}
	if len(allowIPs) > 0 {
		slog.Info("隔離中も到達を許可するアドレスを読み込みました",
			"件数", len(allowIPs), "対象", allowIPs)
	} else {
		// 空が既定であることを起動ログに残す。「設定したのに効かない」と
		// 「そもそも配られていない」を、あとから切り分けられるようにする
		// （compose が env を渡していなかったために検査が丸ごと素通りした
		// 前例がある）。
		slog.Info("ISOLATION_ALLOW_IPS は未設定です。隔離中の到達先は EDR サーバとループバックのみになります")
	}
	server.SetIsolationAllowIPs(allowIPs)

	// アンインストール保護の材料を gRPC のハートビート応答にも載せる。
	//
	// HTTP 側 (agents_handler) だけに載せると、`FallbackSender` が gRPC を
	// 先に試す以上、gRPC が生きている通常時に端末へ届きません。検証は
	// 通信が切れた状態でも走るため、必要になってから取りに行くことは
	// できず、事前に置いてあることが前提の機能です。
	guardStore := store.NewUninstallProtectionStore(db.Pool())
	server.SetUninstallGuardProvider(func(ctx context.Context, agentID string) map[string]any {
		var tenantID string
		if err := db.Pool().QueryRow(ctx,
			`SELECT COALESCE(tenant_id::text, '') FROM agents WHERE id = $1::uuid`,
			agentID).Scan(&tenantID); err != nil {
			slog.Warn("[uninstall] 端末のテナントを引けませんでした（今回は送出せず継続）",
				"agent", agentID, "error", err)
			return nil
		}
		if tenantID == "" {
			return nil
		}
		// 引いたテナントを ctx に載せます。**載せないと PrepareConn は
		// `app.tenant_id` を張りません。** uninstall_guards の RLS からは
		// 「未設定なら全テナント可」の抜け道を落としたので (migration 446)、
		// 張らないままだとこの取得は 0 件になります。
		ctx = context.WithValue(ctx, store.TenantContextKey{}, tenantID)
		g, err := guardStore.GetGuard(ctx, tenantID)
		if errors.Is(err, store.ErrNoUninstallGuard) {
			// パスワード未設定。送るものが無いだけで、異常ではない。
			return nil
		}
		if err != nil {
			// **「設定が無い」と「引けなかった」を同じ nil に潰さない。**
			// 送出しないのは同じだが、こちらは記録が要る。端末は手持ちの
			// 設定を保持するので、保護が外れることはない。
			slog.Warn("[uninstall] 保護設定を引けませんでした（今回は送出せず継続）",
				"agent", agentID, "error", err)
			return nil
		}
		return map[string]any{
			"version":    g.Version,
			"algorithm":  g.Algorithm,
			"iterations": g.Iterations,
			"salt":       g.SaltB64,
			"digest":     g.DigestB64,
			"updated_at": g.UpdatedAt,
		}
	})

	addr := ":" + grpcPort

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("シャットダウン中...")
		cancel()
	}()

	// Metrics HTTP server on :8082
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", metrics.Handler())
		// Liveness (process alive) vs readiness (DB + NATS reachable). /health stays
		// a liveness alias for backward compatibility with existing healthchecks.
		mux.HandleFunc("/health", health.LivenessHandler())
		mux.HandleFunc("/healthz", health.LivenessHandler())
		mux.HandleFunc("/readyz", health.ReadinessHandler(db.Pool(), nc))
		metricsPort := getEnv("METRICS_PORT", "8082")
		// ListenAndServe のままだと読み取りに時間制限が無く、ヘッダを少しずつ
		// 送り続けるだけで接続を占有できる (Slowloris)。
		srv := &http.Server{
			Addr:              ":" + metricsPort,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
			slog.Warn("メトリクスサーバーエラー", "error", err)
		}
	}()

	slog.Info("gRPC Ingestionサーバーを起動中", "addr", addr)
	if err := server.ListenAndServe(ctx, addr); err != nil {
		slog.Error("Ingestionサーバーエラー", "error", err)
		os.Exit(1)
	}
}

// startNATSCommandBridge subscribes to command subjects published by the API
// server and relays them into the in-memory dispatcher so the gRPC streaming
// handler can deliver them to the connected agent.
//
// Uses JetStream durable push consumer so commands published while this server
// was down are re-delivered on restart. Falls back to plain NATS if JetStream
// is unavailable.
func startNATSCommandBridge(nc *nats.Conn, d *ingestion.InMemoryCommandDispatcher) {
	relay := func(subject string, data []byte) {
		type cmdPayload struct {
			AgentID string `json:"agent_id"`
			// CommandID は API 側が採番した response_actions.id。
			// これをそのまま ServerCommand.command_id として使うことで、
			// エージェントが返す ack を監査記録の行に対応付けられる。
			// 空なら従来どおりディスパッチャが採番する（自動対応の経路）。
			CommandID string   `json:"command_id"`
			Reason    string   `json:"reason"`
			AlertID   string   `json:"alert_id"`
			PID       uint32   `json:"pid"`
			Path      string   `json:"path"`
			AllowIPs  []string `json:"allow_ips"`
		}

		// Subject format: commands.{agentID}.{type}
		parts := strings.SplitN(subject, ".", 3)
		if len(parts) != 3 {
			return
		}
		agentID := parts[1]
		cmdType := parts[2]

		var p cmdPayload
		_ = json.Unmarshal(data, &p)

		var err error
		switch cmdType {
		case "isolate":
			err = d.EnqueueIsolate(agentID, p.Reason, p.AlertID, p.AllowIPs, p.CommandID)
		case "unisolate":
			payload, _ := json.Marshal(map[string]interface{}{"reason": p.Reason})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "unisolate",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "kill_process":
			payload, _ := json.Marshal(map[string]interface{}{"pid": p.PID, "reason": p.Reason})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "kill_process",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "quarantine_file":
			payload, _ := json.Marshal(map[string]interface{}{"path": p.Path, "alert_id": p.AlertID})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "quarantine_file",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "restore_file":
			var rp struct {
				QuarantineID string `json:"quarantine_id"`
				RestorePath  string `json:"restore_path"`
			}
			_ = json.Unmarshal(data, &rp)
			payload, _ := json.Marshal(map[string]interface{}{"quarantine_id": rp.QuarantineID, "restore_path": rp.RestorePath})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "restore_file",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "scan":
			var sp struct {
				ScanType string `json:"scan_type"`
				Target   string `json:"target"`
			}
			_ = json.Unmarshal(data, &sp)
			if sp.ScanType == "" {
				sp.ScanType = "full"
			}
			payload, _ := json.Marshal(map[string]interface{}{"scan_type": sp.ScanType, "target": sp.Target})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "scan",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "cert_renew":
			var rp struct {
				RenewalToken string `json:"renewal_token"`
			}
			_ = json.Unmarshal(data, &rp)
			payload, _ := json.Marshal(map[string]interface{}{
				"type":          "cert_renew",
				"renewal_token": rp.RenewalToken,
			})
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "cert_renew",
				Payload:  payload,
				IssuedAt: time.Now(),
			})
		case "live_response_start":
			// Forward the raw payload ({"type":"live_response","session_id":...,
			// "token":...,"callback_url":...}); commandToProto carries it to the
			// agent as a CollectArtifact(type=LOGS) command. Without this case the
			// bridge silently dropped live-response starts and commands stayed
			// pending forever (no command ever reached the agent).
			err = d.Enqueue(agentID, &ingestion.Command{
				ID:       "nats-" + subject,
				Type:     "live_response_start",
				Payload:  data,
				IssuedAt: time.Now(),
			})
		}
		if err != nil {
			slog.Warn("NATS bridge: enqueue failed", "subject", subject, "error", err)
		} else {
			slog.Info("NATS bridge: relayed command", "agent", agentID, "type", cmdType)
		}
	}

	// Attempt JetStream durable push consumer first.
	// The COMMANDS stream (subjects: commands.>) is created by EnsureStreams.
	// Using Durable + AckExplicit means commands survive ingestion server restarts:
	// unacked messages are re-delivered when the consumer reconnects.
	js, err := nc.JetStream()
	if err == nil {
		_, subErr := js.Subscribe("commands.>",
			func(msg *nats.Msg) {
				relay(msg.Subject, msg.Data)
				if ackErr := msg.Ack(); ackErr != nil {
					slog.Warn("NATS JetStream ACK失敗", "subject", msg.Subject, "error", ackErr)
				}
			},
			nats.Durable("ingestion-bridge"),
			nats.AckExplicit(),
			nats.DeliverAll(),
		)
		if subErr == nil {
			slog.Info("NATS JetStream command bridge 起動 (durable=ingestion-bridge)")
			return
		}
		slog.Warn("JetStream subscribe失敗 — プレーンNATSへフォールバック", "error", subErr)
	} else {
		slog.Warn("JetStream利用不可 — プレーンNATSへフォールバック", "error", err)
	}

	// Fallback: plain NATS subscriptions (volatile — commands lost on restart).
	subjects := []string{
		"commands.*.isolate",
		"commands.*.unisolate",
		"commands.*.kill_process",
		"commands.*.quarantine_file",
		"commands.*.restore_file",
		"commands.*.scan",
		"commands.*.cert_renew",
		"commands.*.live_response_start",
	}
	for _, subj := range subjects {
		subj := subj
		if _, err := nc.Subscribe(subj, func(msg *nats.Msg) {
			relay(msg.Subject, msg.Data)
		}); err != nil {
			slog.Warn("NATS bridge: subscribe failed", "subject", subj, "error", err)
		}
	}
	slog.Info("NATS command bridge 起動 (プレーンNATS fallback)")
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
