// Package ingestion implements the gRPC ingestion service.
// Agents connect here to stream events and receive server commands.
package ingestion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// keepalivePingID is the command_id stamped on the downstream keepalive frame the
// EventStream loop sends every tick. The frame carries no command oneof, so the
// agent treats it as liveness-only (convertServerCommand returns nil) and runs its
// receive watchdog off it. It is cosmetic on the wire — the agent discriminates a
// keepalive by the absent oneof, not this string — but makes pcaps/logs legible.
const keepalivePingID = "__edr_keepalive__"

// Server implements the gRPC IngestionService.
// It embeds UnimplementedIngestionServiceServer for forward compatibility.
type Server struct {
	v1.UnimplementedIngestionServiceServer
	store     AgentStore
	pool      *pgxpool.Pool // for writing events to the events table
	nats      *nats.Conn
	js        nats.JetStreamContext // JetStream for persistent event publishing
	commander CommandDispatcher
	tlsCreds  credentials.TransportCredentials

	// hostname cache: agentID → hostname (populated on Enroll/EventStream)
	hostnames sync.Map

	// shutdown is closed by ListenAndServe when the server is stopping, so
	// long-lived EventStream handlers return promptly and GracefulStop can drain.
	shutdown chan struct{}

	// uninstallGuard supplies the tenant's uninstall-password material for the
	// heartbeat reply, or nil when none is configured.
	//
	// **HTTP だけに載せると、この機能は本番では動きません。**
	// `FallbackSender` は gRPC を先に試すので、gRPC が生きている通常時
	// （つまりほぼ全ての端末）に HTTP の応答は使われません。保護設定は
	// 「必要になる前に端末に置いてある」ことが前提で、アンインストールの
	// 検証は通信が切れた状態でも走ります —— そのとき取りに行く機会は
	// ありません。両方の経路で運びます（transport_parity_test.go）。
	uninstallGuard func(ctx context.Context, agentID string) map[string]any

	// isolationAllowIPs は隔離中も到達させるアドレス（ISOLATION_ALLOW_IPS）。
	//
	// **これが空だと、隔離された端末から届くのは EDR サーバとループバックだけ。**
	// DNS も DC も踏み台も切れる。それが隔離の意図ではある一方、proto の
	// allow_ips は最初から "additional IPs to allow (override)" として存在し、
	// **誰も詰めていなかった**ため、運用側に踏み台を残す手段が無かった。
	//
	// 送出時に載せる。コマンドの payload ではなく配備の性質（どのセグメントを
	// 生かすか）なので、投入経路ごとに書かせると必ず書き忘れた経路ができる。
	isolationAllowIPs []string
}

// SetUninstallGuardProvider wires the uninstall-password material into the gRPC
// heartbeat reply. A func rather than a store handle so this package keeps no
// dependency on uninstall protection and stays constructible without it.
func (s *Server) SetUninstallGuardProvider(f func(ctx context.Context, agentID string) map[string]any) {
	s.uninstallGuard = f
}

// SetIsolationAllowIPs sets the addresses that stay reachable while isolated.
// Entries are single IPv4 addresses or CIDR blocks; see ParseAllowIPs.
func (s *Server) SetIsolationAllowIPs(ips []string) { s.isolationAllowIPs = ips }

// gracefulStopTimeout bounds how long a shutdown waits for in-flight RPCs to drain
// before forcing a stop, so a stuck stream can't block the whole shutdown past the
// orchestrator's termination grace period.
const gracefulStopTimeout = 15 * time.Second

// AgentStore handles agent database operations.
type AgentStore interface {
	UpsertAgent(ctx context.Context, agent *AgentRecord) error
	UpdateLastSeen(ctx context.Context, agentID, hostname string, ips []string, agentVersion, osVersion, osType string) error
	UpdateProtectionMode(ctx context.Context, agentID, mode string) error
	UpdateTelemetryMode(ctx context.Context, agentID, mode, detail string) error
	UpdateMetrics(ctx context.Context, agentID string, cpuUsage, memoryUsageMB, totalMemoryMB *float64) error
	ResolveAgentOfflineAlerts(ctx context.Context, agentID string) error
	GetAgentByID(ctx context.Context, id string) (*AgentRecord, error)
	SignCSR(ctx context.Context, enrollToken, agentID, csr string) (signedCert, caCert string, err error)
	UpdateCertExpiry(ctx context.Context, agentID string, notAfter time.Time) error
}

// AgentRecord mirrors the agents table.
type AgentRecord struct {
	ID            string
	Hostname      string
	OSType        string
	OSVersion     string
	AgentVersion  string
	IPAddresses   []string
	Status        string
	LastSeen      time.Time
	ConfigVersion int
	TLSThumbprint string
}

// CommandDispatcher enqueues commands for delivery to agents.
type CommandDispatcher interface {
	Enqueue(agentID string, cmd *Command) error
	Dequeue(agentID string) ([]*Command, error)
}

type Command struct {
	ID       string
	Type     string
	Payload  json.RawMessage
	IssuedAt time.Time
}

func NewServer(store AgentStore, pool *pgxpool.Pool, nc *nats.Conn, commander CommandDispatcher, creds credentials.TransportCredentials) *Server {
	// Upgrade NATS connection to JetStream for persistent, at-least-once delivery.
	// If JetStream is unavailable, we fall back to plain NATS publish.
	js, err := nc.JetStream()
	if err != nil {
		slog.Warn("JetStreamの初期化に失敗しました。通常のNATS publishにフォールバックします", "error", err)
	}

	s := &Server{
		store:     store,
		pool:      pool,
		nats:      nc,
		js:        js,
		commander: commander,
		tlsCreds:  creds,
		shutdown:  make(chan struct{}),
	}

	// Note: NATS command subscriptions are handled by the ingestion server's
	// main.go via type-specific subjects (commands.*.isolate, etc.) to avoid
	// duplicate delivery from a generic commands.> subscription.

	return s
}

// ListenAndServe starts the gRPC server and registers the IngestionService. On
// ctx cancellation (SIGTERM) it drains gracefully: new RPCs are refused, in-flight
// unary RPCs finish, and long-lived EventStream handlers return promptly (they
// watch s.shutdown), so a rolling deploy no longer SIGKILLs the process mid-stream
// and drops received-but-unpersisted events. A forced Stop bounds the wait.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	opts := []grpc.ServerOption{
		grpc.Creds(s.tlsCreds),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(8 * 1024 * 1024),
	}

	srv := grpc.NewServer(opts...)
	v1.RegisterIngestionServiceServer(srv, s)

	go func() {
		<-ctx.Done()
		slog.Info("gRPC ingestion server をグレースフルに停止します")
		close(s.shutdown) // signal EventStream handlers to return
		stopped := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			slog.Warn("グレースフル停止がタイムアウトしました。強制停止します", "timeout", gracefulStopTimeout)
			srv.Stop()
		}
	}()

	slog.Info("gRPC ingestion server 起動", "addr", addr)
	if err := srv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
		return err
	}
	return nil
}

// ─── gRPC method implementations ──────────────────────────────

// EventStream is the main bidirectional streaming RPC.
// Agents send event batches up; the server sends commands down.
// errNonUUIDAgentID is returned to an agent whose identifier cannot be stored.
//
// agents.id and events.agent_id are uuid columns, so a non-UUID identifier
// fails at INSERT with SQLSTATE 22P02 — but only after the batch has been
// published to NATS. Detection then evaluates the events and raises alerts for
// an endpoint whose telemetry is discarded and which never appears in the
// console, because its registration failed the same way.
//
// A verification host ran like that for four days: 636,051 error lines, every
// event dropped, "Suspicious Read of /etc/shadow" firing every minute and
// failing to save every minute, and nothing in the endpoint list to explain
// any of it. The console showed a fleet that did not include it.
//
// Rejecting at the edge cannot break a working deployment: an identifier that
// is not a UUID has never been storable, so anything sending one is already
// wholly non-functional. It only changes silent loss into an error the agent
// can log and an operator can act on.
func validAgentID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// rejectNonUUIDAgentID builds the gRPC error, naming the offending value so the
// fix (edit the agent's config id) is obvious from a single line.
//
// It deliberately does not emit a metric or a log of its own. This is a
// per-request client error, not a component failure: metrics.BackgroundFailed
// answers "did this background worker break", and the honest answer here is no
// — the server is working exactly as intended and the caller is being told so.
//
// Nor does it log. Heartbeat and GetConfig arrive on an interval, so a line per
// rejection reproduces the very flood this change exists to stop: the incident
// that prompted it was 636,051 log lines from one misconfigured agent. The
// rejection is returned to the caller, which is where it can be acted on.
// EventStream logs once per connection attempt (see below) because that is
// bounded by reconnects rather than by a timer.
func rejectNonUUIDAgentID(agentID string) error {
	return status.Errorf(codes.InvalidArgument,
		"agent ID %q is not a UUID; events and registration for it cannot be stored "+
			"(agents.id and events.agent_id are uuid columns). Set a UUID as the agent's id.",
		agentID)
}

func (s *Server) EventStream(stream v1.IngestionService_EventStreamServer) error {
	agentID := extractAgentIDFromCert(stream.Context())
	if agentID == "" {
		return status.Error(codes.Unauthenticated, "agent ID not found in certificate CN")
	}
	if !validAgentID(agentID) {
		// Once per connection attempt, not per event: enough for an operator to
		// find the offending host, without the per-interval flood.
		slog.Warn("エージェントIDがUUIDではないため接続を拒否しました",
			"agent_id", agentID,
			"hint", "エージェントの config の id を UUID にしてください")
		return rejectNonUUIDAgentID(agentID)
	}

	// Populate hostname cache from DB if not already known
	if _, ok := s.hostnames.Load(agentID); !ok {
		if rec, err := s.store.GetAgentByID(stream.Context(), agentID); err == nil {
			s.hostnames.Store(agentID, rec.Hostname)
		}
	}

	slog.Info("エージェントが接続しました", "agent", agentID)

	// done is closed when the receive goroutine exits
	done := make(chan error, 1)

	// Goroutine: receive event batches from the agent
	go func() {
		for {
			batch, err := stream.Recv()
			if err == io.EOF {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
			// Persist with a context detached from the stream so a batch that has
			// already been received is fully written even if the stream is torn
			// down (client disconnect or server shutdown) mid-persist.
			s.publishEventBatch(context.WithoutCancel(stream.Context()), agentID, batch)
		}
	}()

	// Main loop: poll for commands to push down to the agent
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				slog.Warn("イベントストリームが切断されました", "agent", agentID, "error", err)
			} else {
				slog.Info("エージェントが切断しました", "agent", agentID)
			}
			return err

		case <-stream.Context().Done():
			slog.Info("ストリームコンテキストがキャンセルされました", "agent", agentID)
			return nil

		case <-s.shutdown:
			// Server is shutting down (SIGTERM). Return so GracefulStop can drain;
			// the in-flight batch, if any, persists via the detached context above.
			slog.Info("サーバー停止中、エージェントストリームを閉じます", "agent", agentID)
			return nil

		case <-ticker.C:
			cmds, err := s.commander.Dequeue(agentID)
			if err == nil {
				for _, cmd := range cmds {
					protoCmd := commandToProto(cmd, s.isolationAllowIPs)
					if protoCmd == nil {
						continue
					}
					if err := stream.Send(protoCmd); err != nil {
						slog.Warn("コマンド送信に失敗しました", "agent", agentID, "error", err)
						return err
					}
					slog.Info("コマンドを送信しました", "agent", agentID, "type", cmd.Type)
				}
			}

			// Keepalive ping every tick, even when there are no commands. This gives
			// the agent's receive watchdog (see agent grpc_client.go runRecvWatchdog)
			// a positive liveness signal so it can distinguish a half-open downstream
			// from a merely idle one, and lets the server probe the downstream every
			// 5s — without it, a half-open stream stays invisible here until the next
			// (rare) real command. A keepalive carries no command oneof, so the agent
			// treats it as liveness-only and executes nothing.
			if err := stream.Send(&v1.ServerCommand{CommandId: keepalivePingID}); err != nil {
				slog.Warn("キープアライブ送信に失敗しました — ストリーム切断", "agent", agentID, "error", err)
				return err
			}
		}
	}
}

// Enroll registers a new agent and issues a signed client certificate.
func (s *Server) Enroll(ctx context.Context, req *v1.EnrollRequest) (*v1.EnrollResponse, error) {
	slog.Info("新しいエージェントを登録中",
		"hostname", req.GetHostname(),
		"os", req.GetOsType(),
	)

	agentID := generateID()

	// Sign the CSR using the server CA
	signedCert, caCert, err := s.store.SignCSR(ctx, req.GetEnrollmentToken(), agentID, req.GetCsr())
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "CSRの署名に失敗しました: %v", err)
	}

	// Save agent to database
	agent := &AgentRecord{
		ID:           agentID,
		Hostname:     req.GetHostname(),
		OSType:       req.GetOsType(),
		OSVersion:    req.GetOsVersion(),
		AgentVersion: req.GetAgentVersion(),
		IPAddresses:  req.GetIpAddresses(),
		Status:       "online",
		LastSeen:     time.Now(),
	}

	if err := s.store.UpsertAgent(ctx, agent); err != nil {
		return nil, status.Errorf(codes.Internal, "エージェントの保存に失敗しました: %v", err)
	}

	// Parse the signed cert to extract NotAfter and persist it so the cert
	// renewer scheduler can detect approaching expiry.
	if notAfter, parseErr := parseCertNotAfter(signedCert); parseErr == nil {
		if dbErr := s.store.UpdateCertExpiry(ctx, agentID, notAfter); dbErr != nil {
			slog.Warn("cert_not_afterの保存に失敗しました", "agent_id", agentID, "error", dbErr)
		}
	}

	// Cache hostname for event enrichment
	s.hostnames.Store(agentID, req.GetHostname())

	slog.Info("エージェントの登録が完了しました", "agent_id", agentID, "hostname", req.GetHostname())

	return &v1.EnrollResponse{
		AgentId:    agentID,
		SignedCert: signedCert,
		CaCert:     caCert,
	}, nil
}

// parseCertNotAfter decodes a PEM certificate and returns its NotAfter time.
func parseCertNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("PEMデコード失敗")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// Heartbeat processes agent health reports.
func (s *Server) Heartbeat(ctx context.Context, req *v1.HeartbeatRequest) (*v1.HeartbeatResponse, error) {
	agentID := req.GetAgentId()
	if !validAgentID(agentID) {
		return nil, rejectNonUUIDAgentID(agentID)
	}

	// Advertise EventStream keepalive support on this unary reply. Heartbeat lands
	// even when the bidi stream is half-open, so this is how the agent learns to arm
	// its receive watchdog from stream-open and detect a downstream that is half-open
	// from birth (see agent runRecvWatchdog). Best-effort: a send-header failure is
	// non-fatal to the heartbeat itself.
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-edr-keepalive", "1"))

	// Prefer hostname from heartbeat; fall back to cache populated by Enroll/EventStream.
	hostname := req.GetHostname()
	if hostname == "" {
		if v, ok := s.hostnames.Load(agentID); ok {
			hostname, _ = v.(string)
		}
	} else {
		// Cache the real hostname for event enrichment
		s.hostnames.Store(agentID, hostname)
	}

	// Read os_version and os_type from proto fields or gRPC metadata headers.
	osVersion := req.GetOsVersion()
	osType := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if osVersion == "" {
			if vals := md.Get("x-os-version"); len(vals) > 0 {
				osVersion = vals[0]
			}
		}
		if vals := md.Get("x-os-type"); len(vals) > 0 {
			osType = vals[0]
		}
	}

	// Protection mode (enforce/observe/poll) and effective telemetry mode
	// (ebpf/poll/off) arrive as gRPC metadata to avoid a proto regen (same pattern
	// as x-os-version).
	protectionMode := ""
	telemetryMode := ""
	telemetryDetail := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-protection-mode"); len(vals) > 0 {
			protectionMode = vals[0]
		}
		if vals := md.Get("x-telemetry-mode"); len(vals) > 0 {
			telemetryMode = vals[0]
		}
		if vals := md.Get("x-telemetry-detail"); len(vals) > 0 {
			telemetryDetail = vals[0]
		}
	}

	// **隔離状態の突き合わせは、この経路には無いままでした。**
	//
	// HTTP のハートビートは `should_unisolate` を返しますが、`FallbackSender`
	// は gRPC を先に試すので、**gRPC が生きている通常時、その指示は端末に
	// 届きません。** 直る条件（gRPC が落ちている）と直らない条件
	// （gRPC は生きていて指示だけが落ちた）が入れ替わっていました。
	//
	// proto を増やさずに済む形（`x-edr-keepalive` と同じ）で、応答の
	// メタデータに載せます。**DB が唯一の真実**で、指示の送信は速い経路、
	// 届かなければ次のハートビートが直します。
	if agent, aerr := s.store.GetAgentByID(ctx, agentID); aerr == nil {
		reported := "online"
		if req.GetStatus() == v1.HeartbeatRequest_AGENT_STATUS_ISOLATED {
			reported = "isolated"
		}
		for _, h := range isolationHeaders(agent.Status, reported) {
			_ = grpc.SetHeader(ctx, metadata.Pairs(h, "1"))
		}
	}

	// UninstallGuard も同じ経路で運ぶ。構造体なので JSON にして 1 ヘッダに
	// 載せる（`x-edr-keepalive` / `x-edr-should-isolate` と同じく proto を
	// 増やさずに済ませる）。送れなかった回は何も載せない —— 端末は手持ちの
	// 設定をそのまま保持するので、古い設定が消えることはない。
	if s.uninstallGuard != nil {
		if guard := s.uninstallGuard(ctx, agentID); guard != nil {
			if b, err := json.Marshal(guard); err != nil {
				slog.Warn("[uninstall] 保護設定を応答に載せられませんでした", "agent", agentID, "error", err)
			} else {
				_ = grpc.SetHeader(ctx, metadata.Pairs("x-edr-uninstall-guard", string(b)))
			}
		}
	}

	if err := s.store.UpdateLastSeen(ctx, agentID, hostname, req.GetIpAddresses(), req.GetAgentVersion(), osVersion, osType); err != nil {
		slog.Warn("ハートビート更新失敗", "agent", agentID, "error", err)
	} else {
		// Agent is back online — resolve any open offline alerts
		if err := s.store.ResolveAgentOfflineAlerts(ctx, agentID); err != nil {
			slog.Warn("オフラインアラートの自動解決に失敗", "agent", agentID, "error", err)
		}
	}

	// Record the reported kernel-protection tier (best-effort; non-fatal).
	if err := s.store.UpdateProtectionMode(ctx, agentID, protectionMode); err != nil {
		slog.Warn("保護モード更新失敗", "agent", agentID, "error", err)
	}

	// Record the effective collection mechanism (best-effort; non-fatal). Kept
	// separate from the protection tier so a capable-but-degraded endpoint —
	// eBPF-capable host silently running /proc polling — is visible in the fleet.
	if err := s.store.UpdateTelemetryMode(ctx, agentID, telemetryMode, telemetryDetail); err != nil {
		slog.Warn("テレメトリモード更新失敗", "agent", agentID, "error", err)
	}

	// Persist reported CPU/memory usage for the fleet health alerter
	// (best-effort; non-fatal).
	// req.CpuUsage は optional です。**送られていなければ測れていない**ので、
	// nil をそのまま渡して列を NULL のままにします。GetCpuUsage() を使うと
	// 未測定が 0（＝アイドル）に化けます。
	if err := s.store.UpdateMetrics(ctx, agentID,
		req.CpuUsage, req.MemoryUsageMb, req.TotalMemoryMb); err != nil {
		slog.Warn("メトリクス更新失敗", "agent", agentID, "error", err)
	}

	// Pending commands are delivered exclusively via the EventStream RPC's
	// 5-second ticker (see EventStream above). The agent's heartbeat handler
	// only logs PendingCommandCount and does not execute the command bodies,
	// so dequeuing here would silently drop commands. Leave the queue intact
	// so EventStream picks them up and pushes them to the agent.
	return &v1.HeartbeatResponse{}, nil
}

// GetConfig returns the current agent configuration.
func (s *Server) GetConfig(ctx context.Context, req *v1.ConfigRequest) (*v1.AgentConfig, error) {
	if !validAgentID(req.GetAgentId()) {
		return nil, rejectNonUUIDAgentID(req.GetAgentId())
	}
	// Return default collection config; per-agent policies can be added later
	return &v1.AgentConfig{
		Version: 1,
		Collection: &v1.CollectionConfig{
			EventBatchIntervalMs: 500,
		},
	}, nil
}

// ─── Event publishing ─────────────────────────────────────────

const insertEventSQL = `INSERT INTO events (time, agent_id, event_type, raw_data, event_id)
	VALUES ($1, $2::uuid, $3, $4::jsonb, $5::uuid)`

// eventInsertChunk bounds how many events go into one multi-row INSERT. A batch is
// normally tens–hundreds of events; the cap keeps the statement well under the
// PostgreSQL 65535-parameter limit (4 params/row) even for pathologically large
// batches.
const eventInsertChunk = 500

// preppedEvent is one event resolved for persistence + publishing. promoteEventType
// and normalizeEventData are computed once here rather than twice (DB + NATS).
type preppedEvent struct {
	evtType string
	evtTime time.Time
	raw     []byte
	evt     *v1.Event
	idx     int
	// eventID is the row's events.event_id, minted here rather than left to the
	// column DEFAULT so the SAME id can travel on the NATS envelope. Without it
	// the stored row and the published event have no shared identifier, and an
	// alert can never be traced back to the evidence that produced it — see
	// docs/死蔵経路の全数棚卸し_20260810.md §8.
	eventID string
}

// publishEventBatch persists all events in a batch to the DB and publishes them to
// NATS JetStream. DB writes use a single multi-row INSERT per chunk instead of one
// round-trip per event: a burst of ETW/eBPF events would otherwise serialize into N
// sequential INSERT round-trips, throttling ingestion and stressing the pool.
func (s *Server) publishEventBatch(ctx context.Context, agentID string, batch *v1.EventBatch) {
	// コマンドの実行結果は、イベント送信に相乗りしてくる。イベントが 0 件でも
	// ack だけの batch が来るので、events より先に処理する。
	s.applyCommandAcks(ctx, agentID, batch.GetAcks())

	platform := platformString(batch.GetPlatform())

	// Resolve every event once (type + timestamp + payload), dropping unresolvable
	// types. Both the DB write and the NATS publish reuse this.
	events := batch.GetEvents()
	prepped := make([]preppedEvent, 0, len(events))
	for i, evt := range events {
		evtType := promoteEventType(evt)
		if evtType == "" {
			continue
		}
		evtTime := evt.GetTimestamp().AsTime()
		if evtTime.IsZero() {
			evtTime = time.Now()
		}
		prepped = append(prepped, preppedEvent{
			evtType: evtType,
			evtTime: evtTime,
			raw:     normalizeEventData(evt),
			evt:     evt,
			idx:     i,
			eventID: uuid.NewString(),
		})
	}

	// Persist first so DB storage is never skipped by a NATS serialization failure.
	if s.pool != nil {
		s.insertEvents(ctx, agentID, prepped)
		s.insertDeviceEvents(ctx, agentID, prepped)
	}

	if s.nats == nil {
		return
	}
	for _, p := range prepped {
		data, err := s.marshalEventPayload(agentID, platform, p.evtType, p.eventID, p.evt)
		if err != nil {
			metrics.BackgroundFailed("event_publish", err, "イベントペイロードのシリアライズに失敗しました", "agent", agentID, "type", p.evtType)
			continue
		}
		// Topic: events.<agentID>.<type>  (detection engine subscribes to events.>)
		topic := fmt.Sprintf("events.%s.%s", agentID, p.evtType)
		// Msg-ID: deduplicates retransmitted events within the JetStream duplicate window.
		msgID := eventMsgID(agentID, p.evtType, p.evt, p.idx)
		s.publishEvent(topic, data, msgID)
	}
}

// eventMsgID derives the JetStream de-duplication key for an event. It must be:
//   - STABLE across retransmission of the same event (agents replay their ring
//     buffer on reconnect), so genuine retries ARE deduped within the window; and
//   - DISTINCT for two different events even at the same wall-clock second.
//
// The previous key ("agentID-evtType-second-idx") violated the second property:
// collectors that emit several events in the same second, each as its OWN
// single-event batch (idx=0), produced identical keys — so JetStream silently
// dropped all but the first, and those events reached storage (events table) but
// never the detection engine. Observed live (2026-07): the FIM SHA-256 poller
// emits multiple file events per scan at the same second (authorized_keys,
// .bashrc, /etc/ld.so.preload, …), and the ETW remote-thread sensor emits two
// events ~1ms apart — in both cases the extras were deduped away, silently killing
// the whole class of FIM-poller-based file_event detections.
//
// Folding the event's own Id (which agents make unique per event — a uuid, or the
// "fim_change:<uuid>:<json>" / "memory:<uuid>:…" encoded forms) into a content
// hash fixes the collision while keeping the key identical for a verbatim
// retransmission of the same *v1.Event.
func eventMsgID(agentID, evtType string, evt *v1.Event, idx int) string {
	if id := evt.GetId(); id != "" {
		sum := sha256.Sum256([]byte(agentID + "\x00" + evtType + "\x00" + id))
		return fmt.Sprintf("%s-%s-%x", agentID, evtType, sum[:8])
	}
	// No event Id — fall back to the legacy key. Multi-event batches assign each
	// event a genuinely distinct idx, so this path has no known collision.
	return fmt.Sprintf("%s-%s-%d-%d", agentID, evtType, evt.GetTimestamp().GetSeconds(), idx)
}

// insertEvents writes events to the DB with a single multi-row INSERT per chunk. A
// multi-row INSERT is a single atomic statement — on failure nothing in the chunk
// is written — so on error it falls back to per-event inserts, isolating a poison
// event (e.g. an event_type not yet in the events CHECK constraint) to itself
// instead of dropping the whole chunk (matching the old per-event behavior).
func (s *Server) insertEvents(ctx context.Context, agentID string, prepped []preppedEvent) {
	for start := 0; start < len(prepped); start += eventInsertChunk {
		end := start + eventInsertChunk
		if end > len(prepped) {
			end = len(prepped)
		}
		chunk := prepped[start:end]
		if err := s.insertEventsChunk(ctx, agentID, chunk); err != nil {
			slog.Warn("イベントの一括挿入に失敗、個別挿入にフォールバックします",
				"agent", agentID, "count", len(chunk), "error", err)
			for _, p := range chunk {
				if _, e := s.pool.Exec(ctx, insertEventSQL, p.evtTime, agentID, p.evtType, p.raw, p.eventID); e != nil {
					slog.Warn("イベントのDB保存に失敗しました", "agent", agentID, "type", p.evtType, "error", e)
				}
			}
		}
	}
}

// deviceEventRow is one parsed "device_event:" envelope, ready for the
// device_events side table.
type deviceEventRow struct {
	evtTime    time.Time
	action     string
	deviceID   string
	deviceName string
	deviceType string
	vendorID   string
	productID  string
	raw        []byte
}

// deviceEventActions are the only values the device_events.action CHECK
// constraint accepts. Anything else is dropped before it reaches the DB: a
// rejected row would fail the whole multi-row statement, so filtering here keeps
// one odd agent payload from taking the batch's other rows down with it.
var deviceEventActions = map[string]bool{"connected": true, "disconnected": true}

// parseDeviceEvent decodes the inner JSON of a "device_event:" envelope
// ({action, device_id, name, vendor_id, product_id, type}) into a row. ok is
// false when the payload cannot satisfy the table's NOT NULL / CHECK constraints,
// so the caller can skip it rather than let the insert fail.
//
// Pure (no I/O) so the field mapping — the agent's "name"/"type" become
// device_name/device_type — is unit-tested directly.
func parseDeviceEvent(raw []byte, evtTime time.Time) (deviceEventRow, bool) {
	var p struct {
		Action    string `json:"action"`
		DeviceID  string `json:"device_id"`
		Name      string `json:"name"`
		VendorID  string `json:"vendor_id"`
		ProductID string `json:"product_id"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return deviceEventRow{}, false
	}
	if !deviceEventActions[p.Action] || p.DeviceID == "" {
		return deviceEventRow{}, false
	}
	return deviceEventRow{
		evtTime:    evtTime,
		action:     p.Action,
		deviceID:   p.DeviceID,
		deviceName: p.Name,
		deviceType: p.Type,
		vendorID:   p.VendorID,
		productID:  p.ProductID,
		raw:        raw,
	}, true
}

const insertDeviceEventSQL = `INSERT INTO device_events
    (agent_id, action, device_id, device_name, device_type, vendor_id, product_id, raw_data, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`

// insertDeviceEvents mirrors removable-device events into the device_events side
// table, which the XDR engine correlates as endpoint activity and the device API
// serves. Detection already fires on these events (they reach the rules through
// the normal events path); this fills the table that was created for them but
// never written to, so the XDR endpoint dimension was always empty.
//
// Cheap by construction: the loop only allocates when a batch actually carries a
// device_event, which is a plug/unplug — rare next to process/file/network
// telemetry. A failure here is logged and swallowed: the events table and the
// detection path have already succeeded, and losing a correlation row must not
// fail the ingest of the batch.
//
// created_at is the event's own timestamp rather than the column default: agents
// replay their ring buffer after a reconnect, and stamping those with NOW() would
// place a USB insertion at the wrong time in the XDR timeline.
func (s *Server) insertDeviceEvents(ctx context.Context, agentID string, prepped []preppedEvent) {
	var rows []deviceEventRow
	for _, p := range prepped {
		if p.evtType != "device_event" {
			continue
		}
		if row, ok := parseDeviceEvent(p.raw, p.evtTime); ok {
			rows = append(rows, row)
		} else {
			slog.Warn("device_event のペイロードが不正なため device_events への保存をスキップします",
				"agent", agentID)
		}
	}
	for _, r := range rows {
		if _, err := s.pool.Exec(ctx, insertDeviceEventSQL,
			agentID, r.action, r.deviceID,
			nullIfEmpty(r.deviceName), nullIfEmpty(r.deviceType),
			nullIfEmpty(r.vendorID), nullIfEmpty(r.productID),
			r.raw, r.evtTime,
		); err != nil {
			slog.Warn("device_events への保存に失敗しました",
				"agent", agentID, "device", r.deviceID, "error", err)
		}
	}
}

// nullIfEmpty stores NULL rather than "" for absent optional device attributes,
// so consumers can distinguish "not reported" from "reported as empty".
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// insertEventsChunk executes one multi-row INSERT for chunk.
func (s *Server) insertEventsChunk(ctx context.Context, agentID string, chunk []preppedEvent) error {
	if len(chunk) == 0 {
		return nil
	}
	query, args := buildEventsInsert(agentID, chunk)
	_, err := s.pool.Exec(ctx, query, args...)
	return err
}

// buildEventsInsert builds a multi-row INSERT for chunk. Parameter binding is
// identical to the single-row path ($N, $N::uuid, $N, $N::jsonb) so pgx encodes
// each value exactly as before. Pure (no I/O) so it is unit-tested directly.
func buildEventsInsert(agentID string, chunk []preppedEvent) (string, []any) {
	var sb strings.Builder
	sb.WriteString("INSERT INTO events (time, agent_id, event_type, raw_data, event_id) VALUES ")
	args := make([]any, 0, len(chunk)*5)
	for i, p := range chunk {
		if i > 0 {
			sb.WriteByte(',')
		}
		n := i * 5
		fmt.Fprintf(&sb, "($%d, $%d::uuid, $%d, $%d::jsonb, $%d::uuid)", n+1, n+2, n+3, n+4, n+5)
		args = append(args, p.evtTime, agentID, p.evtType, p.raw, p.eventID)
	}
	return sb.String(), args
}

// NormalizedEvent is the canonical event format published to NATS JetStream.
// This is the single shared schema between the ingestion and detection services.
type NormalizedEvent struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	Type     string `json:"type"`
	// EventID is the events.event_id of the row this event was persisted as, so a
	// detection built from it can record which evidence it fired on. Omitted (and
	// therefore empty on the consumer side) only by producers older than this
	// field; consumers must treat "" as "unknown", never as an error.
	EventID   string          `json:"event_id,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

func (s *Server) marshalEventPayload(agentID, platform, evtType, eventID string, evt *v1.Event) ([]byte, error) {
	// Use normalizeEventData (flat key/value form) instead of json.Marshal(evt)
	// (proto oneof wrapper). The detection engine's mergeProtoEvent can then
	// surface inner fields like .query, .path, .dst_ip directly in the flat
	// map fed to IOCMatcher / Sigma — no need to traverse the Payload.Dns /
	// Payload.File wrapper. This also keeps NATS payload identical to what
	// we persist in events.raw_data, so debugging is symmetrical.
	payload := normalizeEventData(evt)

	hostname := ""
	if v, ok := s.hostnames.Load(agentID); ok {
		hostname, _ = v.(string)
	}

	// Use the promoted evtType (e.g. "memory"/"process_block"/"file" derived from
	// the encoded "<type>:<uuid>:<json>" ID), NOT the raw proto type — which is
	// EVENT_TYPE_LOG ("") for those encoded findings. The detection engine
	// discriminates on this Type (e.g. the memory→T1055 alert path), so it must
	// match the DB event_type and the NATS topic.
	ne := NormalizedEvent{
		AgentID:   agentID,
		Hostname:  hostname,
		Platform:  platform,
		Type:      evtType,
		EventID:   eventID,
		Timestamp: evt.GetTimestamp().AsTime(),
		Data:      payload,
	}
	return json.Marshal(ne)
}

// publishEvent publishes to JetStream with a message-ID for deduplication.
// Falls back to plain NATS publish if JetStream is unavailable.
func (s *Server) publishEvent(topic string, data []byte, msgID string) {
	if s.js != nil {
		_, err := s.js.Publish(topic, data, nats.MsgId(msgID))
		if err == nil {
			return
		}
		slog.Warn("JetStream publish失敗、通常publishにフォールバック", "topic", topic, "error", err)
	}
	// Fallback
	if err := s.nats.Publish(topic, data); err != nil {
		slog.Warn("NATS publish失敗", "topic", topic, "error", err)
	}
}

// ─── Command conversion ───────────────────────────────────────

// commandToProto converts an internal Command to a proto ServerCommand.
//
// ペイロードの JSON が壊れていたら nil を返す。以前は json.Unmarshal の
// 戻り値を捨てていたため、パースに失敗するとゼロ値のまま proto を組み立てて
// エージェントへ送っていた。害が具体的なのは kill_process で、**PID 0 の
// プロセス終了コマンド**がそのまま端末に届く。quarantine_file も同様に
// 空パスで飛ぶ。呼び出し側 (Dequeue のループ) は既に nil を読み飛ばすので、
// 送らないのが安全側。
// allowIPs は隔離コマンドにだけ載る。空なら従来どおり EDR サーバとループバック
// だけが残る。
func commandToProto(cmd *Command, allowIPs []string) *v1.ServerCommand {
	sc := &v1.ServerCommand{CommandId: cmd.ID}

	switch cmd.Type {
	case "isolate":
		var p struct {
			Reason  string `json:"reason"`
			AlertID string `json:"alert_id"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		sc.Command = &v1.ServerCommand_Isolate{
			Isolate: &v1.IsolateCommand{
				Reason:   p.Reason,
				AlertId:  p.AlertID,
				AllowIps: allowIPs,
			},
		}

	case "unisolate":
		var p struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		sc.Command = &v1.ServerCommand_Unisolate{
			Unisolate: &v1.UnisolateCommand{Reason: p.Reason},
		}

	case "kill_process":
		var p struct {
			PID    uint32 `json:"pid"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		sc.Command = &v1.ServerCommand_KillProcess{
			KillProcess: &v1.KillProcessCommand{Pid: p.PID, Reason: p.Reason},
		}

	case "quarantine_file":
		var p struct {
			Path    string `json:"path"`
			AlertID string `json:"alert_id"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		sc.Command = &v1.ServerCommand_QuarantineFile{
			QuarantineFile: &v1.QuarantineFileCommand{Path: p.Path, AlertId: p.AlertID},
		}

	case "restore_file":
		var p struct {
			QuarantineID string `json:"quarantine_id"`
			RestorePath  string `json:"restore_path"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		sc.Command = &v1.ServerCommand_RestoreFile{
			RestoreFile: &v1.RestoreFileCommand{QuarantineId: p.QuarantineID, RestorePath: p.RestorePath},
		}

	case "scan":
		var p struct {
			ScanType string `json:"scan_type"`
			Target   string `json:"target"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			slog.Warn("コマンドペイロードの JSON が不正です(送信しません)",
				"command_id", cmd.ID, "type", cmd.Type, "error", err)
			return nil
		}
		scanType := v1.ScanCommand_SCAN_TYPE_FULL_DISK
		if p.ScanType == "file" {
			scanType = v1.ScanCommand_SCAN_TYPE_FILE
		} else if p.ScanType == "memory" {
			scanType = v1.ScanCommand_SCAN_TYPE_MEMORY
		}
		sc.Command = &v1.ServerCommand_Scan{
			Scan: &v1.ScanCommand{Type: scanType, Target: p.Target},
		}

	case "reload_config":
		sc.Command = &v1.ServerCommand_ReloadConfig{
			ReloadConfig: &v1.ReloadConfigCommand{},
		}

	case "live_response_start":
		// Reuse CollectArtifactCommand (type=LOGS) as a carrier for live response session info.
		// The agent decodes the target field as LiveResponseStartPayload JSON.
		targetJSON, _ := json.Marshal(cmd.Payload)
		sc.Command = &v1.ServerCommand_CollectArtifact{
			CollectArtifact: &v1.CollectArtifactCommand{
				Type:   v1.CollectArtifactCommand_ARTIFACT_TYPE_LOGS,
				Target: string(targetJSON),
			},
		}

	case "apply_policy":
		// Carry the full policy JSON in CollectArtifactCommand.Target.
		// ARTIFACT_TYPE_UNSPECIFIED (0) is the sentinel meaning "apply_policy", and
		// the agent narrows it further by the presence of "policy_id".
		//
		// This comment used to claim the payload carries a "type":"apply_policy"
		// field for disambiguation. It never has — store.ApplyPolicyPayload is
		// {agent_id, policy_id, scan_interval_min, cpu_limit_pct, enabled_modules}
		// and has no "type" key at all. The agent looked for a marker that was
		// never sent, fell through to a generic artifact collection, and dropped
		// the command; policy push had therefore never worked on any endpoint.
		// A comment describing a contract nobody implements is worse than none:
		// it makes the reader stop looking.
		sc.Command = &v1.ServerCommand_CollectArtifact{
			CollectArtifact: &v1.CollectArtifactCommand{
				Type:   v1.CollectArtifactCommand_ARTIFACT_TYPE_UNSPECIFIED,
				Target: string(cmd.Payload),
			},
		}

	case "cert_renew":
		// Carry the renewal token JSON in CollectArtifactCommand.Target.
		// The payload JSON is {"type":"cert_renew","renewal_token":"<token>"}.
		// Agent identifies this case by the "type" key inside the JSON.
		sc.Command = &v1.ServerCommand_CollectArtifact{
			CollectArtifact: &v1.CollectArtifactCommand{
				Type:   v1.CollectArtifactCommand_ARTIFACT_TYPE_UNSPECIFIED,
				Target: string(cmd.Payload),
			},
		}

	default:
		return nil
	}

	return sc
}

// ─── Helpers ──────────────────────────────────────────────────

// extractAgentIDFromCert reads the agent ID from the mTLS peer certificate CN.
// Falls back to gRPC metadata header "x-agent-id" for insecure (non-TLS) mode.
func extractAgentIDFromCert(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			state := tlsInfo.State
			if state.HandshakeComplete && len(state.PeerCertificates) > 0 {
				return state.PeerCertificates[0].Subject.CommonName
			}
		}
	}
	// Fallback: read agent ID from gRPC metadata (insecure / dev mode)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-agent-id"); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return ""
}

// eventTypeByIDPrefix maps a log-style event's ID prefix to the canonical
// event_type. Kept as data rather than a switch so producibleEventTypes can
// enumerate the result set — the constraint gate in
// event_type_constraint_test.go needs the full set, and a switch cannot be
// enumerated. Order is irrelevant: no prefix is a prefix of another.
var eventTypeByIDPrefix = []struct{ prefix, evtType string }{
	{"fim_change:", "file"},
	{"process_stats:", "process_stats"},
	{"process_block:", "process_block"},
	{"memory:", "memory"},
	{"credential_access:", "credential_access"},
	{"host_integrity:", "host_integrity"},
	{"create_remote_thread:", "create_remote_thread"},
	{"tls_handshake:", "tls_handshake"},
	{"ps_module:", "ps_module"},
	{"pipe_created:", "pipe_created"},
	{"wmi_activity:", "wmi_activity"},
	{"eventlog_cleared:", "eventlog_cleared"},
	{"service_installed:", "service_installed"},
	{"device_event:", "device_event"},
	{"tamper:", "tamper"},
}

// promoteEventType resolves the canonical event_type for an incoming event.
// Most events carry it in the proto type enum, but log-style findings arrive as
// EVENT_TYPE_LOG ("") with the real type and payload encoded in the ID as
// "<type>:<uuid>:<json>". Without promotion these stay "" and are silently
// dropped — the class of gap found 2026-06-19 (process_block) — so the mapping
// lives in one pure, testable place shared by ingestion and the E2E oracle.
func promoteEventType(evt *v1.Event) string {
	if t := eventTypeString(evt.GetType()); t != "" {
		return t
	}
	id := evt.GetId()
	for _, m := range eventTypeByIDPrefix {
		if strings.HasPrefix(id, m.prefix) {
			return m.evtType
		}
	}
	return ""
}

// producibleEventTypes is every value promoteEventType can return, derived from
// its two sources rather than restated: the proto enum (via eventTypeString) and
// eventTypeByIDPrefix. Every one of these must be permitted by the
// events_event_type_check constraint or the INSERT is rejected with 23514 —
// see event_type_constraint_test.go, which enforces exactly that.
func producibleEventTypes() []string {
	seen := make(map[string]bool)
	for v := range v1.EventType_name {
		if t := eventTypeString(v1.EventType(v)); t != "" {
			seen[t] = true
		}
	}
	for _, m := range eventTypeByIDPrefix {
		seen[m.evtType] = true
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func eventTypeString(t v1.EventType) string {
	switch t {
	case v1.EventType_EVENT_TYPE_PROCESS:
		return "process"
	case v1.EventType_EVENT_TYPE_FILE:
		return "file"
	case v1.EventType_EVENT_TYPE_NETWORK:
		return "network"
	case v1.EventType_EVENT_TYPE_DNS:
		return "dns"
	case v1.EventType_EVENT_TYPE_REGISTRY:
		return "registry"
	case v1.EventType_EVENT_TYPE_AUTH:
		return "auth"
	case v1.EventType_EVENT_TYPE_IMAGE_LOAD:
		return "image_load"
	case v1.EventType_EVENT_TYPE_SCRIPT:
		return "script"
	default:
		return ""
	}
}

func platformString(p v1.Platform) string {
	switch p {
	case v1.Platform_PLATFORM_LINUX:
		return "linux"
	case v1.Platform_PLATFORM_WINDOWS:
		return "windows"
	case v1.Platform_PLATFORM_DARWIN:
		return "darwin"
	default:
		return "unknown"
	}
}

func generateID() string {
	return uuid.New().String()
}

// normalizeEventData extracts the event payload into a flat JSON object
// with snake_case keys so the frontend can query and display it directly.
func normalizeEventData(evt *v1.Event) []byte {
	var m map[string]interface{}

	switch evt.GetType() {
	case v1.EventType_EVENT_TYPE_NETWORK:
		n := evt.GetNetwork()
		if n == nil {
			m = map[string]interface{}{}
			break
		}
		dir := "outbound"
		if n.GetDirection() == v1.NetworkEvent_NETWORK_DIRECTION_INBOUND {
			dir = "inbound"
		}
		m = map[string]interface{}{
			"src_ip":       n.GetSrcIp(),
			"src_port":     n.GetSrcPort(),
			"dst_ip":       n.GetDstIp(),
			"dst_port":     n.GetDstPort(),
			"protocol":     n.GetProtocol(),
			"direction":    dir,
			"bytes_sent":   n.GetBytesSent(),
			"bytes_recv":   n.GetBytesRecv(),
			"pid":          n.GetPid(),
			"process_name": n.GetProcessName(),
			"state":        "ESTABLISHED",
		}
		if h := n.GetHostname(); h != "" {
			m["hostname"] = h
		}
		if cc := n.GetCountryCode(); cc != "" {
			m["country_code"] = cc
		}
		if n.GetIsEncrypted() {
			m["is_encrypted"] = true
		}
		// Surface the agent-side threat-intel verdict so it is not silently dropped.
		if ti := n.GetThreatIntel(); ti != nil && ti.GetMatched() {
			m["threat_intel_matched"] = true
			m["threat_intel_source"] = ti.GetSource()
			m["threat_intel_category"] = ti.GetCategory()
			m["threat_intel_confidence"] = ti.GetConfidence()
		}
	case v1.EventType_EVENT_TYPE_PROCESS:
		p := evt.GetProcess()
		if p == nil {
			m = map[string]interface{}{}
			break
		}
		m = map[string]interface{}{
			"process_name": p.GetProcessName(),
			"pid":          p.GetPid(),
			"ppid":         p.GetPpid(),
			"command_line": p.GetCommandLine(),
			"image_path":   p.GetImagePath(),
			"username":     p.GetUsername(),
			"action":       processActionString(p.GetAction()),
		}
		addHashes(m, p.GetHashes())
		// PE VERSIONINFO — only emit keys the agent actually populated (Windows,
		// best-effort). The alias layer maps these onto the Sysmon Sigma names
		// OriginalFileName/Description/Product/Company that renamed-binary and
		// LOLBin process_creation rules select on.
		if v := p.GetOriginalFileName(); v != "" {
			m["original_file_name"] = v
		}
		if v := p.GetFileDescription(); v != "" {
			m["file_description"] = v
		}
		if v := p.GetProductName(); v != "" {
			m["product_name"] = v
		}
		if v := p.GetCompanyName(); v != "" {
			m["company_name"] = v
		}
		// Token integrity level (Windows) — drives UAC-bypass / privesc rules via
		// the IntegrityLevel alias.
		if v := p.GetIntegrityLevel(); v != "" {
			m["integrity_level"] = v
		}
		// Logon session ID (Windows) — drives elevated-shell rules via LogonId.
		if v := p.GetLogonId(); v != "" {
			m["logon_id"] = v
		}
		// The parent, resolved on the endpoint while it was still alive. Only
		// emitted when the agent could name it: an absent parent is absent, not
		// an empty string, so a reader can tell "unknown" from "no parent".
		if v := p.GetParentName(); v != "" {
			m["parent_name"] = v
		}
		if v := p.GetParentImage(); v != "" {
			m["parent_image"] = v
		}
		// Containment. Only emitted for a process actually in a container, so
		// privileged/host_network are absent rather than false for the host's
		// own processes — "not privileged" and "not in a container" are
		// different facts, and cloudruntime filters on the flags being true.
		if id := p.GetContainerId(); id != "" {
			m["container_id"] = id
			m["privileged"] = p.GetContainerPrivileged()
			m["host_network"] = p.GetContainerHostNetwork()
		}
		// Suspicious environment variables (LD_PRELOAD etc.) for dynamic-linker
		// hijacking detection. `environment` is the joined form Sigma rules match.
		if env := p.GetEnvVars(); len(env) > 0 {
			m["env_vars"] = env
			m["environment"] = strings.Join(env, " ")
		}
	case v1.EventType_EVENT_TYPE_FILE:
		// FIM events from the SHA-256 polling collector encode their payload as
		// "fim_change:<uuid>:<json>" in the event ID field rather than using the
		// proto File oneof. Detect and unpack them first.
		if strings.HasPrefix(evt.GetId(), "fim_change:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				var fimPayload map[string]interface{}
				if err := json.Unmarshal([]byte(parts[2]), &fimPayload); err == nil {
					m = fimPayload
					break
				}
			}
		}
		f := evt.GetFile()
		if f == nil {
			m = map[string]interface{}{}
			break
		}
		m = map[string]interface{}{
			"path":         f.GetPath(),
			"old_path":     f.GetOldPath(),
			"operation":    f.GetAction().String(),
			"process_name": f.GetProcessName(),
			"pid":          f.GetPid(),
			"file_size":    f.GetFileSize(),
		}
		addHashes(m, f.GetHashes())
		// Surface the agent-side YARA verdict so on-endpoint malware hits are not dropped.
		if f.GetYaraMatched() {
			m["yara_matched"] = true
			if ids := f.GetYaraRuleIds(); len(ids) > 0 {
				m["yara_rule_ids"] = ids
			}
		}
	case v1.EventType_EVENT_TYPE_DNS:
		d := evt.GetDns()
		if d == nil {
			m = map[string]interface{}{}
			break
		}
		m = map[string]interface{}{
			"query":        d.GetQuery(),
			"query_type":   d.GetQueryType(),
			"answers":      d.GetAnswers(),
			"process_name": d.GetProcessName(),
			"pid":          d.GetPid(),
		}
		// Surface the agent-side DGA/homograph suspicion flag.
		if d.GetIsSuspicious() {
			m["is_suspicious"] = true
		}
	case v1.EventType_EVENT_TYPE_REGISTRY:
		r := evt.GetRegistry()
		if r == nil {
			m = map[string]interface{}{}
			break
		}
		// Expose under both snake_case and the keyPath/valueName names so the
		// Sigma alias layer maps them onto TargetObject/Details (e.g. the UAC
		// bypass registry-hijack rule).
		m = map[string]interface{}{
			"key_path":     r.GetKeyPath(),
			"keyPath":      r.GetKeyPath(),
			"value_name":   r.GetValueName(),
			"value_data":   r.GetValueData(),
			"operation":    registryActionString(r.GetAction()),
			"pid":          r.GetPid(),
			"process_name": r.GetProcessName(),
		}
	case v1.EventType_EVENT_TYPE_AUTH:
		a := evt.GetAuth()
		if a == nil {
			m = map[string]interface{}{}
			break
		}
		m = map[string]interface{}{
			"username":       a.GetUsername(),
			"action":         authActionString(a.GetAction()),
			"success":        a.GetSuccess(),
			"source_ip":      a.GetSourceIp(),
			"auth_method":    a.GetAuthMethod(),
			"failure_reason": a.GetFailureReason(),
		}
		// Windows 4624/4625 LogonType — feeds the off-hours-login UEBA feature
		// (alert_pipeline login_hour sample) and Sigma LogonType rules (T1078).
		// Emitted only when present so non-Windows auth events stay unchanged.
		if lt := a.GetLogonType(); lt != "" {
			m["logon_type"] = lt
		}
		// Raw Security-log event id (4624/4625/4634/4672/4765/4766/4768/4769), and
		// the Kerberos service-ticket fields from 4769. Emitted only when present,
		// so an event that is not a Kerberos ticket request has no target_spn key
		// rather than an empty one — the Kerberoasting query can then filter on the
		// key's presence and mean it.
		//
		// event_id は数値で入れる。読む側 (auth_attack / SID-History の門) が
		// toFloat64 を通しており、文字列を受け取らない。
		//
		// Note this is NOT the same as making every `EventID:` Sigma rule live —
		// the alias to the Sigma field name is applied selectively in
		// addPipelineSigmaAliases, for the reason documented there. This map is the
		// honest record of what the agent reported.
		if id := a.GetEventId(); id != 0 {
			m["event_id"] = float64(id)
		}
		if v := a.GetTargetSpn(); v != "" {
			m["target_spn"] = v
		}
		if v := a.GetTicketEncryptionType(); v != "" {
			m["ticket_encryption_type"] = v
		}
	case v1.EventType_EVENT_TYPE_IMAGE_LOAD:
		il := evt.GetImageLoad()
		if il == nil {
			m = map[string]interface{}{}
			break
		}
		// image_loaded/signature_status drive the DLL-sideloading Sigma rule
		// (aliased to ImageLoaded/SignatureStatus).
		m = map[string]interface{}{
			"image_loaded":     il.GetImagePath(),
			"process_name":     il.GetProcessName(),
			"pid":              il.GetPid(),
			"signed":           il.GetSigned(),
			"signature_status": il.GetSignatureStatus(),
			"signer":           il.GetSigner(),
		}
		addHashes(m, il.GetHashes())
	case v1.EventType_EVENT_TYPE_SCRIPT:
		s := evt.GetScript()
		if s == nil {
			m = map[string]interface{}{}
			break
		}
		// script_block_text drives the malicious-script Sigma rule (aliased to
		// ScriptBlockText). The deobfuscated content reveals intent that a
		// command line alone (e.g. "-enc <base64>") hides.
		m = map[string]interface{}{
			"script_block_text": s.GetContent(),
			"engine":            s.GetEngine(),
			"process_name":      s.GetProcessName(),
			"pid":               s.GetPid(),
			"content_hash":      s.GetContentHash(),
		}
	default:
		// Per-process stats snapshot: "process_stats:<uuid>:<json-array>"
		if strings.HasPrefix(evt.GetId(), "process_stats:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Process-block decision: "process_block:<uuid>:<json>" — the inner JSON
		// is {process_name, pid, action, rule_id, rule_name, severity}.
		if strings.HasPrefix(evt.GetId(), "process_block:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Memory/injection finding: "memory:<uuid>:<json>" — the inner JSON is
		// {pid, process_name, address, perms, size, unbacked, rwx, reason}.
		if strings.HasPrefix(evt.GetId(), "memory:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Credential-access finding: "credential_access:<uuid>:<json>" — the inner
		// JSON is {target_pid, target_image, source_pid, source_image, access_mask,
		// enforced}.
		if strings.HasPrefix(evt.GetId(), "credential_access:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Host-integrity finding: "host_integrity:<uuid>:<json>" — the inner JSON
		// is {action, pid, process_name, command_line}. action/process_name/
		// command_line/pid are the same field names process_creation events use,
		// so existing Sigma rules and the field-support gate need no changes.
		if strings.HasPrefix(evt.GetId(), "host_integrity:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Remote-thread / injection finding: "create_remote_thread:<uuid>:<json>"
		// — the inner JSON is {source_pid, source_image, target_pid, target_image}.
		if strings.HasPrefix(evt.GetId(), "create_remote_thread:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// TLS fingerprint finding: "tls_handshake:<uuid>:<json>" — the inner JSON is
		// {dst_ip, dst_port, sni, ja3, ja3s, process_name, pid}. The detection engine
		// matches ja3/ja3s against the C2-framework blocklist.
		if strings.HasPrefix(evt.GetId(), "tls_handshake:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// PowerShell module-logging (4103) finding: "ps_module:<uuid>:<json>" — the
		// inner JSON is {payload, context_info, pid}. payload/context_info alias to the
		// Sigma Payload/ContextInfo fields the ps_module rules select on.
		if strings.HasPrefix(evt.GetId(), "ps_module:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// WMI-Activity finding: "wmi_activity:<uuid>:<json>" — the inner JSON uses the
		// SigmaHQ wmi_event field names (event_type, operation, user, query, consumer,
		// name, namespace, destination) rather than the raw ETW property spellings, so
		// the community rules for that category match the flattened event directly.
		if strings.HasPrefix(evt.GetId(), "wmi_activity:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Named-pipe creation finding: "pipe_created:<uuid>:<json>" — the inner JSON is
		// {pipe_name, image_path, pid}. pipe_name aliases to the Sigma PipeName field the
		// Cobalt Strike / C2 pipe_created rules select on.
		if strings.HasPrefix(evt.GetId(), "pipe_created:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Event-log-cleared finding: "eventlog_cleared:<uuid>:<json>" — the inner
		// JSON is {channel, user, backup_path}. Surfaces Windows Security/System
		// audit-log clearing (EID 1102 / 104) as T1070.001 (Indicator Removal:
		// Clear Windows Event Logs), a defense-evasion technique with no other
		// detection consumer.
		if strings.HasPrefix(evt.GetId(), "eventlog_cleared:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Service-installation finding: "service_installed:<uuid>:<json>" — the
		// inner JSON is {service_name, image_path, service_type, start_type,
		// account}. Surfaces Windows System EID 7045 (a service was installed) as
		// T1543.003 when the service binary looks malicious (PsExec / Cobalt
		// Strike lateral movement and persistence).
		if strings.HasPrefix(evt.GetId(), "service_installed:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Removable-device finding: "device_event:<uuid>:<json>" — the inner JSON is
		// {action, device_id, name, vendor_id, product_id, type}. Surfaces USB /
		// removable-media connect events (agent device collector) as T1091 / T1200 /
		// T1052 — a monitored vector for malware replication and USB exfiltration that
		// previously fell through promotion and was silently dropped.
		if strings.HasPrefix(evt.GetId(), "device_event:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		// Agent self-protection finding: "tamper:<uuid>:<json>" — the inner JSON is
		// {tamper_type, component, enforced, path, target_pid, source_pid,
		// source_image, username, signal, access_mask, exit_code, expected_hash,
		// actual_hash, reason}. Surfaces attempts to stop, replace or reconfigure
		// the agent itself (T1562.001 / T1554).
		//
		// This decode is easy to forget and fails quietly when it is: promotion
		// alone gets the event a type and a row, but raw_data falls through to the
		// json.Marshal(evt) below and the payload the rules select on never
		// materialises. The rules then never match, which is indistinguishable from
		// an endpoint nobody has tampered with. Adding a "<type>:<uuid>:<json>"
		// sensor means updating promoteEventType, this decode, the
		// events_event_type_check constraint, and eventTypeCategories — four
		// places, each silent on its own.
		if strings.HasPrefix(evt.GetId(), "tamper:") {
			parts := strings.SplitN(evt.GetId(), ":", 3)
			if len(parts) == 3 {
				return []byte(parts[2])
			}
		}
		raw, _ := json.Marshal(evt)
		return raw
	}

	out, err := json.Marshal(m)
	if err != nil {
		raw, _ := json.Marshal(evt)
		return raw
	}
	return out
}

// addHashes lifts proto FileHashes onto the normalized event under the flat keys
// the IOC matcher (sha256/md5/sha1) and Sigma rules expect. Empty values are
// skipped. Without this, agent-computed hashes never reach the detection layer
// and hash-based IOC matching (known-malware detection) silently never fires.
func addHashes(m map[string]interface{}, h *v1.FileHashes) {
	if h == nil {
		return
	}
	if s := h.GetSha256(); s != "" {
		m["sha256"] = s
	}
	if s := h.GetMd5(); s != "" {
		m["md5"] = s
	}
	if s := h.GetSha1(); s != "" {
		m["sha1"] = s
	}
}

func registryActionString(a v1.RegistryEvent_RegistryAction) string {
	switch a {
	case v1.RegistryEvent_REGISTRY_ACTION_CREATE:
		return "create"
	case v1.RegistryEvent_REGISTRY_ACTION_MODIFY:
		return "modify"
	case v1.RegistryEvent_REGISTRY_ACTION_DELETE:
		return "delete"
	case v1.RegistryEvent_REGISTRY_ACTION_QUERY:
		return "query"
	default:
		return "unknown"
	}
}

func authActionString(a v1.AuthEvent_AuthAction) string {
	switch a {
	case v1.AuthEvent_AUTH_ACTION_LOGIN:
		return "login"
	case v1.AuthEvent_AUTH_ACTION_LOGOUT:
		return "logout"
	case v1.AuthEvent_AUTH_ACTION_PRIVILEGE:
		return "privilege"
	case v1.AuthEvent_AUTH_ACTION_FAILED:
		return "failed"
	case v1.AuthEvent_AUTH_ACTION_SERVICE_TICKET:
		return "kerberos_service_ticket"
	default:
		return "unknown"
	}
}

func processActionString(a v1.ProcessEvent_ProcessAction) string {
	switch a {
	case v1.ProcessEvent_PROCESS_ACTION_CREATE:
		return "create"
	case v1.ProcessEvent_PROCESS_ACTION_TERMINATE:
		return "terminate"
	case v1.ProcessEvent_PROCESS_ACTION_INJECT:
		return "inject"
	case v1.ProcessEvent_PROCESS_ACTION_HOLLOW:
		return "hollow"
	case v1.ProcessEvent_PROCESS_ACTION_UNSPECIFIED:
		return "existing"
	default:
		return "existing"
	}
}

// isolationHeaders returns the response-metadata keys that tell an agent to
// reconcile its isolation state.
//
// **切り出してあるのは、両方向あることを直接確かめるため**です。元は
// gRPC の経路に突き合わせが1つも無く、`FallbackSender` は gRPC を先に
// 試すので、**gRPC が生きている通常時、HTTP 側の巻き戻しは端末に
// 届きませんでした。**
func isolationHeaders(dbStatus, reportedStatus string) []string {
	dbIsolated := dbStatus == "isolated"
	reportedIsolated := reportedStatus == "isolated"
	switch {
	case dbIsolated && !reportedIsolated:
		return []string{"x-edr-should-isolate"}
	case !dbIsolated && reportedIsolated:
		return []string{"x-edr-should-unisolate"}
	}
	return nil
}

// applyCommandAcks closes the audit rows for commands the agent has finished.
//
// command_id は API 側が採番した response_actions.id（#721）。エージェントは
// 受け取った値をそのまま返すので、ここで終了状態に更新できる。
//
// これが無い間、隔離の記録は dispatched のまま残り、期限切れワーカーが
// timeout に畳んでいた。つまり「実際には成功した隔離」も timeout と記録される。
// ack が届いて初めて、成功と「結果が返らなかった」を区別できる。
//
// 終了状態の行は上書きしない。期限切れで畳んだ後に遅れて ack が届いた場合、
// 記録を書き換えると「いつ確定したのか」が失われる。遅れて届いた事実は
// ログに残す。
func (s *Server) applyCommandAcks(ctx context.Context, agentID string, acks []*v1.CommandAck) {
	if len(acks) == 0 || s.pool == nil {
		return
	}
	for _, ack := range acks {
		id := ack.GetCommandId()
		if id == "" {
			continue
		}
		status := "success"
		if ack.GetStatus() != v1.CommandAck_ACK_STATUS_SUCCESS {
			status = "failure"
		}
		var errMsg *string
		if e := ack.GetError(); e != "" {
			errMsg = &e
		}
		tag, err := s.pool.Exec(ctx, `
			UPDATE response_actions
			   SET status_text = $2,
			       error_msg   = COALESCE($3, error_msg)
			 WHERE id = $1
			   AND status_text IN ('pending', 'dispatched', 'running')
		`, id, status, errMsg)
		if err != nil {
			slog.Warn("コマンド実行結果の記録に失敗しました",
				"agent", agentID, "command_id", id, "error", err)
			continue
		}
		if tag.RowsAffected() == 0 {
			// 期限切れで畳まれた後に届いたか、そもそも該当する記録が無い
			// （自動対応の経路は id を持たない）。どちらも異常ではないが、
			// 継続的に出るなら期限が短すぎる。
			slog.Info("対応する記録が無い、または既に確定済みの ACK を受け取りました",
				"agent", agentID, "command_id", id, "status", status)
			continue
		}
		slog.Info("コマンドの実行結果を記録しました",
			"agent", agentID, "command_id", id, "status", status)
	}
}
