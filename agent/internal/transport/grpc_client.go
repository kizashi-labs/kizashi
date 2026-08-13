package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/agent/internal/config"
	"github.com/edr-platform/agent/internal/heartbeat"
	"github.com/edr-platform/agent/internal/response"
	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// GRPCClient manages the persistent connection to the EDR server.
// It handles mTLS authentication, reconnection with exponential backoff,
// and offline buffering via RingBuffer.
type GRPCClient struct {
	mu              sync.RWMutex
	cfg             *config.Config
	conn            *grpc.ClientConn
	ingestionClient v1.IngestionServiceClient
	stream          v1.IngestionService_EventStreamClient
	streamMu        sync.Mutex
	sendMu          sync.Mutex    // serializes stream.Send across live-send and drain paths
	sendTimeout     time.Duration // bounds a single stream.Send (half-open watchdog)
	recvTimeout     time.Duration // max silence on the downstream before presuming half-open
	buffer          *RingBuffer
	connected       bool
	connCancel      context.CancelFunc // cancels the current connection scope to force a reconnect
	onCommand       CommandHandler

	// serverKeepalive latches true once we learn the server pushes EventStream
	// keepalives — either by receiving one, or (crucially) from the x-edr-keepalive
	// header on a unary Heartbeat reply, which keeps working even when the bidi
	// stream is half-open. Once set, the receive watchdog arms from stream-open so a
	// downstream that is half-open *from birth* (no keepalive ever arrives — the
	// hairpin-NAT failure mode) is still detected. While unset (an older server that
	// never sends keepalives) the watchdog never reconnects on silence, avoiding
	// false flapping. Atomic: written by the heartbeat/receive goroutines, read by
	// the watchdog.
	serverKeepalive atomic.Bool
}

// defaultSendTimeout bounds a single stream.Send(). A normal send completes in
// milliseconds; this only fires on an application-level half-open stream where the
// server stopped reading but HTTP/2 + keepalive stay healthy (see sendWithWatchdog).
const defaultSendTimeout = 15 * time.Second

// defaultRecvTimeout bounds the silence tolerated on the downstream (server→agent)
// half of the event stream before we presume an application-level half-open and
// force a reconnect (see runRecvWatchdog). The server pushes a keepalive frame on
// its EventStream ticker every serverKeepaliveInterval (5s, see ingestion
// handler.go), so any value comfortably above that interval — here 6 missed
// keepalives — means "genuinely silent", not merely "idle with no commands".
const defaultRecvTimeout = 30 * time.Second

// signalDisconnect marks the client disconnected and cancels the current
// connection scope so RunWithReconnect's waitForDisconnect unblocks and re-dials.
// Needed because the server may close only the bidirectional stream (Send/Recv
// returns EOF) while the underlying HTTP/2 connection stays READY — in that
// half-open case conn.GetState() never flips, so without this the agent would
// buffer forever and never receive commands again (observed after a server
// restart: scans dispatched but never executed).
func (c *GRPCClient) signalDisconnect() {
	c.mu.Lock()
	c.connected = false
	cancel := c.connCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// CommandHandler is called when the server sends a command to this agent.
type CommandHandler func(cmd *ServerCommand)

// ScanCmd is delivered when the server requests a YARA scan.
type ScanCmd struct {
	CommandID string
	ScanType  string // "SCAN_TYPE_FULL_DISK" | "SCAN_TYPE_FILE" | "SCAN_TYPE_MEMORY"
	Target    string // path to scan; empty means default paths
}

// ForensicsJobPayload is the JSON carried in the CollectArtifact target field
// when the server dispatches a forensics job (type="forensics_job").
// It mirrors the server's agents.forensics.{agentID} NATS message schema.
type ForensicsJobPayload struct {
	Type      string `json:"type"` // always "forensics_job"
	JobID     string `json:"job_id"`
	JobType   string `json:"job_type"`   // "process_list" | "memory_dump" | "artifact_collect"
	ProcessID int    `json:"process_id"` // for memory_dump jobs
}

// ServerCommand represents a command received from the server.
type ServerCommand struct {
	CommandID string
	Type      CommandType
	Payload   interface{}
}

type CommandType int

const (
	CmdReloadConfig CommandType = iota
	CmdIsolate
	CmdUnisolate
	CmdKillProcess
	CmdQuarantineFile
	CmdRestoreFile
	CmdCollectArtifact
	CmdScan
	CmdUpdateAgent
	CmdLiveResponseStart
	CmdForensicsJob
	CmdCertRenew
	CmdApplyPolicy
)

// ApplyPolicyCmd mirrors the server's store.ApplyPolicyPayload — the shape the
// API, the database and the admin UI have all used from the start.
//
// The agent used to have a THIRD, incompatible idea of what a policy looks like
// (internal/policy.Policy: {type, version, content, updated_at, checksum}), and
// ingestion's comment claimed the wire payload carried a "type":"apply_policy"
// field for disambiguation — a field the server has never sent. Three contracts,
// no agreement, so the command was received and silently discarded. Aligning on
// the server's shape is the only option that leaves the UI, the API and the
// stored policies untouched.
type ApplyPolicyCmd struct {
	CommandID       string
	PolicyID        string   `json:"policy_id"`
	ScanIntervalMin int      `json:"scan_interval_min"`
	CPULimitPct     int      `json:"cpu_limit_pct"`
	EnabledModules  []string `json:"enabled_modules"`
}

// CertRenewCmd is the payload for CmdCertRenew commands.
type CertRenewCmd struct {
	CommandID    string
	RenewalToken string
}

func NewGRPCClient(cfg *config.Config, buffer *RingBuffer, handler CommandHandler) *GRPCClient {
	return &GRPCClient{
		cfg:         cfg,
		buffer:      buffer,
		onCommand:   handler,
		sendTimeout: defaultSendTimeout,
		recvTimeout: defaultRecvTimeout,
	}
}

// Connect establishes the mTLS gRPC connection to the server.
func (c *GRPCClient) Connect(ctx context.Context) error {
	serverAddr := fmt.Sprintf("%s:%d",
		extractHost(c.cfg.Server.URL),
		c.cfg.Server.IngestionGRPCPort,
	)

	// Use insecure gRPC when no CA cert is configured (development / TLS_ENABLED=false)
	var dialCred grpc.DialOption
	if c.cfg.Server.CACert == "" {
		slog.Info("CA証明書未設定 — 平文gRPCで接続")
		dialCred = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		tlsCfg, err := c.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("build TLS config: %w", err)
		}
		dialCred = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}

	// 接続できるまで待つ。RunWithReconnect がこのエラーで指数バックオフを
	// 回すため、サーバ不達で成功を返してはならない (dial.go を参照)。
	conn, err := dialBlocking(ctx, serverAddr,
		time.Duration(c.cfg.Server.ConnectTimeoutSec)*time.Second,
		dialCred,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("grpc dial %s: %w", serverAddr, err)
	}

	c.mu.Lock()
	c.conn = conn
	c.ingestionClient = v1.NewIngestionServiceClient(conn)
	c.connected = true
	c.mu.Unlock()

	slog.Info("connected to EDR server", "addr", serverAddr)
	return nil
}

// openStream opens the bidirectional event stream and starts receiving commands.
func (c *GRPCClient) openStream(ctx context.Context) error {
	// In insecure mode (no CA cert), pass agent ID via metadata header
	if c.cfg.Server.CACert == "" && c.cfg.Agent.ID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-agent-id", c.cfg.Agent.ID)
	}
	stream, err := c.ingestionClient.EventStream(ctx)
	if err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}

	c.streamMu.Lock()
	c.stream = stream
	c.streamMu.Unlock()

	// ctx is the connection-scoped context; it bounds the receive watchdog so it
	// dies together with the stream on reconnect.
	go c.receiveCommands(ctx, stream)
	return nil
}

// receiveCommands reads server commands from the stream until it closes.
//
// On an application-level half-open stream (the server stopped *writing* the
// downstream while HTTP/2 + gRPC keepalive stay healthy — e.g. a wedged server
// EventStream goroutine, or a hairpin-NAT path that silently drops one direction)
// stream.Recv() blocks with no EOF until the OS TCP read timeout fires minutes
// later. Queued isolate/scan commands would sit undelivered the whole time even
// though ingestion logged "コマンドを送信しました". runRecvWatchdog closes that gap:
// the server pushes a keepalive frame every 5s, each received frame pokes the
// watchdog, and prolonged silence forces a reconnect.
func (c *GRPCClient) receiveCommands(ctx context.Context, stream v1.IngestionService_EventStreamClient) {
	// Buffered so a frame arriving while the watchdog isn't selecting is not lost
	// and Recv never blocks on the poke.
	activity := make(chan recvSignal, 1)
	go c.runRecvWatchdog(ctx, activity)

	for {
		cmd, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				slog.Info("command stream closed by server")
			} else {
				slog.Warn("command stream error", "error", err)
			}
			// Receiving ended → the stream is dead. Force a reconnect so the
			// command channel is re-established (don't rely solely on the
			// connection-level state, which stays READY on a half-open stream).
			c.signalDisconnect()
			return
		}

		// Any frame proves the downstream half of the stream is live; poke the
		// watchdog (non-blocking). A keepalive carries no command oneof — flag it, and
		// latch server-keepalive capability so every later stream arms from open.
		isKeepalive := cmd.GetCommand() == nil
		if isKeepalive {
			c.serverKeepalive.Store(true)
		}
		select {
		case activity <- recvSignal{keepalive: isKeepalive}:
		default:
		}

		internalCmd := convertServerCommand(cmd)
		if internalCmd == nil {
			// Keepalive ping (no command oneof set) or an unrecognized command —
			// nothing to execute. Liveness is already recorded above.
			continue
		}
		slog.Info("サーバコマンドを受信しました", "command_id", internalCmd.CommandID, "type", internalCmd.Type)
		if c.onCommand != nil {
			c.onCommand(internalCmd)
		}
	}
}

// recvSignal is one downstream frame observed by receiveCommands. keepalive marks
// the server's no-oneof liveness ping (vs a real command). Both reset the watchdog
// deadline and arm it (see runRecvWatchdog).
type recvSignal struct {
	keepalive bool
}

// runRecvWatchdog forces a reconnect when the downstream (server→agent) half of
// the event stream falls silent for recvTimeout. It is the receive-direction twin
// of sendWithWatchdog: gRPC keepalive answers at the HTTP/2 layer and
// conn.GetState() stays READY on an application-level half-open, so neither
// detects a server that stopped writing. The server's 5s keepalive frame (see
// ingestion handler.go) makes real silence — not idleness — the only thing that
// trips this.
//
// Arming is gated on knowing the server actually sends keepalives, so an older
// server that never sends them cannot cause false flapping. But that capability is
// learned out-of-band via the unary Heartbeat reply header (c.serverKeepalive),
// which keeps working even when the bidi stream is half-open — so the watchdog
// arms from stream-open even when NO keepalive ever reaches this stream. That is
// the critical case the previous "arm only after the first keepalive frame" gate
// missed: a downstream half-open from birth (hairpin NAT) never delivers a frame,
// so frame-gated arming stayed disarmed forever and the bug persisted. Receiving a
// keepalive also arms it, covering the window before the first heartbeat lands.
//
// Returns when ctx (the connection scope) is cancelled on reconnect, or after it
// has signalled a disconnect itself.
func (c *GRPCClient) runRecvWatchdog(ctx context.Context, activity <-chan recvSignal) {
	timeout := c.recvTimeout
	if timeout <= 0 {
		timeout = defaultRecvTimeout
	}

	// The timer always runs so the capability latch is re-checked every timeout even
	// on a stream that never delivers a frame (half-open from birth). Arming is
	// expressed purely through c.serverKeepalive, not a local flag, so a real
	// command on an older (non-keepalive) server can never be mistaken for a reason
	// to enforce silence.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	resetDeadline := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(timeout)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-activity:
			// A frame arrived (keepalive or real command) → the downstream is alive;
			// defer the deadline. Keepalive frames also set the latch in receiveCommands.
			resetDeadline()
		case <-timer.C:
			if c.serverKeepalive.Load() {
				// We know the server sends keepalives, yet the deadline elapsed with
				// no frame → half-open downstream (possibly from birth). Reconnect.
				slog.Warn("受信ストリームが無音です — 半開きと判断して再接続します", "timeout", timeout)
				c.signalDisconnect()
				return
			}
			// Capability not yet known (older server, or the first heartbeat hasn't
			// landed). Keep polling without reconnecting so we never flap on idleness.
			resetDeadline()
		}
	}
}

// convertServerCommand converts a proto ServerCommand to internal ServerCommand.
func convertServerCommand(cmd *v1.ServerCommand) *ServerCommand {
	if cmd == nil {
		return nil
	}

	internal := &ServerCommand{
		CommandID: cmd.GetCommandId(),
	}

	switch cmd.Command.(type) {
	case *v1.ServerCommand_Isolate:
		internal.Type = CmdIsolate
		ic := cmd.GetIsolate()
		internal.Payload = response.IsolateCmd{
			CommandID:  cmd.GetCommandId(),
			Reason:     ic.GetReason(),
			AlertID:    ic.GetAlertId(),
			AllowedIPs: ic.GetAllowIps(),
		}
	case *v1.ServerCommand_Unisolate:
		internal.Type = CmdUnisolate
		uc := cmd.GetUnisolate()
		internal.Payload = response.UnisolateCmd{
			CommandID: cmd.GetCommandId(),
			Reason:    uc.GetReason(),
		}
	case *v1.ServerCommand_KillProcess:
		internal.Type = CmdKillProcess
		kp := cmd.GetKillProcess()
		internal.Payload = response.KillProcessCmd{
			CommandID:   cmd.GetCommandId(),
			PID:         kp.GetPid(),
			ProcessName: kp.GetProcessName(),
			Reason:      kp.GetReason(),
		}
	case *v1.ServerCommand_QuarantineFile:
		internal.Type = CmdQuarantineFile
		qf := cmd.GetQuarantineFile()
		internal.Payload = response.QuarantineFileCmd{
			CommandID: cmd.GetCommandId(),
			Path:      fixWindowsPath(qf.GetPath()),
			Reason:    qf.GetReason(),
			AlertID:   qf.GetAlertId(),
		}
	case *v1.ServerCommand_RestoreFile:
		internal.Type = CmdRestoreFile
		rf := cmd.GetRestoreFile()
		internal.Payload = response.RestoreFileCmd{
			CommandID:    cmd.GetCommandId(),
			QuarantineID: rf.GetQuarantineId(),
			RestorePath:  fixWindowsPath(rf.GetRestorePath()),
		}
	case *v1.ServerCommand_ReloadConfig:
		internal.Type = CmdReloadConfig

	case *v1.ServerCommand_Scan:
		internal.Type = CmdScan
		sc := cmd.GetScan()
		internal.Payload = ScanCmd{
			CommandID: cmd.GetCommandId(),
			ScanType:  sc.GetType().String(),
			Target:    sc.GetTarget(),
		}

	case *v1.ServerCommand_CollectArtifact:
		ca := cmd.GetCollectArtifact()
		target := ca.GetTarget()
		// Live response sessions are delivered via CollectArtifact(type=LOGS)
		// with the target field containing LiveResponseStartPayload JSON.
		if ca.GetType() == v1.CollectArtifactCommand_ARTIFACT_TYPE_LOGS {
			if strings.Contains(target, `"live_response"`) {
				var payload response.LiveResponseStartPayload
				if err := json.Unmarshal([]byte(target), &payload); err == nil && payload.Type == "live_response" {
					internal.Type = CmdLiveResponseStart
					internal.Payload = payload
					return internal
				}
			}
		}
		// Forensics jobs are delivered via CollectArtifact with the target
		// field containing a ForensicsJobPayload JSON (type="forensics_job").
		if strings.Contains(target, `"forensics_job"`) {
			var payload ForensicsJobPayload
			if err := json.Unmarshal([]byte(target), &payload); err == nil && payload.Type == "forensics_job" {
				internal.Type = CmdForensicsJob
				internal.Payload = payload
				return internal
			}
		}
		// Certificate renewal commands carry {"type":"cert_renew","renewal_token":"..."}.
		if strings.Contains(target, `"cert_renew"`) {
			var p struct {
				Type         string `json:"type"`
				RenewalToken string `json:"renewal_token"`
			}
			if err := json.Unmarshal([]byte(target), &p); err == nil && p.Type == "cert_renew" {
				internal.Type = CmdCertRenew
				internal.Payload = CertRenewCmd{
					CommandID:    cmd.GetCommandId(),
					RenewalToken: p.RenewalToken,
				}
				return internal
			}
		}
		// Policy pushes ride the same tunnel with ARTIFACT_TYPE_UNSPECIFIED as the
		// sentinel. They carry no "type" marker — the server's payload has never
		// had one, whatever ingestion's comment says — so identify them by the
		// field only a policy has: policy_id.
		if ca.GetType() == v1.CollectArtifactCommand_ARTIFACT_TYPE_UNSPECIFIED {
			var p ApplyPolicyCmd
			if err := json.Unmarshal([]byte(target), &p); err == nil && p.PolicyID != "" {
				p.CommandID = cmd.GetCommandId()
				internal.Type = CmdApplyPolicy
				internal.Payload = p
				return internal
			}
		}
		internal.Type = CmdCollectArtifact

	default:
		return nil
	}

	return internal
}

// stableConnThreshold is how long a connection must survive before we treat it as
// healthy and reset the reconnect backoff. A session that dies sooner is churn — a
// hairpin-NAT reset, or a half-open caught immediately by the watchdogs — so we
// back off before redialing instead of hot-looping. Without this, conn Close +
// watchdog-driven reconnect can spin into a reconnect storm (observed ~50 conn/s)
// that spawns orphan server-side EventStream handlers faster than they retire.
const stableConnThreshold = 30 * time.Second

// RunWithReconnect maintains a persistent connection with exponential backoff.
// It also drains the offline buffer on reconnection.
func (c *GRPCClient) RunWithReconnect(ctx context.Context) {
	backoff := &exponentialBackoff{min: 5 * time.Second, max: 5 * time.Minute}

	// backoffSleep waits one backoff step, returning false if ctx is cancelled.
	backoffSleep := func(msg string, err error) bool {
		wait := backoff.Next()
		slog.Warn(msg, "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
			return true
		}
	}

	// closeConn tears down the current conn/stream (idempotent). Closing fully drops
	// the old TCP/HTTP2 so the server promptly retires the orphaned EventStream
	// handler instead of leaving it to compete for this agent's command queue, and
	// avoids leaking a *grpc.ClientConn on every reconnect.
	closeConn := func() {
		c.mu.Lock()
		c.connected = false
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()
		c.streamMu.Lock()
		c.stream = nil
		c.streamMu.Unlock()
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Create a connection-scoped context; cancel on disconnect.
		connCtx, connCancel := context.WithCancel(ctx)
		c.mu.Lock()
		c.connCancel = connCancel
		c.mu.Unlock()

		if err := c.Connect(connCtx); err != nil {
			connCancel()
			if !backoffSleep("connection failed, retrying", err) {
				return
			}
			continue
		}

		// Open bidirectional stream
		if err := c.openStream(connCtx); err != nil {
			connCancel()
			closeConn() // drop the dialed-but-unusable conn before backing off
			if !backoffSleep("failed to open event stream", err) {
				return
			}
			continue
		}

		// The connection is operational from here; time its lifetime so we only
		// reset the backoff for a session that actually held up (see below).
		connStart := time.Now()

		// Drain offline buffer
		if c.buffer.Len() > 0 {
			slog.Info("draining offline buffer", "events", c.buffer.Len())
			c.drainBuffer(connCtx)
		}

		// Block until connection drops
		c.waitForDisconnect(connCtx)
		connCancel()
		closeConn()

		// Reset the backoff only if the connection was stable long enough; otherwise
		// keep escalating so repeated short-lived connects (a half-open caught at
		// once, or a NAT that resets every dial) ramp the delay instead of storming.
		if lasted := time.Since(connStart); lasted >= stableConnThreshold {
			backoff.Reset()
			slog.Warn("connection lost, reconnecting...")
		} else {
			wait := backoff.Next()
			slog.Warn("short-lived connection, backing off before reconnect",
				"lasted", lasted.Round(time.Millisecond), "retry_in", wait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

// sendWithWatchdog runs send() under sendMu, bounding it with sendTimeout.
//
// gRPC's stream.Send() returns nil as long as the batch fits the HTTP/2
// flow-control window and only returns an error once the stream is definitively
// broken. When the server stops *reading* the stream but the connection and gRPC
// keepalive stay healthy (application-level half-open — e.g. a server restart that
// orphaned the stream, or an ingest stall), Send fills the window and then blocks
// forever. Neither receiveCommands' Recv (no EOF), waitForDisconnect's GetState
// (stays READY), nor keepalive (answered by the gRPC layer) detects this, so the
// live-send and drain paths wedge while the unary heartbeat keeps the agent
// "online" — detection silently dies with no visible failure.
//
// On timeout we force a reconnect: signalDisconnect cancels the connection scope,
// which cancels the stream context and unblocks the wedged Send with an error. We
// wait for the send goroutine to return before releasing sendMu so the next caller
// never races a still-running Send on the same stream (Send is not concurrency-safe).
func (c *GRPCClient) sendWithWatchdog(send func() error) error {
	timeout := c.sendTimeout
	if timeout <= 0 {
		timeout = defaultSendTimeout
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	done := make(chan error, 1)
	go func() { done <- send() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		slog.Warn("stream send timed out — treating as half-open stream, reconnecting",
			"timeout", timeout)
		c.signalDisconnect() // cancels stream ctx → unblocks the wedged Send
		<-done               // wait for Send to actually return before releasing sendMu
		return fmt.Errorf("stream send timeout after %s (half-open stream)", timeout)
	}
}

// batchPlatform maps runtime.GOOS onto the wire enum. Unknown platforms stay
// UNSPECIFIED, which the server treats as "unknown OS" and fails OPEN — every rule
// is evaluated. That is the safe direction: a rare cross-OS false positive beats
// silently dropping detections on a platform we failed to name.
func batchPlatform() v1.Platform {
	switch runtime.GOOS {
	case "windows":
		return v1.Platform_PLATFORM_WINDOWS
	case "linux":
		return v1.Platform_PLATFORM_LINUX
	case "darwin":
		return v1.Platform_PLATFORM_DARWIN
	default:
		return v1.Platform_PLATFORM_UNSPECIFIED
	}
}

// SendEvents sends a batch of events. Falls back to buffer if disconnected.
//
// Stamps EventBatch.Platform here rather than at each construction site. Every
// collector builds its own batch (a dozen call sites across cmd/agent and
// internal/collector) and NOT ONE of them set this field — no assignment to
// Platform_PLATFORM_* existed anywhere in agent/. The server derives the event's
// `platform` from it (ingestion/handler.go platformString), so it was always
// "unknown", and the detection server's OS gate — added in #356 precisely to stop
// cross-OS false positives — fell through its fail-open branch for every event
// ever sent. The gate has been a no-op in production since the day it shipped.
// Observed 2026-07-02: "Local System Accounts Discovery - Linux" firing on a
// Windows host's `net user`.
//
// This is also the single choke point for the offline path: bufferBatch is only
// reachable from inside this function, so buffered-then-replayed batches carry the
// stamp too.
func (c *GRPCClient) SendEvents(ctx context.Context, batch *v1.EventBatch) error {
	if batch != nil && batch.GetPlatform() == v1.Platform_PLATFORM_UNSPECIFIED {
		batch.Platform = batchPlatform()
	}
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return c.bufferBatch(batch)
	}

	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream == nil {
		return c.bufferBatch(batch)
	}

	if err := c.sendWithWatchdog(func() error { return stream.Send(batch) }); err != nil {
		// The stream is dead — either a plain Send error (commonly EOF when the
		// server closed only the stream) or a watchdog timeout (half-open: server
		// stopped reading). Force a reconnect — otherwise we would buffer forever
		// and never receive server commands again. signalDisconnect is idempotent,
		// so calling it here after the watchdog already did is harmless. Then buffer.
		slog.Warn("stream send failed, reconnecting & buffering", "error", err)
		c.signalDisconnect()
		return c.bufferBatch(batch)
	}
	return nil
}

// bufferBatch serializes a proto EventBatch with protojson and writes it to the ring buffer.
func (c *GRPCClient) bufferBatch(batch *v1.EventBatch) error {
	data, err := protojson.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch for buffer: %w", err)
	}
	return c.buffer.Write(data)
}

// SendHeartbeat implements heartbeat.HeartbeatSender.
func (c *GRPCClient) SendHeartbeat(ctx context.Context, req *heartbeat.HeartbeatRequest) (*heartbeat.HeartbeatResponse, error) {
	c.mu.RLock()
	client := c.ingestionClient
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected")
	}

	status := v1.HeartbeatRequest_AGENT_STATUS_ONLINE
	switch req.Status {
	case "isolated":
		status = v1.HeartbeatRequest_AGENT_STATUS_ISOLATED
	case "error":
		status = v1.HeartbeatRequest_AGENT_STATUS_ERROR
	}

	protoReq := &v1.HeartbeatRequest{
		AgentId:        req.AgentID,
		AgentVersion:   req.AgentVersion,
		IpAddresses:    req.IPAddresses,
		EventsBuffered: uint64(req.EventsBuffered),
		CpuUsage:       req.CPUUsage,
		MemoryUsageMb:  req.MemoryUsageMB,
		Status:         status,
		ConfigVersion:  req.ConfigVersion,
		Hostname:       req.Hostname,
		OsVersion:      req.OSVersion,
	}

	// Also pass os_version as gRPC metadata so the server can read it
	// even if the proto descriptor hasn't been regenerated yet.
	if req.OSVersion != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-os-version", req.OSVersion)
	}
	// os_type has no proto field on HeartbeatRequest at all, so metadata is the only
	// channel. Without it the server falls back to a default and a Windows host that
	// was auto-created from a heartbeat is displayed as Linux forever.
	if req.OSType != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-os-type", req.OSType)
	}
	// Protection mode (enforce/observe/poll) travels as metadata too, avoiding a
	// proto regen for a single string field (same pattern as os_version).
	if req.ProtectionMode != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-protection-mode", req.ProtectionMode)
	}
	// Effective collection mode (ebpf/poll/off) — same metadata trick. Distinct
	// from protection mode: that one is host capability, this one is what the
	// collectors actually ended up running on.
	if req.TelemetryMode != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-telemetry-mode", req.TelemetryMode)
	}

	// Capture the response header: a keepalive-capable server stamps x-edr-keepalive.
	// Heartbeat is a unary RPC on its own HTTP/2 stream, so this reply lands even
	// when the bidi EventStream is half-open — that is what lets the receive watchdog
	// arm from stream-open and catch a downstream half-open from birth (see
	// runRecvWatchdog / serverKeepalive).
	var respHeader metadata.MD
	resp, err := client.Heartbeat(ctx, protoReq, grpc.Header(&respHeader))
	if err != nil {
		return nil, err
	}
	if vals := respHeader.Get("x-edr-keepalive"); len(vals) > 0 && vals[0] == "1" {
		c.serverKeepalive.Store(true)
	}

	return &heartbeat.HeartbeatResponse{
		ConfigUpdateAvailable: resp.GetConfigUpdateAvailable(),
		LatestConfigVersion:   resp.GetLatestConfigVersion(),
		PendingCommandCount:   len(resp.GetPendingCommands()),
	}, nil
}

// IsConnected returns the current connection state.
func (c *GRPCClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Close gracefully shuts down the connection.
func (c *GRPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Reconnect closes the current gRPC connection so RunWithReconnect re-dials
// with whatever credentials are currently on disk. Call this after writing a
// renewed certificate with RenewCertificate().
func (c *GRPCClient) Reconnect() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		// Closing the conn causes waitForDisconnect to observe SHUTDOWN and
		// return, which causes RunWithReconnect to loop and re-dial with the
		// new cert that RenewCertificate() wrote to disk.
		_ = conn.Close()
	}
}

// ─── Enrollment ───────────────────────────────────────────────

// EnrollRequest contains data for initial enrollment.
type EnrollRequest struct {
	Token     string
	Hostname  string
	OSType    string
	OSVersion string
	IPs       []string
	CSR       string
}

// EnrollResponse contains data returned from enrollment.
type EnrollResponse struct {
	AgentID    string
	SignedCert string
	CACert     string
}

// Enroll registers this agent with the server using a one-time enrollment token.
func (c *GRPCClient) Enroll(ctx context.Context, req *EnrollRequest) (*EnrollResponse, error) {
	// Build a temporary insecure connection for enrollment (server cert only, no mTLS)
	serverAddr := fmt.Sprintf("%s:%d",
		extractHost(c.cfg.Server.URL),
		c.cfg.Server.GRPCPort,
	)

	// Use insecure connection when no CA cert is configured (TLS_ENABLED=false)
	var dialCreds grpc.DialOption
	if c.cfg.Server.CACert == "" {
		slog.Info("CA証明書未設定 — 平文gRPCで登録")
		dialCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		caCert, err := os.ReadFile(c.cfg.Server.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("parse CA cert")
		}
		tlsCfg := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}
		dialCreds = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}

	// 登録はサーバ不達なら早く失敗させる。接続できていないのに
	// 「登録処理を続行」してしまうと、原因が分かりにくい。
	conn, err := dialBlocking(ctx, serverAddr, 30*time.Second, dialCreds)
	if err != nil {
		return nil, fmt.Errorf("enrollment dial: %w", err)
	}
	defer conn.Close()

	client := v1.NewIngestionServiceClient(conn)
	resp, err := client.Enroll(ctx, &v1.EnrollRequest{
		EnrollmentToken: req.Token,
		Hostname:        req.Hostname,
		OsType:          req.OSType,
		OsVersion:       req.OSVersion,
		IpAddresses:     req.IPs,
		Csr:             req.CSR,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll rpc: %w", err)
	}

	return &EnrollResponse{
		AgentID:    resp.GetAgentId(),
		SignedCert: resp.GetSignedCert(),
		CACert:     resp.GetCaCert(),
	}, nil
}

// RenewCertificate generates a fresh RSA key + CSR, calls Enroll with the
// one-time renewal token, and atomically saves the new cert and key to the
// paths configured in Server.ClientCert / Server.ClientKey.
// The caller should schedule a reconnect after this returns nil.
func (c *GRPCClient) RenewCertificate(ctx context.Context, renewalToken string) error {
	c.mu.RLock()
	cfg := c.cfg
	c.mu.RUnlock()

	// Generate new RSA-2048 key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("RSA鍵の生成に失敗しました: %w", err)
	}

	// Build CSR with the agent ID as CN (same as initial enrollment).
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cfg.Agent.ID,
			Organization: []string{"EDR Agent"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return fmt.Errorf("CSRの生成に失敗しました: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// Enroll with "renew:<token>" so the server validates it as a renewal.
	resp, err := c.Enroll(ctx, &EnrollRequest{
		Token:    "renew:" + renewalToken,
		Hostname: cfg.Agent.Hostname,
		CSR:      csrPEM,
	})
	if err != nil {
		return fmt.Errorf("renewal Enroll RPC失敗: %w", err)
	}

	// Encode private key as PKCS8 PEM.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("秘密鍵のエンコードに失敗しました: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Write new cert and key atomically (write to temp, then rename).
	if err := atomicWrite(cfg.Server.ClientCert, []byte(resp.SignedCert), 0600); err != nil {
		return fmt.Errorf("証明書の保存に失敗しました: %w", err)
	}
	if err := atomicWrite(cfg.Server.ClientKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("秘密鍵の保存に失敗しました: %w", err)
	}

	slog.Info("mTLS証明書を更新しました",
		"agent_id", resp.AgentID,
		"cert_path", cfg.Server.ClientCert,
	)
	return nil
}

// atomicWrite writes data to path by writing a temp file then renaming it.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cert-renew-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// ─── Internal helpers ─────────────────────────────────────────

func (c *GRPCClient) buildTLSConfig() (*tls.Config, error) {
	// Load client certificate (for mTLS)
	cert, err := tls.LoadX509KeyPair(c.cfg.Server.ClientCert, c.cfg.Server.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	// Load CA certificate (for server cert verification + pinning)
	caCert, err := os.ReadFile(c.cfg.Server.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	// Certificate pinning: if CertPins is configured, verify the server's leaf
	// certificate SPKI fingerprint against the pinset after normal TLS validation.
	if len(c.cfg.Server.CertPins) > 0 {
		pins := c.cfg.Server.CertPins
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("cert pin: no server certificate presented")
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			got := base64.StdEncoding.EncodeToString(sum[:])
			for _, pin := range pins {
				if got == pin {
					return nil
				}
			}
			slog.Error("証明書ピン留め検証に失敗しました",
				"fingerprint", got,
				"expected", pins,
			)
			return fmt.Errorf("cert pin: server certificate fingerprint %q not in pinset", got)
		}
	}

	return tlsCfg, nil
}

func (c *GRPCClient) drainBuffer(ctx context.Context) {
	const batchSize = 50
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rawBatch, err := c.buffer.ReadBatch(batchSize)
		if err != nil || len(rawBatch) == 0 {
			return
		}

		for _, raw := range rawBatch {
			var batch v1.EventBatch
			if err := protojson.Unmarshal(raw, &batch); err != nil {
				// Incompatible format (e.g. events buffered before a proto schema change).
				// Discard immediately so they don't repeat on the next reconnect.
				slog.Info("discarding buffered event with incompatible format", "error", err)
				c.buffer.Ack(1)
				continue
			}

			c.streamMu.Lock()
			stream := c.stream
			c.streamMu.Unlock()

			if stream == nil {
				return
			}
			// Bound the drain send too: on a half-open stream this would otherwise
			// block forever and the offline backlog would never drain (observed:
			// buffer stuck at the size cap for days). On timeout sendWithWatchdog
			// forces a reconnect; we stop draining and the batch stays buffered.
			// sendWithWatchdog joins the send goroutine before returning, so passing
			// &batch (a loop-local) is safe — it never outlives this iteration.
			if err := c.sendWithWatchdog(func() error { return stream.Send(&batch) }); err != nil {
				slog.Warn("drain send failed", "error", err)
				return
			}
			c.buffer.Ack(1)
		}

		if len(rawBatch) < batchSize {
			return // drained
		}
	}
}

func (c *GRPCClient) waitForDisconnect(ctx context.Context) {
	if c.conn == nil {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state := c.conn.GetState()
			if state.String() == "TRANSIENT_FAILURE" || state.String() == "SHUTDOWN" {
				return
			}
		}
	}
}

func extractHost(rawURL string) string {
	// Strip scheme (e.g. "http://")
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
	}
	// Strip path
	if i := strings.Index(rawURL, "/"); i >= 0 {
		rawURL = rawURL[:i]
	}
	// Strip port (keep only hostname)
	if i := strings.LastIndex(rawURL, ":"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return rawURL
}

// ─── Exponential Backoff ──────────────────────────────────────

type exponentialBackoff struct {
	min     time.Duration
	max     time.Duration
	attempt int
}

func (b *exponentialBackoff) Next() time.Duration {
	d := time.Duration(float64(b.min) * math.Pow(2, float64(b.attempt)))
	if d > b.max {
		d = b.max
	}
	b.attempt++
	return d
}

func (b *exponentialBackoff) Reset() {
	b.attempt = 0
}

// fixWindowsPath restores Windows paths that were corrupted during JSON transit.
// When the server sends a path with a single backslash in JSON (e.g. "C:\temp"),
// JSON parsers interpret \t as TAB (0x09), \n as newline, etc.
// This function reverses that corruption so the path is usable on Windows.
func fixWindowsPath(p string) string {
	return strings.NewReplacer(
		"\t", `\t`, // TAB (0x09) ← was \t in the original path (C:\temp)
		"\n", `\n`, // newline (0x0A) ← was \n in path
		"\r", `\r`, // CR (0x0D) ← was \r in path
		"\f", `\f`, // form-feed (0x0C) ← was \f in path
		"\b", `\b`, // backspace (0x08) ← was \b in path
	).Replace(p)
}
