package ingestion

import (
	"context"
	"os"
	"testing"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/credentials/insecure"
)

// ─── Stubs for the AgentStore / CommandDispatcher interfaces ──────────────────
//
// The real store operates on ingestion's own record types, so the RPC handlers
// only need an in-memory stub that returns zero values. SignCSR returns a dummy
// non-empty cert so Enroll's happy path is reachable (parseCertNotAfter fails to
// PEM-decode the dummy and is handled best-effort, not fatally).

type covStubStore struct{}

func (covStubStore) UpsertAgent(ctx context.Context, agent *AgentRecord) error { return nil }
func (covStubStore) UpdateLastSeen(ctx context.Context, agentID, hostname string, ips []string, agentVersion, osVersion, osType string) error {
	return nil
}
func (covStubStore) UpdateProtectionMode(ctx context.Context, agentID, mode string) error { return nil }
func (covStubStore) UpdateTelemetryMode(ctx context.Context, agentID, mode string) error  { return nil }
func (covStubStore) UpdateMetrics(ctx context.Context, agentID string, cpu, memMB float64) error {
	return nil
}
func (covStubStore) ResolveAgentOfflineAlerts(ctx context.Context, agentID string) error { return nil }
func (covStubStore) GetAgentByID(ctx context.Context, id string) (*AgentRecord, error) {
	return &AgentRecord{ID: id, Hostname: "cov-host"}, nil
}
func (covStubStore) SignCSR(ctx context.Context, enrollToken, agentID, csr string) (string, string, error) {
	return "dummy-signed-cert", "dummy-ca-cert", nil
}
func (covStubStore) UpdateCertExpiry(ctx context.Context, agentID string, notAfter time.Time) error {
	return nil
}

type covStubDispatcher struct{}

func (covStubDispatcher) Enqueue(agentID string, cmd *Command) error { return nil }
func (covStubDispatcher) Dequeue(agentID string) ([]*Command, error) { return nil, nil }

// covServer wires a real DB pool + real NATS (for JetStream) into NewServer,
// skipping when either dependency is unavailable so pure-logic runs stay green.
func covServer(t *testing.T) (*Server, *pgxpool.Pool) {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping ingestion coverage tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		t.Skip("NATS_URL not set - skipping ingestion coverage tests")
	}
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Skipf("NATS connect failed (%v) - skipping", err)
	}
	t.Cleanup(nc.Close)

	// NewServer dereferences creds via grpc.Creds only in ListenAndServe (which we
	// never call), but pass insecure creds to be safe.
	srv := NewServer(covStubStore{}, pool, nc, covStubDispatcher{}, insecure.NewCredentials())
	return srv, pool
}

// seedAgent inserts a real agent row and returns its UUID (text), cleaning it up
// afterward. GetConfig/Heartbeat/Enroll requests use this id so their handlers
// run against a genuinely present row.
func seedAgent(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW())
		 RETURNING id::text`,
		"cov-ingest-"+time.Now().Format("150405.000000"),
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE agent_id = $1::uuid`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id = $1::uuid`, id)
	})
	return id
}

// TestCovIngestRPCs drives the reachable unary RPC handlers on *Server against a
// seeded DB + real NATS/JetStream, exercising their query/assembly bodies.
func TestCovIngestRPCs(t *testing.T) {
	srv, pool := covServer(t)
	agentID := seedAgent(t, pool)
	ctx := context.Background()

	// GetConfig — static assembly, but drives the ConfigRequest path.
	cfg, err := srv.GetConfig(ctx, &v1.ConfigRequest{AgentId: agentID, CurrentVersion: 0})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.GetVersion() == 0 || cfg.GetCollection() == nil {
		t.Fatalf("GetConfig returned empty config: %+v", cfg)
	}

	// Heartbeat — traverses the store update + offline-alert-resolve + protection
	// mode paths (stubbed store returns nil, so happy path).
	hbResp, err := srv.Heartbeat(ctx, &v1.HeartbeatRequest{
		AgentId:      agentID,
		Hostname:     "cov-host",
		AgentVersion: "1.2.3",
		OsVersion:    "6.1.0",
		IpAddresses:  []string{"10.0.0.5"},
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if hbResp == nil {
		t.Fatalf("Heartbeat returned nil response")
	}

	// Heartbeat again with empty hostname to exercise the hostname-cache fallback
	// branch (cache was populated by the first heartbeat).
	if _, err := srv.Heartbeat(ctx, &v1.HeartbeatRequest{AgentId: agentID}); err != nil {
		t.Fatalf("Heartbeat (cache fallback): %v", err)
	}

	// Enroll — signs the (stub) CSR, upserts the agent, parses cert expiry
	// best-effort, and caches the hostname. Stub SignCSR succeeds, so no error.
	enrollResp, err := srv.Enroll(ctx, &v1.EnrollRequest{
		EnrollmentToken: "cov-token",
		Hostname:        "cov-enroll-host",
		OsType:          "linux",
		OsVersion:       "6.1.0",
		AgentVersion:    "1.2.3",
		IpAddresses:     []string{"10.0.0.6"},
		Csr:             "-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollResp.GetAgentId() == "" || enrollResp.GetSignedCert() == "" {
		t.Fatalf("Enroll returned empty response: %+v", enrollResp)
	}

	// skipped: EventStream — bidi streaming RPC needs a mock stream server and
	// blocks on a 5s command ticker; its persistence body is driven below instead.

	// Drive publishEventBatch directly (in-package) to exercise the largest
	// non-RPC body: the multi-row INSERT into events + JetStream publish. This is
	// the persistence path the EventStream receive-goroutine runs per batch.
	batch := &v1.EventBatch{
		Platform: v1.Platform_PLATFORM_LINUX,
		Events: []*v1.Event{
			{
				Type: v1.EventType_EVENT_TYPE_PROCESS,
				Id:   "cov-evt-1",
				Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
					ProcessName: "bash",
					Pid:         4242,
					CommandLine: "bash -c id",
					Action:      v1.ProcessEvent_PROCESS_ACTION_CREATE,
				}},
			},
			{
				Type:    v1.EventType_EVENT_TYPE_DNS,
				Id:      "cov-evt-2",
				Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "example.com", QueryType: "A"}},
			},
		},
	}
	srv.publishEventBatch(ctx, agentID, batch)

	// Confirm at least one event landed in the DB for the seeded agent.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE agent_id = $1::uuid`, agentID).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected events persisted for agent %s, got 0", agentID)
	}
}
