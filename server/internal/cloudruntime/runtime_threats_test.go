package cloudruntime

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DetectRuntimeThreats has four branches and none of them could fire.
//
// It selected event_type IN ('container_event', 'process', 'container_process').
// Two of those three are values events_event_type_check does not permit, so no
// row can ever hold them; only 'process' could match — which is correct, because
// a container's processes arrive as ordinary process events.
//
// On that one working type the keys were wrong anyway:
//
//	cmdline       -> command_line     crypto-miner and container-escape branches
//	privileged    -> not collected    privileged-container branch
//	host_network  -> not collected    host-network branch
//	container_id  -> not collected    "containers monitored" was always 0
//
// So the crypto-miner and escape rules were one rename away from working the
// whole time, and the two container-property rules had no telemetry at all.
// Containment is kernel state, so the endpoint answers it from /proc without a
// runtime API (agent/internal/collector/container.go).

func runtimePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedProcessEvent writes one process event for a throwaway agent and returns
// the agent id.
func seedProcessEvent(t *testing.T, pool *pgxpool.Pool, rawJSON string) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'runtime-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO events (time, agent_id, event_type, raw_data)
		 VALUES (NOW() - INTERVAL '5 minutes', $1::uuid, 'process', $2::jsonb)`,
		agentID, rawJSON); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	return agentID
}

func threatFor(threats []*RuntimeThreat, agentID string) *RuntimeThreat {
	for _, th := range threats {
		if th.AgentID == agentID {
			return th
		}
	}
	return nil
}

const fixtureContainerID = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

// Each branch, one test. All four are seeded as ordinary process events,
// because that is what a container's processes actually are.
func TestEveryRuntimeThreatBranchFires(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{
			"crypto miner by process name",
			`{"process_name":"xmrig","command_line":"./xmrig -o pool:3333",
			  "container_id":"` + fixtureContainerID + `","privileged":false,"host_network":false}`,
		},
		{
			"crypto miner by command line",
			`{"process_name":"httpd","command_line":"curl x | sh -c stratum+tcp://pool:3333",
			  "container_id":"` + fixtureContainerID + `","privileged":false,"host_network":false}`,
		},
		{
			"container escape via /proc/1/root",
			`{"process_name":"sh","command_line":"chroot /proc/1/root /bin/bash",
			  "container_id":"` + fixtureContainerID + `","privileged":false,"host_network":false}`,
		},
		{
			"shell in a privileged container",
			`{"process_name":"bash","command_line":"bash",
			  "container_id":"` + fixtureContainerID + `","privileged":true,"host_network":false}`,
		},
		{
			"unusual process on host network",
			`{"process_name":"nmap","command_line":"nmap -sS 10.0.0.0/24",
			  "container_id":"` + fixtureContainerID + `","privileged":false,"host_network":true}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := runtimePool(t)
			agentID := seedProcessEvent(t, pool, tc.raw)

			threats, err := NewMonitor(pool).DetectRuntimeThreats(context.Background(), 24)
			if err != nil {
				t.Fatalf("DetectRuntimeThreats: %v", err)
			}
			th := threatFor(threats, agentID)
			if th == nil {
				t.Fatalf("%s が検出されていません (検出総数 %d)。"+
					"存在し得ない event_type と誤ったキー名のため、"+
					"この検知は一度も発火していません", tc.name, len(threats))
			}
			if th.ContainerID != fixtureContainerID {
				t.Errorf("コンテナIDが取れていません: %q。"+
					"どのコンテナで起きたか分からない検知になります", th.ContainerID)
			}
		})
	}
}

// Ordinary container activity must not be reported, so the tests above cannot
// be passing by flagging every process event.
func TestOrdinaryContainerActivityIsNotAThreat(t *testing.T) {
	pool := runtimePool(t)
	agentID := seedProcessEvent(t, pool,
		`{"process_name":"nginx","command_line":"nginx -g daemon off;",
		  "container_id":"`+fixtureContainerID+`","privileged":false,"host_network":false}`)

	threats, err := NewMonitor(pool).DetectRuntimeThreats(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectRuntimeThreats: %v", err)
	}
	if th := threatFor(threats, agentID); th != nil {
		t.Errorf("通常のコンテナ活動を脅威として報告しています: %+v", *th)
	}
}

// A host process with no containment keys must not be swept into the
// privileged or host-network branches — those read a missing key, and a
// COALESCE to false is what keeps that from matching.
func TestAHostProcessIsNotSweptIn(t *testing.T) {
	pool := runtimePool(t)
	agentID := seedProcessEvent(t, pool,
		`{"process_name":"bash","command_line":"bash"}`)

	threats, err := NewMonitor(pool).DetectRuntimeThreats(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectRuntimeThreats: %v", err)
	}
	if th := threatFor(threats, agentID); th != nil {
		t.Errorf("コンテナ外のシェル起動を脅威として報告しています: %+v", *th)
	}
}

// "Containers monitored" counts distinct container IDs and was always 0.
func TestContainersMonitoredCountsRealContainers(t *testing.T) {
	pool := runtimePool(t)
	m := NewMonitor(pool)

	before := m.GetRuntimeStats(context.Background()).ContainersMonitored
	seedProcessEvent(t, pool,
		`{"process_name":"nginx","command_line":"nginx",
		  "container_id":"`+fixtureContainerID+`","privileged":false,"host_network":false}`)
	after := m.GetRuntimeStats(context.Background()).ContainersMonitored

	if after <= before {
		t.Errorf("監視対象コンテナ数が増えていません (%d -> %d)。"+
			"container_id を収集していなかったため、この値は常に 0 でした",
			before, after)
	}
}
