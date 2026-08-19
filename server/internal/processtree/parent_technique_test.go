package processtree

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// suspiciousParentChild is a table of parent→child pairs that identify a
// technique: winword.exe spawning powershell.exe is T1566.001, explorer.exe
// spawning cmd.exe is T1059.003, and so on. It is the only place this codebase
// detects a technique from process lineage.
//
// It could not match. mitreFromParentChild(parentName, childName) was called
// with a parentName read from raw_data->>'parent_name', and ProcessEvent
// carried no parent under that or any other name — pid and ppid were all it
// had. So the parent was empty on every node ever built, the map lookup missed
// every time, and not one of these techniques has ever been reported.
//
// The agent resolves the parent on the endpoint now, while it is still alive.
// These tests build a tree from rows shaped exactly as ingestion writes them
// and assert the technique comes out.

func treePool(t *testing.T) *pgxpool.Pool {
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

// seedLineage writes a parent and a child process event for a throwaway agent,
// in the shape ingestion produces.
func seedLineage(t *testing.T, pool *pgxpool.Pool, parentName, childName string, withParentKey bool) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'lineage-fixture','windows','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	ins := func(raw string) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO events (time, agent_id, event_type, raw_data)
			 VALUES (NOW() - INTERVAL '5 minutes', $1::uuid, 'process', $2::jsonb)`,
			agentID, raw); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	ins(`{"pid":"4242","ppid":"1","process_name":"` + parentName + `","image_path":"C:\\` + parentName + `"}`)

	child := `{"pid":"4243","ppid":"4242","process_name":"` + childName + `"`
	if withParentKey {
		child += `,"parent_name":"` + parentName + `","parent_image":"C:\\` + parentName + `"`
	}
	child += `}`
	ins(child)

	return agentID
}

func findNode(t *testing.T, tree *ProcessTree, pid int) *ProcessNode {
	t.Helper()
	var walk func(nodes []*ProcessNode) *ProcessNode
	walk = func(nodes []*ProcessNode) *ProcessNode {
		for _, n := range nodes {
			if n.PID == pid {
				return n
			}
			if found := walk(n.Children); found != nil {
				return found
			}
		}
		return nil
	}
	return walk(tree.Roots)
}

// The headline: Office spawning PowerShell is reported as T1566.001.
func TestOfficeSpawningPowerShellIsReportedAsATechnique(t *testing.T) {
	pool := treePool(t)
	agentID := seedLineage(t, pool, "winword.exe", "powershell.exe", true)

	tree, err := NewBuilder(pool).BuildTree(context.Background(), agentID, 24)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	child := findNode(t, tree, 4243)
	if child == nil {
		t.Fatal("子プロセスがツリーに現れませんでした")
	}
	if child.ParentName != "winword.exe" {
		t.Errorf("親プロセス名 = %q, want winword.exe。"+
			"raw_data.parent_name が読めていません", child.ParentName)
	}
	if child.MITRETech != "T1566.001" {
		t.Errorf("MITRE テクニック = %q, want T1566.001。"+
			"親が空だと suspiciousParentChild は一度も一致しません", child.MITRETech)
	}
	if !child.Suspicious {
		t.Error("親子関係で検出されたのに suspicious が立っていません")
	}
}

// And it works when the parent's own row is NOT in the window — which is the
// case the stored key exists for, and the one the pidMap fallback cannot cover.
//
// Without this the previous test passes even with the parent_name projection
// removed: the fallback finds the parent among the sibling rows and supplies
// the name, so one path silently covers for the other being broken. A parent
// that started before the query window is exactly what the endpoint resolution
// buys, so that is what this asserts.
func TestAParentOutsideTheWindowIsStillNamed(t *testing.T) {
	pool := treePool(t)
	ctx := context.Background()

	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'lineage-orphan-fixture','windows','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// Only the child. winword.exe started days ago and its create event is long
	// out of the window — the ordinary case for a long-running parent.
	if _, err := pool.Exec(ctx,
		`INSERT INTO events (time, agent_id, event_type, raw_data)
		 VALUES (NOW() - INTERVAL '5 minutes', $1::uuid, 'process',
		 '{"pid":"4243","ppid":"4242","process_name":"powershell.exe",
		   "parent_name":"winword.exe","parent_image":"C:\\winword.exe"}'::jsonb)`,
		agentID); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	tree, err := NewBuilder(pool).BuildTree(ctx, agentID, 24)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	child := findNode(t, tree, 4243)
	if child == nil {
		t.Fatal("子プロセスがツリーに現れませんでした")
	}
	if child.ParentName != "winword.exe" {
		t.Errorf("親プロセス名 = %q, want winword.exe。"+
			"親の行が窓の外にある場合、raw_data.parent_name しか手掛かりがありません — "+
			"pidMap のフォールバックでは補えない、まさにこのためのキーです",
			child.ParentName)
	}
	if child.MITRETech != "T1566.001" {
		t.Errorf("MITRE テクニック = %q, want T1566.001", child.MITRETech)
	}
}

// An ordinary lineage stays clean, so the assertion above cannot be passing by
// marking everything suspicious.
func TestAnOrdinaryLineageIsNotFlagged(t *testing.T) {
	pool := treePool(t)
	agentID := seedLineage(t, pool, "explorer.exe", "notepad.exe", true)

	tree, err := NewBuilder(pool).BuildTree(context.Background(), agentID, 24)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	child := findNode(t, tree, 4243)
	if child == nil {
		t.Fatal("子プロセスがツリーに現れませんでした")
	}
	if child.MITRETech != "" {
		t.Errorf("通常の親子関係に %q が付きました", child.MITRETech)
	}
}

// Events written by an older agent carry no parent key. The tree still names
// the parent from the other rows in the window, so the technique is not lost
// during a fleet upgrade.
func TestAnOlderAgentsEventsStillResolveWithinTheWindow(t *testing.T) {
	pool := treePool(t)
	agentID := seedLineage(t, pool, "winword.exe", "powershell.exe", false)

	tree, err := NewBuilder(pool).BuildTree(context.Background(), agentID, 24)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	child := findNode(t, tree, 4243)
	if child == nil {
		t.Fatal("子プロセスがツリーに現れませんでした")
	}
	if child.ParentName != "winword.exe" {
		t.Errorf("親プロセス名 = %q, want winword.exe。"+
			"parent_name を持たない旧エージェントのイベントでは、"+
			"同じ結果セット内の親の行から解決するフォールバックが必要です",
			child.ParentName)
	}
	if child.MITRETech != "T1566.001" {
		t.Errorf("MITRE テクニック = %q, want T1566.001", child.MITRETech)
	}
}
