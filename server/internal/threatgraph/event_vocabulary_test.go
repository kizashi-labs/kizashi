package threatgraph

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The threat graph is assembled from events.raw_data, which internal/ingestion
// writes from the proto payloads. Several of the names this package read are
// names ingestion does not produce, and a missing key in a JSON map is nil
// rather than an error, so the graph rendered — plausibly — with the facts
// missing. Reproduced against the payloads normalizeEventData actually emits,
// five events in, four nodes out:
//
//	file:<agent>:unknown       both files, folded into ONE node, because the
//	                           path was read as "file_path" and written as
//	                           "path". Two edges pointed at the same vertex.
//	process ... cmdline:<nil>  read as "cmdline"/"hash"; written as
//	           hash:<nil>      "command_line" and sha256/sha1/md5.
//	(no dns node at all)       read as "domain"; written as "query". The
//	                           dns_resolved edge type was unreachable.
//	edge type "accessed"       for a FILE_ACTION_DELETE, because the action was
//	                           compared against "write"/"create"/"delete" and
//	                           ingestion writes the proto enum name.
//
// A graph that silently drops the command line, the hash, the resolved domain
// and the distinction between reading and destroying a file is not a weaker
// graph — it is one that answers an analyst's question wrongly. The single
// merged file node is the worst of them: it asserts a relationship between
// files that were never related.
//
// The fixtures are dated well into the past on purpose. Test packages run
// concurrently against one database, and several of them scan `events` over
// 24-hour and 30-day windows; fixtures at NOW() break those packages. An
// earlier version of this file did exactly that.
//
// Mutation-tested at 16 mutations, 15 killed. The survivor is the rows.Err()
// return added to BuildFromEvents: pgx sets it on a mid-iteration failure,
// which a SELECT over a handful of local rows will not produce, so no test here
// can distinguish its presence. It is recorded rather than covered by a test
// that only appears to check it.

// ingestionEvent is one event exactly as normalizeEventData writes it.
type ingestionEvent struct {
	typ  string
	data map[string]interface{}
}

func graphPool(t *testing.T) *pgxpool.Pool {
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

// graphFixtureBase is the timestamp the fixtures are anchored at: far enough
// back that no other package's rolling window sees them.
var graphFixtureBase = time.Now().Add(-400 * 24 * time.Hour)

// seedGraphEvents writes the events and returns the agent id.
func seedGraphEvents(t *testing.T, pool *pgxpool.Pool, events []ingestionEvent) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'threatgraph-fixture','windows','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	for i, e := range events {
		raw, err := json.Marshal(e.data)
		if err != nil {
			t.Fatalf("marshal %s: %v", e.typ, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO events (time, agent_id, event_type, raw_data) VALUES ($1,$2::uuid,$3,$4)`,
			graphFixtureBase.Add(time.Duration(i)*time.Second), agentID, e.typ, raw); err != nil {
			t.Fatalf("seed %s event: %v", e.typ, err)
		}
	}
	return agentID
}

// buildGraph runs the real build over the seeded events.
func buildGraph(t *testing.T, pool *pgxpool.Pool, agentID string) *Graph {
	t.Helper()
	g := NewGraph(pool)
	if err := g.BuildFromEvents(context.Background(), agentID, graphFixtureBase.Add(-time.Hour)); err != nil {
		t.Fatalf("BuildFromEvents: %v", err)
	}
	return g
}

// nodesOfType returns the built nodes of one type.
func nodesOfType(g *Graph, typ NodeType) []*Node {
	var out []*Node
	for _, n := range g.nodes {
		if n.Type == typ {
			out = append(out, n)
		}
	}
	return out
}

// edgesOfType returns the built edges of one type.
func edgesOfType(g *Graph, typ EdgeType) []*Edge {
	var out []*Edge
	for _, e := range g.edges {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// intrusionEvents is one small intrusion, in ingestion's own vocabulary.
func intrusionEvents() []ingestionEvent {
	return []ingestionEvent{
		{"process", map[string]interface{}{
			"process_name": "powershell.exe", "pid": 4242, "ppid": 1000,
			"command_line": `powershell -enc SQBFAFgAaQBuAHYAbwBrAGUA`,
			"image_path":   `C:\Windows\System32\powershell.exe`,
			"username":     "CORP\\alice", "action": "PROCESS_ACTION_START",
			"sha256": "a1b2c3d4e5f6",
		}},
		{"file", map[string]interface{}{
			"path": `C:\Users\alice\report.docx`, "operation": "FILE_ACTION_MODIFY",
			"process_name": "powershell.exe", "pid": 4242, "sha256": "def456",
		}},
		{"file", map[string]interface{}{
			"path": `C:\Users\alice\notes.txt`, "operation": "FILE_ACTION_DELETE",
			"process_name": "powershell.exe", "pid": 4242,
		}},
		{"file", map[string]interface{}{
			"path": `C:\Users\alice\readme.md`, "operation": "FILE_ACTION_OPEN",
			"process_name": "powershell.exe", "pid": 4242,
		}},
		{"dns", map[string]interface{}{
			"query": "evil-c2.example.com", "query_type": "A",
			"answers": []string{"203.0.113.9"}, "process_name": "powershell.exe", "pid": 4242,
		}},
		{"network", map[string]interface{}{
			"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 443,
			"protocol": "tcp", "pid": 4242, "process_name": "powershell.exe",
		}},
	}
}

// TestEachFileTouchedIsItsOwnNode is the core gate.
func TestEachFileTouchedIsItsOwnNode(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	files := nodesOfType(g, NodeFile)
	if len(files) != 3 {
		labels := make([]string, 0, len(files))
		for _, f := range files {
			labels = append(labels, f.Label)
		}
		t.Fatalf("%d file node(s) for three distinct files: %v\nThe path is read "+
			"under a name ingestion does not write, so every file event produced "+
			"the same id and the graph folded unrelated files into one vertex.",
			len(files), labels)
	}

	want := map[string]bool{
		`C:\Users\alice\report.docx`: false,
		`C:\Users\alice\notes.txt`:   false,
		`C:\Users\alice\readme.md`:   false,
	}
	for _, f := range files {
		if _, ok := want[f.Label]; !ok {
			t.Errorf("unexpected file node %q", f.Label)
			continue
		}
		want[f.Label] = true
		if p, _ := f.Properties["file_path"].(string); p != f.Label {
			t.Errorf("file node %q carries file_path=%v", f.Label, f.Properties["file_path"])
		}
	}
	for path, seen := range want {
		if !seen {
			t.Errorf("no node for %s", path)
		}
	}
}

// TestAFileEventWithNoPathIsNotANode is the floor for the above: the fix must
// not be "invent a placeholder path", which is how one shared node arose.
func TestAFileEventWithNoPathIsNotANode(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, []ingestionEvent{
		{"file", map[string]interface{}{"operation": "FILE_ACTION_MODIFY", "pid": 4242}},
		{"file", map[string]interface{}{"operation": "FILE_ACTION_DELETE", "pid": 4242}},
	})
	g := buildGraph(t, pool, agentID)

	if files := nodesOfType(g, NodeFile); len(files) != 0 {
		t.Errorf("%d file node(s) from events that carry no path: %v", len(files), files[0].ID)
	}
}

// TestDestroyingAFileIsNotTheSameAsReadingIt.
func TestDestroyingAFileIsNotTheSameAsReadingIt(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	modified := edgesOfType(g, EdgeModified)
	if len(modified) != 2 {
		t.Errorf("%d modified edge(s), want 2 (a MODIFY and a DELETE). The action "+
			"is compared against literals ingestion never writes — it writes the "+
			"proto enum name, e.g. FILE_ACTION_MODIFY — so a process destroying "+
			"files looks exactly like one reading them.", len(modified))
	}
	if accessed := edgesOfType(g, EdgeAccessed); len(accessed) != 1 {
		t.Errorf("%d accessed edge(s), want 1 (the OPEN)", len(accessed))
	}
}

// TestADNSLookupBecomesANode. The dns_resolved edge type existed and could
// never be produced.
func TestADNSLookupBecomesANode(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	n, ok := g.GetNode("network:dns:evil-c2.example.com")
	if !ok {
		t.Fatal("no node for the domain the process looked up. The lookup is read " +
			"under a name ingestion does not write, so no DNS activity has ever " +
			"appeared in the graph.")
	}
	if n.Properties["answers"] == nil {
		t.Error("the resolved address is missing, so nothing connects the domain to " +
			"the outbound connection that follows it")
	}
	if len(edgesOfType(g, EdgeDNSResolved)) != 1 {
		t.Error("no dns_resolved edge from the process that made the lookup")
	}
}

// TestAProcessNodeCarriesWhatAnAnalystOpensItFor.
func TestAProcessNodeCarriesWhatAnAnalystOpensItFor(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	procs := nodesOfType(g, NodeProcess)
	if len(procs) != 1 {
		t.Fatalf("%d process node(s), want 1", len(procs))
	}
	p := procs[0]

	for key, want := range map[string]string{
		"cmdline":      `powershell -enc SQBFAFgAaQBuAHYAbwBrAGUA`,
		"image_path":   `C:\Windows\System32\powershell.exe`,
		"hash":         "a1b2c3d4e5f6",
		"user":         "CORP\\alice",
		"process_name": "powershell.exe",
	} {
		got, _ := p.Properties[key].(string)
		if got != want {
			t.Errorf("process node %s = %q, want %q", key, got, want)
		}
	}
}

// TestAbsentFieldsAreAbsentRatherThanEmpty. The symptom that made this defect
// visible was a process node carrying hash=<nil> and cmdline=<nil>: keys the
// builder emitted unconditionally from a map that did not have them. A node
// that says hash="" is making a claim; a node with no hash key is not.
func TestAbsentFieldsAreAbsentRatherThanEmpty(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, []ingestionEvent{
		// A process event with no hash, no command line and no user — the shape a
		// short-lived process on a Linux agent produces.
		{"process", map[string]interface{}{
			"process_name": "sh", "pid": 77, "action": "PROCESS_ACTION_START",
		}},
		{"file", map[string]interface{}{
			"path": "/tmp/x", "operation": "FILE_ACTION_OPEN", "pid": 77,
		}},
	})
	g := buildGraph(t, pool, agentID)

	procs := nodesOfType(g, NodeProcess)
	if len(procs) != 1 {
		t.Fatalf("%d process node(s), want 1", len(procs))
	}
	for _, key := range []string{"hash", "cmdline", "user", "image_path"} {
		if v, ok := procs[0].Properties[key]; ok {
			t.Errorf("process node carries %s=%v for an event that has no such field", key, v)
		}
	}

	files := nodesOfType(g, NodeFile)
	if len(files) != 1 {
		t.Fatalf("%d file node(s), want 1", len(files))
	}
	if v, ok := files[0].Properties["hash"]; ok {
		t.Errorf("file node carries hash=%v for an event that has no hash", v)
	}
}

// TestTheNetworkNodeStillWorks. Network was the one event type whose names
// already matched; a change to the shared readers must not break it.
func TestTheNetworkNodeStillWorks(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	var found *Node
	for _, n := range nodesOfType(g, NodeNetwork) {
		if n.Label == "203.0.113.9:443" {
			found = n
		}
	}
	if found == nil {
		t.Fatal("no node for the outbound connection")
	}
	if len(edgesOfType(g, EdgeConnected)) != 1 {
		t.Error("no connected edge from the process that opened it")
	}
}

// TestTheWholeIntrusionIsOneConnectedSubgraph is what the feature is for: from
// the process, an analyst must be able to reach the files it destroyed, the
// domain it resolved, and the address it connected to.
func TestTheWholeIntrusionIsOneConnectedSubgraph(t *testing.T) {
	pool := graphPool(t)
	agentID := seedGraphEvents(t, pool, intrusionEvents())
	g := buildGraph(t, pool, agentID)

	sub := g.GetSubGraph(&GraphQuery{
		RootNodeID: "process:" + agentID + ":pid:4242",
		Depth:      3,
	})

	labels := map[string]bool{}
	for _, n := range sub.Nodes {
		labels[n.Label] = true
	}
	for _, want := range []string{
		`C:\Users\alice\report.docx`,
		`C:\Users\alice\notes.txt`,
		"evil-c2.example.com",
		"203.0.113.9:443",
		"powershell.exe",
	} {
		if !labels[want] {
			t.Errorf("the subgraph rooted at the process does not reach %q", want)
		}
	}
}
