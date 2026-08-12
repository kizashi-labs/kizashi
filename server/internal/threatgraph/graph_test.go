package threatgraph

import (
	"fmt"
	"testing"
	"time"
)

func TestAddNodeAndEdge(t *testing.T) {
	g := NewGraph(nil)

	n1 := &Node{ID: "n1", Type: NodeProcess, Label: "cmd.exe", Timestamp: time.Now()}
	n2 := &Node{ID: "n2", Type: NodeFile, Label: "malware.exe", Timestamp: time.Now()}
	g.AddNode(n1)
	g.AddNode(n2)

	e1 := &Edge{ID: "e1", Source: "n1", Target: "n2", Type: EdgeAccessed, Timestamp: time.Now()}
	g.AddEdge(e1)

	if g.NodeCount() != 2 {
		t.Errorf("expected 2 nodes, got %d", g.NodeCount())
	}

	n, ok := g.GetNode("n1")
	if !ok {
		t.Fatal("node n1 not found")
	}
	if n.Label != "cmd.exe" {
		t.Errorf("expected label cmd.exe, got %s", n.Label)
	}
}

func TestGetSubGraph(t *testing.T) {
	g := NewGraph(nil)

	// Build a chain: n1 -> n2 -> n3 -> n4
	now := time.Now()
	for i := 1; i <= 4; i++ {
		g.AddNode(&Node{ID: fmt.Sprintf("n%d", i), Type: NodeProcess, Label: fmt.Sprintf("proc%d", i), Timestamp: now})
	}
	for i := 1; i <= 3; i++ {
		g.AddEdge(&Edge{
			ID:        fmt.Sprintf("e%d", i),
			Source:    fmt.Sprintf("n%d", i),
			Target:    fmt.Sprintf("n%d", i+1),
			Type:      EdgeSpawned,
			Timestamp: now,
		})
	}

	// Query depth=2 from n1: should get n1, n2, n3 (not n4)
	sub := g.GetSubGraph(&GraphQuery{RootNodeID: "n1", Depth: 2})
	if len(sub.Nodes) != 3 {
		t.Errorf("expected 3 nodes at depth 2, got %d", len(sub.Nodes))
	}
}

func TestSearchNodes(t *testing.T) {
	g := NewGraph(nil)
	g.AddNode(&Node{ID: "n1", Type: NodeProcess, Label: "mimikatz.exe", Timestamp: time.Now()})
	g.AddNode(&Node{ID: "n2", Type: NodeProcess, Label: "explorer.exe", Timestamp: time.Now()})
	g.AddNode(&Node{ID: "n3", Type: NodeFile, Label: "C:\\Windows\\System32\\cmd.exe", Timestamp: time.Now()})

	results := g.SearchNodes("mimi", 10)
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'mimi', got %d", len(results))
	}

	results2 := g.SearchNodes("exe", 10)
	if len(results2) != 3 {
		t.Errorf("expected 3 results for 'exe', got %d", len(results2))
	}
}

func TestContainsCI(t *testing.T) {
	if !containsCI("MimiKatz.exe", "mimikatz") {
		t.Error("case insensitive match failed")
	}
	if containsCI("explorer.exe", "mimikatz") {
		t.Error("non-match should return false")
	}
}
