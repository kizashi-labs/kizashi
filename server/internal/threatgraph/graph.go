package threatgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detection"
)

// NodeType represents the type of a graph node
type NodeType string

const (
	NodeProcess NodeType = "process"
	NodeFile    NodeType = "file"
	NodeNetwork NodeType = "network"
	NodeUser    NodeType = "user"
	NodeAlert   NodeType = "alert"
	NodeAgent   NodeType = "agent"
)

// EdgeType represents the relationship between nodes
type EdgeType string

const (
	EdgeSpawned     EdgeType = "spawned"      // process spawned process
	EdgeAccessed    EdgeType = "accessed"     // process accessed file
	EdgeConnected   EdgeType = "connected"    // process connected to network
	EdgeTriggered   EdgeType = "triggered"    // process triggered alert
	EdgeRunAs       EdgeType = "run_as"       // process ran as user
	EdgeModified    EdgeType = "modified"     // process modified file
	EdgeLoaded      EdgeType = "loaded"       // process loaded file (DLL)
	EdgeDNSResolved EdgeType = "dns_resolved" // process resolved DNS
)

// Node represents a node in the threat graph
type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties"`
	RiskScore  int                    `json:"risk_score"`
	Timestamp  time.Time              `json:"timestamp"`
	AgentID    string                 `json:"agent_id,omitempty"`
}

// Edge represents a relationship between two nodes
type Edge struct {
	ID         string                 `json:"id"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       EdgeType               `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// Graph is an in-memory threat graph with DB persistence
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string]*Edge
	// adjacency: nodeID -> list of edge IDs
	outgoing map[string][]string
	incoming map[string][]string
	pool     *pgxpool.Pool
}

// GraphQuery is a query for subgraph extraction
type GraphQuery struct {
	RootNodeID string   `json:"root_node_id"`
	Depth      int      `json:"depth"`      // max traversal depth
	NodeTypes  []string `json:"node_types"` // filter node types
	AgentID    string   `json:"agent_id,omitempty"`
	Since      string   `json:"since,omitempty"` // RFC3339
}

// SubGraph is a portion of the graph
type SubGraph struct {
	Nodes    []*Node `json:"nodes"`
	Edges    []*Edge `json:"edges"`
	RootID   string  `json:"root_id"`
	MaxDepth int     `json:"max_depth"`
}

// NewGraph creates a new Graph
func NewGraph(pool *pgxpool.Pool) *Graph {
	return &Graph{
		nodes:    make(map[string]*Node),
		edges:    make(map[string]*Edge),
		outgoing: make(map[string][]string),
		incoming: make(map[string][]string),
		pool:     pool,
	}
}

// AddNode adds or updates a node
func (g *Graph) AddNode(n *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.nodes[n.ID]; !exists {
		g.outgoing[n.ID] = []string{}
		g.incoming[n.ID] = []string{}
	}
	g.nodes[n.ID] = n
}

// AddEdge adds an edge between two nodes
func (g *Graph) AddEdge(e *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[e.ID] = e
	g.outgoing[e.Source] = append(g.outgoing[e.Source], e.ID)
	g.incoming[e.Target] = append(g.incoming[e.Target], e.ID)
}

// GetSubGraph extracts a subgraph around a root node up to the given depth using BFS
func (g *Graph) GetSubGraph(q *GraphQuery) *SubGraph {
	g.mu.RLock()
	defer g.mu.RUnlock()

	depth := q.Depth
	if depth <= 0 {
		depth = 3
	}
	if depth > 6 {
		depth = 6
	}

	visited := map[string]bool{}
	queue := []struct {
		id    string
		level int
	}{{q.RootNodeID, 0}}

	nodeSet := map[string]*Node{}
	edgeSet := map[string]*Edge{}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		if visited[curr.id] || curr.level > depth {
			continue
		}
		visited[curr.id] = true

		n, ok := g.nodes[curr.id]
		if !ok {
			continue
		}
		nodeSet[curr.id] = n

		// Traverse outgoing edges
		for _, eid := range g.outgoing[curr.id] {
			e, ok := g.edges[eid]
			if !ok {
				continue
			}
			edgeSet[eid] = e
			if !visited[e.Target] {
				queue = append(queue, struct {
					id    string
					level int
				}{e.Target, curr.level + 1})
			}
		}
		// Traverse incoming edges
		for _, eid := range g.incoming[curr.id] {
			e, ok := g.edges[eid]
			if !ok {
				continue
			}
			edgeSet[eid] = e
			if !visited[e.Source] {
				queue = append(queue, struct {
					id    string
					level int
				}{e.Source, curr.level + 1})
			}
		}
	}

	nodes := make([]*Node, 0, len(nodeSet))
	for _, n := range nodeSet {
		nodes = append(nodes, n)
	}
	edges := make([]*Edge, 0, len(edgeSet))
	for _, e := range edgeSet {
		edges = append(edges, e)
	}

	return &SubGraph{
		Nodes:    nodes,
		Edges:    edges,
		RootID:   q.RootNodeID,
		MaxDepth: depth,
	}
}

// graphEventLimit bounds one build. Named so the truncation is visible: beyond
// this many events the graph is a prefix of the window, not the whole of it.
const graphEventLimit = 5000

// firstString returns the first of keys present in data with a non-empty string
// form.
//
// The graph is assembled from events.raw_data, which internal/ingestion writes
// from the proto payloads. Several of the names this package read are not names
// ingestion produces, and a missing key in a map yields nil rather than an
// error, so the graph rendered with the fields simply absent. firstString makes
// the accepted spellings explicit at each site.
func firstString(data map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := data[k]
		if !ok || v == nil {
			continue
		}
		if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

// processHash returns the strongest hash present. Ingestion writes sha256/sha1/
// md5 as separate keys (addHashes); nothing writes "hash", which is what this
// package used to read, so every process and file node carried hash=<nil>.
func processHash(data map[string]interface{}) string {
	return firstString(data, "sha256", "sha1", "md5", "hash")
}

// BuildFromEvents constructs graph nodes/edges from raw events in DB
func (g *Graph) BuildFromEvents(ctx context.Context, agentID string, since time.Time) error {
	rows, err := g.pool.Query(ctx, `
        SELECT e.event_id::text, e.agent_id::text, e.event_type, e.time, e.raw_data,
               COALESCE(a.hostname, e.agent_id::text)
        FROM events e
        LEFT JOIN agents a ON a.id = e.agent_id
        WHERE ($1::text = '' OR e.agent_id::text = $1)
          AND e.time >= $2
        ORDER BY e.time ASC
        LIMIT $3
    `, agentID, since, graphEventLimit)
	if err != nil {
		return fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var eventID, evtAgentID, eventType, hostname string
		var ts time.Time
		var rawData []byte
		if err := rows.Scan(&eventID, &evtAgentID, &eventType, &ts, &rawData, &hostname); err != nil {
			continue
		}

		var data map[string]interface{}
		_ = json.Unmarshal(rawData, &data)

		agentNode := &Node{
			ID:        "agent:" + evtAgentID,
			Type:      NodeAgent,
			Label:     hostname,
			Timestamp: ts,
			AgentID:   evtAgentID,
			Properties: map[string]interface{}{
				"hostname": hostname,
			},
		}
		g.AddNode(agentNode)

		switch eventType {
		case "process":
			processNode := buildProcessNode(eventID, evtAgentID, ts, data)
			g.AddNode(processNode)
			g.AddEdge(&Edge{
				ID:        "e:agent-proc:" + eventID,
				Source:    agentNode.ID,
				Target:    processNode.ID,
				Type:      EdgeSpawned,
				Timestamp: ts,
			})

			// Parent-child relationship
			if ppid, ok := data["ppid"]; ok {
				parentID := fmt.Sprintf("process:%s:pid:%v", evtAgentID, ppid)
				g.AddEdge(&Edge{
					ID:        "e:parent:" + eventID,
					Source:    parentID,
					Target:    processNode.ID,
					Type:      EdgeSpawned,
					Timestamp: ts,
				})
			}

		case "network":
			netNode := buildNetworkNode(eventID, evtAgentID, ts, data)
			g.AddNode(netNode)

			if pid, ok := data["pid"]; ok {
				procID := fmt.Sprintf("process:%s:pid:%v", evtAgentID, pid)
				g.AddEdge(&Edge{
					ID:        "e:net:" + eventID,
					Source:    procID,
					Target:    netNode.ID,
					Type:      EdgeConnected,
					Timestamp: ts,
				})
			}

		case "file":
			// A file event with no path cannot be a node: every one of them would
			// share the id "file:<agent>:unknown", so the graph would fold all file
			// activity on the host into a single vertex and show every process
			// touching the same imaginary file.
			fileNode := buildFileNode(eventID, evtAgentID, ts, data)
			if fileNode == nil {
				continue
			}
			g.AddNode(fileNode)

			if pid, ok := data["pid"]; ok {
				procID := fmt.Sprintf("process:%s:pid:%v", evtAgentID, pid)
				edgeType := EdgeAccessed
				if detection.IsDestructiveFileAction(firstString(data, "operation", "action")) {
					edgeType = EdgeModified
				}
				g.AddEdge(&Edge{
					ID:        "e:file:" + eventID,
					Source:    procID,
					Target:    fileNode.ID,
					Type:      edgeType,
					Timestamp: ts,
				})
			}

		case "dns":
			// Ingestion writes the looked-up name as "query"; "domain" is a name
			// nothing produces, so no DNS node had ever been created and the
			// dns_resolved edge type was unreachable.
			if domain := firstString(data, "query", "domain"); domain != "" {
				props := map[string]interface{}{
					"domain": domain,
					"type":   "dns",
				}
				if answers, ok := data["answers"]; ok && answers != nil {
					props["answers"] = answers
				}
				if qt := firstString(data, "query_type"); qt != "" {
					props["query_type"] = qt
				}
				dnsNode := &Node{
					ID:         "network:dns:" + domain,
					Type:       NodeNetwork,
					Label:      domain,
					Timestamp:  ts,
					AgentID:    evtAgentID,
					Properties: props,
				}
				g.AddNode(dnsNode)
				if pid, ok := data["pid"]; ok {
					procID := fmt.Sprintf("process:%s:pid:%v", evtAgentID, pid)
					g.AddEdge(&Edge{
						ID:        "e:dns:" + eventID,
						Source:    procID,
						Target:    dnsNode.ID,
						Type:      EdgeDNSResolved,
						Timestamp: ts,
					})
				}
			}
		}
	}
	return rows.Err()
}

// Stats returns graph statistics
func (g *Graph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	typeCounts := map[string]int{}
	for _, n := range g.nodes {
		typeCounts[string(n.Type)]++
	}
	typeCounts["total_nodes"] = len(g.nodes)
	typeCounts["total_edges"] = len(g.edges)
	return typeCounts
}

// NodeCount returns the total number of nodes
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// GetNode retrieves a node by ID
func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// SearchNodes searches nodes by label or property substring
func (g *Graph) SearchNodes(query string, maxResults int) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if maxResults <= 0 {
		maxResults = 50
	}
	var results []*Node
	for _, n := range g.nodes {
		if len(results) >= maxResults {
			break
		}
		if containsCI(n.Label, query) {
			results = append(results, n)
			continue
		}
		for _, v := range n.Properties {
			if s, ok := v.(string); ok && containsCI(s, query) {
				results = append(results, n)
				break
			}
		}
	}
	return results
}

// buildProcessNode reads the names internal/ingestion writes for a process
// event. It read "cmdline" and "hash", neither of which ingestion produces
// (they are "command_line" and sha256/sha1/md5), so every process in the graph
// showed a name and nothing else — no command line, no binary, no hash. Those
// three are most of what an analyst opens a process node to see.
func buildProcessNode(eventID, agentID string, ts time.Time, data map[string]interface{}) *Node {
	pid := fmt.Sprintf("%v", data["pid"])
	label := firstString(data, "process_name", "image_path", "image")
	if label == "" {
		label = "unknown"
	}
	props := map[string]interface{}{
		"pid":      pid,
		"event_id": eventID,
	}
	for key, value := range map[string]string{
		"process_name": firstString(data, "process_name"),
		"image_path":   firstString(data, "image_path", "image"),
		"cmdline":      firstString(data, "command_line", "cmdline"),
		"hash":         processHash(data),
		"user":         firstString(data, "username", "user"),
	} {
		if value != "" {
			props[key] = value
		}
	}
	return &Node{
		ID:         fmt.Sprintf("process:%s:pid:%v", agentID, pid),
		Type:       NodeProcess,
		Label:      label,
		Timestamp:  ts,
		AgentID:    agentID,
		Properties: props,
	}
}

func buildNetworkNode(eventID, agentID string, ts time.Time, data map[string]interface{}) *Node {
	dst := fmt.Sprintf("%v:%v", data["dst_ip"], data["dst_port"])
	return &Node{
		ID:        "network:" + agentID + ":" + dst,
		Type:      NodeNetwork,
		Label:     dst,
		Timestamp: ts,
		AgentID:   agentID,
		Properties: map[string]interface{}{
			"src_ip":   data["src_ip"],
			"dst_ip":   data["dst_ip"],
			"dst_port": data["dst_port"],
			"protocol": data["protocol"],
			"event_id": eventID,
		},
	}
}

// buildFileNode reads the names internal/ingestion writes for a file event, and
// returns nil when there is no path.
//
// It read "file_path". Ingestion writes "path" (and "old_path" for a rename),
// so the path was always absent and every file node was built with the literal
// id "file:<agent>:unknown". Node ids are the graph's identity, so all file
// activity on an agent collapsed into one vertex: two different files touched
// by one process produced two edges pointing at the same node, and the graph
// asserted a relationship that does not exist.
func buildFileNode(eventID, agentID string, ts time.Time, data map[string]interface{}) *Node {
	path := firstString(data, "path", "file_path", "target_path", "old_path")
	if path == "" {
		return nil
	}
	props := map[string]interface{}{
		"file_path": path,
		"event_id":  eventID,
	}
	if op := firstString(data, "operation", "action"); op != "" {
		props["operation"] = op
	}
	if h := processHash(data); h != "" {
		props["hash"] = h
	}
	return &Node{
		ID:         "file:" + agentID + ":" + path,
		Type:       NodeFile,
		Label:      path,
		Timestamp:  ts,
		AgentID:    agentID,
		Properties: props,
	}
}

func containsCI(s, sub string) bool {
	if sub == "" {
		return true
	}
	sl := len(s)
	subl := len(sub)
	if subl > sl {
		return false
	}
	for i := 0; i <= sl-subl; i++ {
		match := true
		for j := 0; j < subl; j++ {
			cs := s[i+j]
			cp := sub[j]
			if cs >= 'A' && cs <= 'Z' {
				cs += 32
			}
			if cp >= 'A' && cp <= 'Z' {
				cp += 32
			}
			if cs != cp {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
