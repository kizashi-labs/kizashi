package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NetworkTopologyHandler struct{ pool *pgxpool.Pool }

func NewNetworkTopologyHandler(pool *pgxpool.Pool) *NetworkTopologyHandler {
	return &NetworkTopologyHandler{pool: pool}
}

func (h *NetworkTopologyHandler) GetTopology(c *gin.Context) {
	// Nodes
	nodeRows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, COALESCE(agent_id::text,''), node_type, name, ip_addresses::text[],
		       COALESCE(os_info,''), COALESCE(department,''), criticality, x_pos, y_pos, last_seen, created_at
		FROM network_topology_nodes ORDER BY name
	`)
	if err != nil {
		ReadFailure(c, err, gin.H{"nodes": []any{}, "edges": []any{}})
		return
	}
	defer nodeRows.Close()

	type Node struct {
		ID          string   `json:"id"`
		AgentID     string   `json:"agent_id"`
		NodeType    string   `json:"node_type"`
		Name        string   `json:"name"`
		IPAddresses []string `json:"ip_addresses"`
		OSInfo      string   `json:"os_info"`
		Department  string   `json:"department"`
		Criticality string   `json:"criticality"`
		X           float64  `json:"x"`
		Y           float64  `json:"y"`
		LastSeen    *string  `json:"last_seen"`
		CreatedAt   string   `json:"created_at"`
	}

	var nodes []Node
	for nodeRows.Next() {
		var n Node
		var lastSeen *time.Time
		var createdAt time.Time
		if err := nodeRows.Scan(&n.ID, &n.AgentID, &n.NodeType, &n.Name, &n.IPAddresses,
			&n.OSInfo, &n.Department, &n.Criticality, &n.X, &n.Y, &lastSeen, &createdAt); err != nil {
			continue
		}
		n.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if lastSeen != nil {
			s := lastSeen.UTC().Format(time.RFC3339)
			n.LastSeen = &s
		}
		nodes = append(nodes, n)
	}
	if err := nodeRows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		ReadFailure(c, err, gin.H{"nodes": []any{}, "edges": []any{}})
		return
	}
	if nodes == nil {
		nodes = []Node{}
	}

	// Edges
	edgeRows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, source_node_id, target_node_id, edge_type, COALESCE(protocol,''), COALESCE(port::text,''),
		       bytes_sent, bytes_received
		FROM network_topology_edges
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": []any{}})
		return
	}
	defer edgeRows.Close()

	type Edge struct {
		ID            string `json:"id"`
		SourceNodeID  string `json:"source_node_id"`
		TargetNodeID  string `json:"target_node_id"`
		EdgeType      string `json:"edge_type"`
		Protocol      string `json:"protocol"`
		Port          string `json:"port"`
		BytesSent     int64  `json:"bytes_sent"`
		BytesReceived int64  `json:"bytes_received"`
	}
	var edges []Edge
	for edgeRows.Next() {
		var e Edge
		if err := edgeRows.Scan(&e.ID, &e.SourceNodeID, &e.TargetNodeID, &e.EdgeType,
			&e.Protocol, &e.Port, &e.BytesSent, &e.BytesReceived); err != nil {
			continue
		}
		edges = append(edges, e)
	}
	if err := edgeRows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if edges == nil {
		edges = []Edge{}
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

func (h *NetworkTopologyHandler) Stats(c *gin.Context) {
	var total, endpoints, servers, critical int
	if err := h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE node_type='endpoint'),
		       COUNT(*) FILTER (WHERE node_type='server'),
		       COUNT(*) FILTER (WHERE criticality='critical')
		FROM network_topology_nodes
	`).Scan(&total, &endpoints, &servers, &critical); err != nil {
		slog.Warn("network topology: 集計クエリに失敗しました", "error", err)
	}
	var edgeCount int
	if err := h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM network_topology_edges`).Scan(&edgeCount); err != nil {
		slog.Warn("network topology: 集計クエリに失敗しました", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"total_nodes":    total,
		"endpoints":      endpoints,
		"servers":        servers,
		"critical_nodes": critical,
		"total_edges":    edgeCount,
	})
}
