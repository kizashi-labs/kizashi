package handlers

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// nodeCoord returns a deterministic coordinate for a node in [0, max).
// FNV-1a hash over the node ID + salt ensures consistent layout across requests.
func nodeCoord(id string, salt int, max float64) float64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	_, _ = h.Write([]byte{byte(salt)})
	return float64(h.Sum32()%uint32(max*100)) / 100.0
}

// NetworkMapHandler provides network topology and subnet data.
type NetworkMapHandler struct {
	pool *pgxpool.Pool
}

// NewNetworkMapHandler creates a new NetworkMapHandler.
func NewNetworkMapHandler(pool *pgxpool.Pool) *NetworkMapHandler {
	return &NetworkMapHandler{pool: pool}
}

// tableExistsNetMap checks whether a given table exists.
func tableExistsNetMap(pool *pgxpool.Pool, c *gin.Context, tableName string) bool {
	var exists bool
	err := pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)`, tableName).Scan(&exists)
	return err == nil && exists
}

type netNode struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	Type            string   `json:"type"`
	IPs             []string `json:"ip"`
	OS              string   `json:"os"`
	Status          string   `json:"status"`
	X               float64  `json:"x"`
	Y               float64  `json:"y"`
	LateralMovement bool     `json:"lateral_movement,omitempty"`
}

type netEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Count  int64  `json:"count"`
}

type subnetGroup struct {
	Subnet string   `json:"subnet"`
	Nodes  []string `json:"nodes"`
}

// GetTopology returns the full network topology: nodes, edges, and subnet groups.
// GET /api/v1/network/topology
func (h *NetworkMapHandler) GetTopology(c *gin.Context) {
	ctx := c.Request.Context()

	nodes := []netNode{}
	agentIPMap := map[string]string{} // ip -> agent_id

	if h.pool != nil && tableExistsNetMap(h.pool, c, "agents") {
		// agents の OS 列は `os_type` (migration 001)。`os` は存在せず、
		// このクエリは毎回失敗し、ネットワークマップにノードが 1 つも出なかった。
		rows, err := h.pool.Query(ctx,
			`SELECT id, hostname, ip_addresses, os_type, status FROM agents LIMIT 500`,
		)
		if err != nil {
			slog.Warn("network map: エージェント一覧の取得に失敗", "error", err)
		}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, hostname, osName, status string
				var ipAddresses []string
				if err := rows.Scan(&id, &hostname, &ipAddresses, &osName, &status); err != nil {
					continue
				}
				node := netNode{
					ID:     id,
					Label:  hostname,
					Type:   "agent",
					IPs:    ipAddresses,
					OS:     osName,
					Status: status,
					X:      nodeCoord(id, 0, 1000),
					Y:      nodeCoord(id, 1, 800),
				}
				nodes = append(nodes, node)
				for _, ip := range ipAddresses {
					agentIPMap[ip] = id
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}

	// Build edges from network_connections
	edges := []netEdge{}
	// Track connections per agent in last hour for lateral movement detection
	agentConnCount := map[string]map[string]bool{} // agent_id -> set of dst agent IDs

	if h.pool != nil && tableExistsNetMap(h.pool, c, "network_connections") {
		rows, err := h.pool.Query(ctx,
			`SELECT DISTINCT agent_id, dst_ip, COUNT(*) as connection_count
			 FROM network_connections
			 WHERE timestamp > NOW() - INTERVAL '24 hours'
			 GROUP BY agent_id, dst_ip
			 LIMIT 2000`,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var agentID, dstIP string
				var count int64
				if err := rows.Scan(&agentID, &dstIP, &count); err != nil {
					continue
				}
				dstAgentID, ok := agentIPMap[dstIP]
				if !ok {
					continue
				}
				edges = append(edges, netEdge{
					Source: agentID,
					Target: dstAgentID,
					Count:  count,
				})
				if _, exists := agentConnCount[agentID]; !exists {
					agentConnCount[agentID] = map[string]bool{}
				}
				agentConnCount[agentID][dstAgentID] = true
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}

		// Detect lateral movement: agents with >5 connections to other agents in last 1 hour
		lateralAgents := map[string]bool{}
		lmRows, err := h.pool.Query(ctx,
			`SELECT agent_id, COUNT(DISTINCT dst_ip) as peer_count
			 FROM network_connections
			 WHERE timestamp > NOW() - INTERVAL '1 hour'
			 GROUP BY agent_id
			 HAVING COUNT(DISTINCT dst_ip) > 5`,
		)
		if err == nil {
			defer lmRows.Close()
			for lmRows.Next() {
				var agentID string
				var peerCount int64
				if err := lmRows.Scan(&agentID, &peerCount); err != nil {
					continue
				}
				lateralAgents[agentID] = true
			}
			if err := lmRows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}

		// Apply lateral movement flag to nodes
		for i, node := range nodes {
			if lateralAgents[node.ID] {
				nodes[i].LateralMovement = true
			}
		}
	}

	// Build subnet groups
	subnetMap := map[string][]string{} // subnet -> []node_ids
	for _, node := range nodes {
		for _, ip := range node.IPs {
			subnet := ipToSubnet24(ip)
			if subnet != "" {
				subnetMap[subnet] = append(subnetMap[subnet], node.ID)
			}
		}
	}

	subnets := []subnetGroup{}
	for subnet, nodeIDs := range subnetMap {
		subnets = append(subnets, subnetGroup{
			Subnet: subnet,
			Nodes:  nodeIDs,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes":         nodes,
		"edges":         edges,
		"subnet_groups": subnets,
	})
}

// subnetAgent holds agent details for subnet listing.
type subnetAgent struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ip_addresses"`
	Status   string   `json:"status"`
}

// subnetResult holds a single subnet summary.
type subnetResult struct {
	Subnet     string        `json:"subnet"`
	AgentCount int           `json:"agent_count"`
	Agents     []subnetAgent `json:"agents"`
}

// GetSubnets groups agents by /24 subnet.
// GET /api/v1/network/subnets
func (h *NetworkMapHandler) GetSubnets(c *gin.Context) {
	ctx := c.Request.Context()

	subnetMap := map[string][]subnetAgent{}

	if h.pool != nil && tableExistsNetMap(h.pool, c, "agents") {
		rows, err := h.pool.Query(ctx,
			`SELECT id, hostname, ip_addresses, status FROM agents LIMIT 500`,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, hostname, status string
				var ips []string
				if err := rows.Scan(&id, &hostname, &ips, &status); err != nil {
					continue
				}
				agent := subnetAgent{
					ID:       id,
					Hostname: hostname,
					IPs:      ips,
					Status:   status,
				}
				seen := map[string]bool{}
				for _, ip := range ips {
					subnet := ipToSubnet24(ip)
					if subnet == "" || seen[subnet] {
						continue
					}
					seen[subnet] = true
					subnetMap[subnet] = append(subnetMap[subnet], agent)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}

	results := []subnetResult{}
	for subnet, agents := range subnetMap {
		results = append(results, subnetResult{
			Subnet:     subnet,
			AgentCount: len(agents),
			Agents:     agents,
		})
	}

	c.JSON(http.StatusOK, gin.H{"subnets": results})
}

// ipToSubnet24 converts an IP address string to its /24 CIDR notation.
// Returns empty string for invalid or non-IPv4 addresses.
func ipToSubnet24(ipStr string) string {
	if strings.Contains(ipStr, ":") {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}
