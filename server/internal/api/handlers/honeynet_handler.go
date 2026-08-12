package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HoneynetHandler manages full honeynet nodes and interactions.
type HoneynetHandler struct {
	pool *pgxpool.Pool
}

// NewHoneynetHandler creates a new HoneynetHandler.
func NewHoneynetHandler(pool *pgxpool.Pool) *HoneynetHandler {
	return &HoneynetHandler{pool: pool}
}

func (h *HoneynetHandler) checkNodesTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='honeynet_nodes')`).Scan(&exists)
	return err == nil && exists
}

func (h *HoneynetHandler) checkInteractionsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='honeynet_interactions')`).Scan(&exists)
	return err == nil && exists
}

// ListNodes returns all honeynet nodes.
// GET /api/v1/admin/honeynet/nodes
func (h *HoneynetHandler) ListNodes(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusOK, gin.H{"nodes": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, node_type, ip_address, hostname, os_profile,
		        services, is_active, interaction_count, last_interaction,
		        network_segment, created_at
		 FROM honeynet_nodes ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list honeynet nodes"})
		return
	}
	defer rows.Close()

	type node struct {
		ID               string      `json:"id"`
		Name             string      `json:"name"`
		NodeType         string      `json:"node_type"`
		IPAddress        *string     `json:"ip_address"`
		Hostname         *string     `json:"hostname"`
		OSProfile        *string     `json:"os_profile"`
		Services         interface{} `json:"services"`
		IsActive         bool        `json:"is_active"`
		InteractionCount int         `json:"interaction_count"`
		LastInteraction  *string     `json:"last_interaction"`
		NetworkSegment   *string     `json:"network_segment"`
		CreatedAt        string      `json:"created_at"`
	}

	var result []node
	for rows.Next() {
		var n node
		var lastInteraction *time.Time
		var createdAt time.Time
		var servicesRaw []byte
		if err := rows.Scan(
			&n.ID, &n.Name, &n.NodeType, &n.IPAddress, &n.Hostname,
			&n.OSProfile, &servicesRaw, &n.IsActive, &n.InteractionCount,
			&lastInteraction, &n.NetworkSegment, &createdAt,
		); err != nil {
			continue
		}
		if lastInteraction != nil {
			s := lastInteraction.Format(time.RFC3339)
			n.LastInteraction = &s
		}
		n.CreatedAt = createdAt.Format(time.RFC3339)
		n.Services = jsonRawOrEmpty(servicesRaw)
		result = append(result, n)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []node{}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": result, "total": len(result)})
}

// CreateNode creates a new honeynet node.
// POST /api/v1/admin/honeynet/nodes
func (h *HoneynetHandler) CreateNode(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "honeynet_nodes table not available"})
		return
	}
	var body struct {
		Name           string  `json:"name" binding:"required"`
		NodeType       string  `json:"node_type"`
		IPAddress      *string `json:"ip_address"`
		Hostname       *string `json:"hostname"`
		OSProfile      *string `json:"os_profile"`
		Services       *string `json:"services"`
		IsActive       *bool   `json:"is_active"`
		NetworkSegment *string `json:"network_segment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.NodeType == "" {
		body.NodeType = "honeypot"
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}
	services := "[]"
	if body.Services != nil && *body.Services != "" {
		services = *body.Services
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO honeynet_nodes (name, node_type, ip_address, hostname, os_profile, services, is_active, network_segment)
		 VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8) RETURNING id`,
		body.Name, body.NodeType, body.IPAddress, body.Hostname, body.OSProfile,
		services, isActive, body.NetworkSegment,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create honeynet node"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Honeynet node created"})
}

// UpdateNode updates a honeynet node.
// PUT /api/v1/admin/honeynet/nodes/:id
func (h *HoneynetHandler) UpdateNode(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name           string  `json:"name"`
		NodeType       string  `json:"node_type"`
		IPAddress      *string `json:"ip_address"`
		Hostname       *string `json:"hostname"`
		OSProfile      *string `json:"os_profile"`
		Services       *string `json:"services"`
		IsActive       *bool   `json:"is_active"`
		NetworkSegment *string `json:"network_segment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	services := "[]"
	if body.Services != nil && *body.Services != "" {
		services = *body.Services
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE honeynet_nodes SET name=$1, node_type=$2, ip_address=$3, hostname=$4,
		        os_profile=$5, services=$6::jsonb, is_active=$7, network_segment=$8
		 WHERE id=$9`,
		body.Name, body.NodeType, body.IPAddress, body.Hostname,
		body.OSProfile, services, body.IsActive, body.NetworkSegment, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update honeynet node"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Honeynet node updated"})
}

// DeleteNode deletes a honeynet node.
// DELETE /api/v1/admin/honeynet/nodes/:id
func (h *HoneynetHandler) DeleteNode(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM honeynet_nodes WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete honeynet node"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Honeynet node deleted"})
}

// ToggleNode flips the is_active state of a honeynet node.
// POST /api/v1/admin/honeynet/nodes/:id/toggle
func (h *HoneynetHandler) ToggleNode(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`UPDATE honeynet_nodes SET is_active = NOT is_active WHERE id=$1 RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle honeynet node"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// ListInteractions returns honeynet interactions with optional filters.
// GET /api/v1/admin/honeynet/interactions
func (h *HoneynetHandler) ListInteractions(c *gin.Context) {
	if !h.checkInteractionsTable(c) {
		c.JSON(http.StatusOK, gin.H{"interactions": []interface{}{}, "total": 0})
		return
	}
	nodeID := c.Query("node_id")
	threatLevel := c.Query("threat_level")
	isAutomatedStr := c.Query("is_automated")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	ctx := c.Request.Context()
	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1
	if nodeID != "" {
		where += " AND node_id=$" + strconv.Itoa(idx)
		args = append(args, nodeID)
		idx++
	}
	if threatLevel != "" {
		where += " AND threat_level=$" + strconv.Itoa(idx)
		args = append(args, threatLevel)
		idx++
	}
	if isAutomatedStr != "" {
		isAutomated := isAutomatedStr == "true" || isAutomatedStr == "1"
		where += " AND is_automated=$" + strconv.Itoa(idx)
		args = append(args, isAutomated)
		idx++
	}
	args = append(args, limit, offset)
	query := `SELECT id, node_id, attacker_ip, attacker_port, protocol, payload,
	                 commands, files_accessed, session_duration_s, threat_level,
	                 geo_country, is_automated, created_at
	          FROM honeynet_interactions ` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list interactions"})
		return
	}
	defer rows.Close()

	type interaction struct {
		ID               string      `json:"id"`
		NodeID           string      `json:"node_id"`
		AttackerIP       string      `json:"attacker_ip"`
		AttackerPort     *int        `json:"attacker_port"`
		Protocol         *string     `json:"protocol"`
		Payload          *string     `json:"payload"`
		Commands         interface{} `json:"commands"`
		FilesAccessed    interface{} `json:"files_accessed"`
		SessionDurationS int         `json:"session_duration_s"`
		ThreatLevel      string      `json:"threat_level"`
		GeoCountry       *string     `json:"geo_country"`
		IsAutomated      bool        `json:"is_automated"`
		CreatedAt        string      `json:"created_at"`
	}

	var result []interaction
	for rows.Next() {
		var i interaction
		var createdAt time.Time
		var commandsRaw, filesRaw []byte
		if err := rows.Scan(
			&i.ID, &i.NodeID, &i.AttackerIP, &i.AttackerPort, &i.Protocol,
			&i.Payload, &commandsRaw, &filesRaw, &i.SessionDurationS,
			&i.ThreatLevel, &i.GeoCountry, &i.IsAutomated, &createdAt,
		); err != nil {
			continue
		}
		i.CreatedAt = createdAt.Format(time.RFC3339)
		i.Commands = jsonRawOrEmpty(commandsRaw)
		i.FilesAccessed = jsonRawOrEmpty(filesRaw)
		result = append(result, i)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []interaction{}
	}
	c.JSON(http.StatusOK, gin.H{"interactions": result, "total": len(result)})
}

// GetInteraction returns a single interaction.
// GET /api/v1/admin/honeynet/interactions/:id
func (h *HoneynetHandler) GetInteraction(c *gin.Context) {
	if !h.checkInteractionsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	var i struct {
		ID               string      `json:"id"`
		NodeID           string      `json:"node_id"`
		AttackerIP       string      `json:"attacker_ip"`
		AttackerPort     *int        `json:"attacker_port"`
		Protocol         *string     `json:"protocol"`
		Payload          *string     `json:"payload"`
		Commands         interface{} `json:"commands"`
		FilesAccessed    interface{} `json:"files_accessed"`
		SessionDurationS int         `json:"session_duration_s"`
		ThreatLevel      string      `json:"threat_level"`
		GeoCountry       *string     `json:"geo_country"`
		IsAutomated      bool        `json:"is_automated"`
		CreatedAt        string      `json:"created_at"`
	}
	var createdAt time.Time
	var commandsRaw, filesRaw []byte
	err := h.pool.QueryRow(ctx,
		`SELECT id, node_id, attacker_ip, attacker_port, protocol, payload,
		        commands, files_accessed, session_duration_s, threat_level,
		        geo_country, is_automated, created_at
		 FROM honeynet_interactions WHERE id=$1`, id,
	).Scan(
		&i.ID, &i.NodeID, &i.AttackerIP, &i.AttackerPort, &i.Protocol,
		&i.Payload, &commandsRaw, &filesRaw, &i.SessionDurationS,
		&i.ThreatLevel, &i.GeoCountry, &i.IsAutomated, &createdAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Interaction not found"})
		return
	}
	i.CreatedAt = createdAt.Format(time.RFC3339)
	i.Commands = jsonRawOrEmpty(commandsRaw)
	i.FilesAccessed = jsonRawOrEmpty(filesRaw)
	c.JSON(http.StatusOK, i)
}

// GetStats returns honeynet statistics.
// GET /api/v1/admin/honeynet/stats
func (h *HoneynetHandler) GetStats(c *gin.Context) {
	if !h.checkNodesTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"interactions_by_protocol":  []interface{}{},
			"top_attacker_ips":          []interface{}{},
			"interactions_per_day":      []interface{}{},
			"threat_level_distribution": []interface{}{},
		})
		return
	}
	ctx := c.Request.Context()

	// Interactions by protocol
	type protocolCount struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
	}
	var byProtocol []protocolCount
	if h.checkInteractionsTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT COALESCE(protocol,'unknown'), COUNT(*) FROM honeynet_interactions
			 GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 10`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var p protocolCount
				if err := rows.Scan(&p.Protocol, &p.Count); err == nil {
					byProtocol = append(byProtocol, p)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("honeynet byProtocol iteration failed", "error", err)
			}
		}
	}
	if byProtocol == nil {
		byProtocol = []protocolCount{}
	}

	// Top attacker IPs
	type ipCount struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	var topIPs []ipCount
	if h.checkInteractionsTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT attacker_ip::text, COUNT(*) FROM honeynet_interactions
			 GROUP BY attacker_ip ORDER BY COUNT(*) DESC LIMIT 10`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ip ipCount
				if err := rows.Scan(&ip.IP, &ip.Count); err == nil {
					topIPs = append(topIPs, ip)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("honeynet topIPs iteration failed", "error", err)
			}
		}
	}
	if topIPs == nil {
		topIPs = []ipCount{}
	}

	// Interactions per day (last 7 days)
	type dayCount struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	var perDay []dayCount
	if h.checkInteractionsTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT DATE(created_at)::text, COUNT(*) FROM honeynet_interactions
			 WHERE created_at >= NOW() - INTERVAL '7 days'
			 GROUP BY DATE(created_at) ORDER BY DATE(created_at)`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var d dayCount
				if err := rows.Scan(&d.Date, &d.Count); err == nil {
					perDay = append(perDay, d)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("honeynet perDay iteration failed", "error", err)
			}
		}
	}
	if perDay == nil {
		perDay = []dayCount{}
	}

	// Threat level distribution
	type tlCount struct {
		ThreatLevel string `json:"threat_level"`
		Count       int    `json:"count"`
	}
	var byThreatLevel []tlCount
	if h.checkInteractionsTable(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT threat_level, COUNT(*) FROM honeynet_interactions
			 GROUP BY threat_level ORDER BY COUNT(*) DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var tl tlCount
				if err := rows.Scan(&tl.ThreatLevel, &tl.Count); err == nil {
					byThreatLevel = append(byThreatLevel, tl)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("honeynet byThreatLevel iteration failed", "error", err)
			}
		}
	}
	if byThreatLevel == nil {
		byThreatLevel = []tlCount{}
	}

	c.JSON(http.StatusOK, gin.H{
		"interactions_by_protocol":  byProtocol,
		"top_attacker_ips":          topIPs,
		"interactions_per_day":      perDay,
		"threat_level_distribution": byThreatLevel,
	})
}

// jsonRawOrEmpty converts a raw JSONB byte slice to interface{} or an empty slice.
func jsonRawOrEmpty(raw []byte) interface{} {
	if raw == nil {
		return []interface{}{}
	}
	// Return as json.RawMessage so gin serialises it directly
	return raw
}
