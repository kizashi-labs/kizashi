package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetworkSegmentationHandler manages network segments and inter-segment policies,
// and runs a real (data-driven) compliance check over them.
type NetworkSegmentationHandler struct {
	pool *pgxpool.Pool
}

// NewNetworkSegmentationHandler creates a new NetworkSegmentationHandler.
func NewNetworkSegmentationHandler(pool *pgxpool.Pool) *NetworkSegmentationHandler {
	return &NetworkSegmentationHandler{pool: pool}
}

// ── Types (mirror the frontend) ────────────────────────────────────────────────

type nsDevice struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Type     string `json:"type"` // server, workstation, network, iot
}

type nsSegment struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	VlanID      int        `json:"vlan_id"`
	Cidr        string     `json:"cidr"`
	Gateway     string     `json:"gateway"`
	DNSServers  []string   `json:"dns_servers"`
	DeviceCount int        `json:"device_count"`
	PolicyCount int        `json:"policy_count"`
	Status      string     `json:"status"`
	Devices     []nsDevice `json:"devices"`
}

type nsPolicy struct {
	ID          string `json:"id"`
	FromSegment string `json:"from_segment"`
	ToSegment   string `json:"to_segment"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	Ports       string `json:"ports"`
	Description string `json:"description"`
}

// ── Read ───────────────────────────────────────────────────────────────────────

// GetSegmentation returns all segments (with live device counts) and policies.
// GET /api/v1/admin/network-segments
func (h *NetworkSegmentationHandler) GetSegmentation(c *gin.Context) {
	ctx := c.Request.Context()

	policies := h.loadPolicies(ctx)

	// policy_count per segment name (counts policies referencing it either way).
	policyCount := map[string]int{}
	for _, p := range policies {
		policyCount[p.FromSegment]++
		if p.ToSegment != p.FromSegment {
			policyCount[p.ToSegment]++
		}
	}

	segments := []nsSegment{}
	rows, err := h.pool.Query(ctx, `
		SELECT id, name, description, vlan_id, cidr, gateway, dns_servers, status
		FROM network_segments ORDER BY name`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s nsSegment
			if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.VlanID, &s.Cidr,
				&s.Gateway, &s.DNSServers, &s.Status); err != nil {
				continue
			}
			if s.DNSServers == nil {
				s.DNSServers = []string{}
			}
			s.Devices = h.devicesInCIDR(ctx, s.Cidr)
			s.DeviceCount = len(s.Devices)
			s.PolicyCount = policyCount[s.Name]
			segments = append(segments, s)
		}
	}

	c.JSON(http.StatusOK, gin.H{"segments": segments, "policies": policies})
}

func (h *NetworkSegmentationHandler) loadPolicies(ctx context.Context) []nsPolicy {
	policies := []nsPolicy{}
	rows, err := h.pool.Query(ctx, `
		SELECT id, from_segment, to_segment, action, protocol, ports, description
		FROM network_segment_policies ORDER BY created_at`)
	if err != nil {
		return policies
	}
	defer rows.Close()
	for rows.Next() {
		var p nsPolicy
		if err := rows.Scan(&p.ID, &p.FromSegment, &p.ToSegment, &p.Action,
			&p.Protocol, &p.Ports, &p.Description); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	return policies
}

// devicesInCIDR returns agents whose ip_addresses fall within the segment CIDR.
// Returns an empty slice for an invalid/empty CIDR (best effort, never errors out).
func (h *NetworkSegmentationHandler) devicesInCIDR(ctx context.Context, cidr string) []nsDevice {
	devices := []nsDevice{}
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return devices
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return devices
	}
	rows, err := h.pool.Query(ctx, `
		SELECT a.hostname, a.os_type,
		       (SELECT host(ipx) FROM unnest(a.ip_addresses) ipx WHERE ipx << $1::inet LIMIT 1) AS ip
		FROM agents a
		WHERE EXISTS (SELECT 1 FROM unnest(a.ip_addresses) ip WHERE ip << $1::inet)
		LIMIT 200`, cidr)
	if err != nil {
		return devices
	}
	defer rows.Close()
	for rows.Next() {
		var hostname, osType string
		var ip *string
		if err := rows.Scan(&hostname, &osType, &ip); err != nil {
			continue
		}
		d := nsDevice{Hostname: hostname, Type: deviceTypeFromOS(osType)}
		if ip != nil {
			d.IP = *ip
		}
		devices = append(devices, d)
	}
	return devices
}

func deviceTypeFromOS(osType string) string {
	switch strings.ToLower(osType) {
	case "linux":
		return "server"
	case "windows", "darwin":
		return "workstation"
	default:
		return "network"
	}
}

// ── Write ──────────────────────────────────────────────────────────────────────

// CreateSegment creates a network segment.
// POST /api/v1/admin/network-segments
func (h *NetworkSegmentationHandler) CreateSegment(c *gin.Context) {
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		VlanID      int      `json:"vlan_id"`
		Cidr        string   `json:"cidr"`
		Gateway     string   `json:"gateway"`
		DNSServers  []string `json:"dns_servers"`
		Status      string   `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Status == "" {
		body.Status = "active"
	}
	if body.DNSServers == nil {
		body.DNSServers = []string{}
	}
	dns, _ := json.Marshal(body.DNSServers)

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO network_segments (name, description, vlan_id, cidr, gateway, dns_servers, status)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7) RETURNING id`,
		body.Name, body.Description, body.VlanID, body.Cidr, body.Gateway, dns, body.Status,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// DeleteSegment removes a segment.
// DELETE /api/v1/admin/network-segments/:id
func (h *NetworkSegmentationHandler) DeleteSegment(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `DELETE FROM network_segments WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "segment not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// CreatePolicy creates an inter-segment policy.
// POST /api/v1/admin/network-segments/policies
func (h *NetworkSegmentationHandler) CreatePolicy(c *gin.Context) {
	var body struct {
		FromSegment string `json:"from_segment"`
		ToSegment   string `json:"to_segment"`
		Action      string `json:"action"`
		Protocol    string `json:"protocol"`
		Ports       string `json:"ports"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Action == "" {
		body.Action = "allow"
	}
	if body.Protocol == "" {
		body.Protocol = "TCP"
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO network_segment_policies (from_segment, to_segment, action, protocol, ports, description)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		body.FromSegment, body.ToSegment, body.Action, body.Protocol, body.Ports, body.Description,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// DeletePolicy removes a policy.
// DELETE /api/v1/admin/network-segments/policies/:id
func (h *NetworkSegmentationHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `DELETE FROM network_segment_policies WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// ── Compliance ─────────────────────────────────────────────────────────────────

// ComplianceCheck analyses the defined segments and policies and returns real,
// data-driven findings (replacing the previous hard-coded mock results).
// POST /api/v1/admin/network-segments/compliance-check
func (h *NetworkSegmentationHandler) ComplianceCheck(c *gin.Context) {
	ctx := c.Request.Context()

	// Load segment names.
	segNames := []string{}
	if rows, err := h.pool.Query(ctx, `SELECT name FROM network_segments ORDER BY name`); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				segNames = append(segNames, n)
			}
		}
		rows.Close()
	}
	policies := h.loadPolicies(ctx)

	issues := []string{}

	if len(segNames) == 0 {
		issues = append(issues, "ネットワークセグメントが1件も定義されていません。")
		c.JSON(http.StatusOK, gin.H{"issues": issues, "checked_at": time.Now().UTC().Format(time.RFC3339), "compliant": false})
		return
	}
	if len(policies) == 0 {
		issues = append(issues, "セグメントは定義されていますが、通信ポリシーが1件も定義されていません。デフォルトの通信可否が不定です。")
	}

	// 1) Segments not referenced by any policy.
	referenced := map[string]bool{}
	hasDeny := false
	for _, p := range policies {
		referenced[p.FromSegment] = true
		referenced[p.ToSegment] = true
		if p.Action == "deny" {
			hasDeny = true
		}
	}
	for _, name := range segNames {
		if !referenced[name] {
			issues = append(issues, fmt.Sprintf("「%s」セグメントを対象とする通信ポリシーが定義されていません。", name))
		}
	}

	// 2) No explicit deny anywhere → default-deny posture is missing.
	if len(policies) > 0 && !hasDeny {
		issues = append(issues, "明示的な拒否(deny)ポリシーが存在しません。デフォルト拒否の方針を検討してください。")
	}

	// Low-trust zones that should not reach internal zones directly.
	lowTrust := map[string]bool{"DMZ": true, "GUEST": true, "OT": true}
	internal := map[string]bool{"CORP": true, "MGMT": true}

	for _, p := range policies {
		// 3) Overly-permissive allow (all ports).
		if p.Action == "allow" {
			ports := strings.ToLower(strings.TrimSpace(p.Ports))
			if ports == "" || ports == "*" || ports == "any" || ports == "all" {
				issues = append(issues, fmt.Sprintf("ポリシー「%s→%s」が全ポート許可になっています(過剰な許可)。", p.FromSegment, p.ToSegment))
			}
			// 4) Trust-boundary violation: low-trust → internal allow.
			if lowTrust[strings.ToUpper(p.FromSegment)] && internal[strings.ToUpper(p.ToSegment)] {
				issues = append(issues, fmt.Sprintf("「%s→%s」への直接アクセスが許可されています(信頼境界の越境)。", p.FromSegment, p.ToSegment))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"issues":     issues,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"compliant":  len(issues) == 0,
	})
}
