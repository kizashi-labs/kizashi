package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WirelessHandler manages wireless/IoT security monitoring.
type WirelessHandler struct {
	pool *pgxpool.Pool
}

// NewWirelessHandler creates a new WirelessHandler.
func NewWirelessHandler(pool *pgxpool.Pool) *WirelessHandler {
	return &WirelessHandler{pool: pool}
}

// ListNetworks GET /wireless/networks
func (h *WirelessHandler) ListNetworks(c *gin.Context) {
	isRogue := c.Query("is_rogue")
	isAuthorized := c.Query("is_authorized")

	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1

	if isRogue != "" {
		where += " AND is_rogue = $" + strconv.Itoa(idx)
		args = append(args, isRogue == "true")
		idx++
	}
	if isAuthorized != "" {
		where += " AND is_authorized = $" + strconv.Itoa(idx)
		args = append(args, isAuthorized == "true")
		idx++
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, ssid, bssid, channel, frequency, security_type, signal_strength,
		        is_authorized, is_rogue, vendor, first_seen_at, last_seen_at
		 FROM wireless_networks `+where+` ORDER BY last_seen_at DESC`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list networks"})
		return
	}
	defer rows.Close()

	type Network struct {
		ID             string    `json:"id"`
		SSID           string    `json:"ssid"`
		BSSID          string    `json:"bssid"`
		Channel        int       `json:"channel"`
		Frequency      string    `json:"frequency"`
		SecurityType   string    `json:"security_type"`
		SignalStrength int       `json:"signal_strength"`
		IsAuthorized   bool      `json:"is_authorized"`
		IsRogue        bool      `json:"is_rogue"`
		Vendor         string    `json:"vendor"`
		FirstSeenAt    time.Time `json:"first_seen_at"`
		LastSeenAt     time.Time `json:"last_seen_at"`
	}

	networks := []Network{}
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.SSID, &n.BSSID, &n.Channel, &n.Frequency,
			&n.SecurityType, &n.SignalStrength, &n.IsAuthorized, &n.IsRogue,
			&n.Vendor, &n.FirstSeenAt, &n.LastSeenAt); err == nil {
			networks = append(networks, n)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list networks"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": networks})
}

// UpsertNetwork POST /wireless/networks
func (h *WirelessHandler) UpsertNetwork(c *gin.Context) {
	var req struct {
		SSID           string `json:"ssid" binding:"required"`
		BSSID          string `json:"bssid" binding:"required"`
		Channel        int    `json:"channel"`
		Frequency      string `json:"frequency"`
		SecurityType   string `json:"security_type"`
		SignalStrength int    `json:"signal_strength"`
		Vendor         string `json:"vendor"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ssid and bssid are required"})
		return
	}
	if req.Frequency == "" {
		req.Frequency = "2.4GHz"
	}
	if req.SecurityType == "" {
		req.SecurityType = "WPA2"
	}

	// Auto-set is_rogue=true if open security
	isRogue := req.SecurityType == "Open"

	// Check for duplicate SSID of authorized network (rogue if same SSID but different BSSID)
	if !isRogue {
		var authorizedCount int
		if !ReadOK(c, h.pool.QueryRow(c.Request.Context(),
			`SELECT COUNT(*) FROM wireless_networks
				 WHERE ssid = $1 AND bssid != $2 AND is_authorized = TRUE`,
			req.SSID, req.BSSID).Scan(&authorizedCount)) {
			return
		}
		if authorizedCount > 0 {
			isRogue = true
		}
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO wireless_networks (ssid, bssid, channel, frequency, security_type, signal_strength, vendor, is_rogue)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (bssid) DO UPDATE
		   SET ssid = EXCLUDED.ssid,
		       channel = EXCLUDED.channel,
		       frequency = EXCLUDED.frequency,
		       security_type = EXCLUDED.security_type,
		       signal_strength = EXCLUDED.signal_strength,
		       vendor = EXCLUDED.vendor,
		       is_rogue = EXCLUDED.is_rogue,
		       last_seen_at = NOW()
		 RETURNING id`,
		req.SSID, req.BSSID, req.Channel, req.Frequency, req.SecurityType,
		req.SignalStrength, req.Vendor, isRogue).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert network"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "network upserted", "id": id, "is_rogue": isRogue})
}

// AuthorizeNetwork POST /wireless/networks/:id/authorize
func (h *WirelessHandler) AuthorizeNetwork(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(),
		`UPDATE wireless_networks SET is_authorized = TRUE, is_rogue = FALSE WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "network not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "network authorized"})
}

// ListIoTDevices GET /wireless/iot
func (h *WirelessHandler) ListIoTDevices(c *gin.Context) {
	isManaged := c.Query("is_managed")
	deviceType := c.Query("device_type")
	riskScoreMin := c.Query("risk_score_min")

	args := []interface{}{}
	where := "WHERE 1=1"
	idx := 1

	if isManaged != "" {
		where += " AND is_managed = $" + strconv.Itoa(idx)
		args = append(args, isManaged == "true")
		idx++
	}
	if deviceType != "" {
		where += " AND device_type = $" + strconv.Itoa(idx)
		args = append(args, deviceType)
		idx++
	}
	if riskScoreMin != "" {
		if v, err := strconv.Atoi(riskScoreMin); err == nil {
			where += " AND risk_score >= $" + strconv.Itoa(idx)
			args = append(args, v)
			idx++
		}
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, ip_address, mac_address, device_name, device_type, manufacturer,
		        firmware_version, open_ports, vulnerabilities, risk_score, is_managed,
		        last_seen_at, created_at
		 FROM iot_devices `+where+` ORDER BY risk_score DESC`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list IoT devices"})
		return
	}
	defer rows.Close()

	type IoTDevice struct {
		ID              string          `json:"id"`
		IPAddress       string          `json:"ip_address"`
		MACAddress      string          `json:"mac_address"`
		DeviceName      string          `json:"device_name"`
		DeviceType      string          `json:"device_type"`
		Manufacturer    string          `json:"manufacturer"`
		FirmwareVersion string          `json:"firmware_version"`
		OpenPorts       json.RawMessage `json:"open_ports"`
		Vulnerabilities json.RawMessage `json:"vulnerabilities"`
		RiskScore       int             `json:"risk_score"`
		IsManaged       bool            `json:"is_managed"`
		LastSeenAt      time.Time       `json:"last_seen_at"`
		CreatedAt       time.Time       `json:"created_at"`
	}

	devices := []IoTDevice{}
	for rows.Next() {
		var d IoTDevice
		if err := rows.Scan(&d.ID, &d.IPAddress, &d.MACAddress, &d.DeviceName, &d.DeviceType,
			&d.Manufacturer, &d.FirmwareVersion, &d.OpenPorts, &d.Vulnerabilities,
			&d.RiskScore, &d.IsManaged, &d.LastSeenAt, &d.CreatedAt); err == nil {
			devices = append(devices, d)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list IoT devices"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": devices})
}

// UpsertIoTDevice POST /wireless/iot
func (h *WirelessHandler) UpsertIoTDevice(c *gin.Context) {
	var req struct {
		IPAddress       string      `json:"ip_address" binding:"required"`
		MACAddress      string      `json:"mac_address" binding:"required"`
		DeviceName      string      `json:"device_name"`
		DeviceType      string      `json:"device_type"`
		Manufacturer    string      `json:"manufacturer"`
		FirmwareVersion string      `json:"firmware_version"`
		OpenPorts       interface{} `json:"open_ports"`
		Vulnerabilities interface{} `json:"vulnerabilities"`
		RiskScore       int         `json:"risk_score"`
		IsManaged       bool        `json:"is_managed"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip_address and mac_address are required"})
		return
	}
	if req.DeviceType == "" {
		req.DeviceType = "unknown"
	}

	openPortsJSON, _ := json.Marshal(req.OpenPorts)
	vulnsJSON, _ := json.Marshal(req.Vulnerabilities)
	if string(openPortsJSON) == "null" {
		openPortsJSON = []byte("[]")
	}
	if string(vulnsJSON) == "null" {
		vulnsJSON = []byte("[]")
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO iot_devices (ip_address, mac_address, device_name, device_type, manufacturer,
		                          firmware_version, open_ports, vulnerabilities, risk_score, is_managed)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (mac_address) DO UPDATE
		   SET ip_address = EXCLUDED.ip_address,
		       device_name = EXCLUDED.device_name,
		       device_type = EXCLUDED.device_type,
		       manufacturer = EXCLUDED.manufacturer,
		       firmware_version = EXCLUDED.firmware_version,
		       open_ports = EXCLUDED.open_ports,
		       vulnerabilities = EXCLUDED.vulnerabilities,
		       risk_score = EXCLUDED.risk_score,
		       is_managed = EXCLUDED.is_managed,
		       last_seen_at = NOW()
		 RETURNING id`,
		req.IPAddress, req.MACAddress, req.DeviceName, req.DeviceType, req.Manufacturer,
		req.FirmwareVersion, string(openPortsJSON), string(vulnsJSON), req.RiskScore, req.IsManaged).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert IoT device"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "IoT device upserted", "id": id})
}

// GetStats GET /wireless/stats
func (h *WirelessHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	var totalNetworks, rogueCount, authorizedCount int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM wireless_networks`).Scan(&totalNetworks)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM wireless_networks WHERE is_rogue = TRUE`).Scan(&rogueCount)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM wireless_networks WHERE is_authorized = TRUE`).Scan(&authorizedCount)) {
		return
	}

	var totalIoT, highRiskIoT int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iot_devices`).Scan(&totalIoT)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iot_devices WHERE risk_score >= 70`).Scan(&highRiskIoT)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_networks":    totalNetworks,
		"rogue_count":       rogueCount,
		"authorized_count":  authorizedCount,
		"total_iot_devices": totalIoT,
		"high_risk_iot":     highRiskIoT,
	})
}
