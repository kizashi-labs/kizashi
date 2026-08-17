package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IoTOTHandler serves IoT/OT security data.
// GET /api/v1/iot-ot/devices
// GET /api/v1/iot-ot/anomalies
type IoTOTHandler struct {
	pool *pgxpool.Pool
}

func NewIoTOTHandler(pool *pgxpool.Pool) *IoTOTHandler {
	return &IoTOTHandler{pool: pool}
}

func (h *IoTOTHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

// ── Types ─────────────────────────────────────────────────────────────────────

type iotDevice struct {
	ID               string          `json:"id"`
	DeviceName       string          `json:"device_name"`
	DeviceType       string          `json:"device_type"`
	IPAddress        string          `json:"ip_address"`
	Vendor           string          `json:"vendor"`
	FirmwareVersion  string          `json:"firmware_version"`
	Protocol         string          `json:"protocol"`
	NetworkZone      string          `json:"network_zone"`
	RiskScore        int             `json:"risk_score"`
	LastSeen         string          `json:"last_seen"`
	PatchStatus      string          `json:"patch_status"`
	OpenPorts        json.RawMessage `json:"open_ports"`
	KnownVulns       json.RawMessage `json:"known_vulns"`
	CommunicatesWith json.RawMessage `json:"communicates_with"`
	HardeningSteps   json.RawMessage `json:"hardening_steps"`
}

type iotAnomaly struct {
	ID                  string `json:"id"`
	Timestamp           string `json:"timestamp"`
	DeviceID            string `json:"device_id"`
	DeviceName          string `json:"device_name"`
	AnomalyType         string `json:"anomaly_type"`
	Severity            string `json:"severity"`
	Description         string `json:"description"`
	Status              string `json:"status"`
	ProtocolContext     string `json:"protocol_context"`
	RecommendedResponse string `json:"recommended_response"`
}

// ListDevices returns all IoT/OT devices.
// GET /api/v1/iot-ot/devices
func (h *IoTOTHandler) ListDevices(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "iot_devices") {
		c.JSON(http.StatusOK, []iotDevice{})
		return
	}

	// Check if extended columns exist
	hasProtocol := h.tableExists(c, "iot_devices") // always true here; check column instead
	var colExists bool
	// **確認できなかったことを「列が無い」と答えていました。** `_ =` で
	// 捨てていたので、DB が応答しないだけで縮小版のクエリに落ち、
	// protocol / network_zone などが既定値で返っていました ——
	// 画面には「そういう機器」として並びます。
	// `probeAnswer` は確認できなければ「在る」と答えます。列が本当に
	// 無ければ確認は成功して false を返し、今まで通り縮小版に落ちます。
	colErr := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iot_devices' AND column_name='protocol')`).Scan(&colExists)
	colExists = probeAnswer(colExists, colErr)

	var query string
	if colExists {
		query = `
			SELECT id::text, device_name, device_type, ip_address,
			       COALESCE(manufacturer,''), COALESCE(firmware_version,''),
			       COALESCE(protocol,'HTTP'), COALESCE(network_zone,'IoT'),
			       risk_score, last_seen_at,
			       COALESCE(patch_status,'unknown'),
			       COALESCE(open_ports,'[]'::jsonb),
			       COALESCE(known_vulns,'[]'::jsonb),
			       COALESCE(communicates_with,'[]'::jsonb),
			       COALESCE(hardening_steps,'[]'::jsonb)
			FROM iot_devices ORDER BY risk_score DESC LIMIT 200`
	} else {
		query = `
			SELECT id::text, device_name, device_type, ip_address,
			       COALESCE(manufacturer,''), COALESCE(firmware_version,''),
			       'HTTP', 'IoT',
			       risk_score, last_seen_at,
			       'unknown',
			       COALESCE(open_ports,'[]'::jsonb),
			       COALESCE(vulnerabilities,'[]'::jsonb),
			       '[]'::jsonb, '[]'::jsonb
			FROM iot_devices ORDER BY risk_score DESC LIMIT 200`
	}
	_ = hasProtocol // suppress unused warning

	rows, err := h.pool.Query(ctx, query)
	if err != nil {
		ReadFailure(c, err, []iotDevice{})
		return
	}
	defer rows.Close()

	var devices []iotDevice
	for rows.Next() {
		var d iotDevice
		var lastSeen time.Time
		if rows.Scan(
			&d.ID, &d.DeviceName, &d.DeviceType, &d.IPAddress,
			&d.Vendor, &d.FirmwareVersion, &d.Protocol, &d.NetworkZone,
			&d.RiskScore, &lastSeen, &d.PatchStatus,
			&d.OpenPorts, &d.KnownVulns, &d.CommunicatesWith, &d.HardeningSteps,
		) != nil {
			continue
		}
		d.LastSeen = lastSeen.Format(time.RFC3339)
		if d.OpenPorts == nil {
			d.OpenPorts = json.RawMessage(`[]`)
		}
		if d.KnownVulns == nil {
			d.KnownVulns = json.RawMessage(`[]`)
		}
		if d.CommunicatesWith == nil {
			d.CommunicatesWith = json.RawMessage(`[]`)
		}
		if d.HardeningSteps == nil {
			d.HardeningSteps = json.RawMessage(`[]`)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListDevices: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []iotDevice{})
		return
	}
	if devices == nil {
		devices = []iotDevice{}
	}
	c.JSON(http.StatusOK, devices)
}

// ListAnomalies returns IoT/OT anomaly alerts.
// GET /api/v1/iot-ot/anomalies
func (h *IoTOTHandler) ListAnomalies(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "iot_ot_anomalies") {
		c.JSON(http.StatusOK, []iotAnomaly{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, timestamp, device_id, device_name, anomaly_type,
		       severity, description, status, protocol_context, recommended_response
		FROM iot_ot_anomalies ORDER BY timestamp DESC LIMIT 200
	`)
	if err != nil {
		ReadFailure(c, err, []iotAnomaly{})
		return
	}
	defer rows.Close()

	var anomalies []iotAnomaly
	for rows.Next() {
		var a iotAnomaly
		var ts time.Time
		if rows.Scan(
			&a.ID, &ts, &a.DeviceID, &a.DeviceName, &a.AnomalyType,
			&a.Severity, &a.Description, &a.Status, &a.ProtocolContext, &a.RecommendedResponse,
		) != nil {
			continue
		}
		a.Timestamp = ts.Format(time.RFC3339)
		anomalies = append(anomalies, a)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListAnomalies: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []iotAnomaly{})
		return
	}
	if anomalies == nil {
		anomalies = []iotAnomaly{}
	}
	c.JSON(http.StatusOK, anomalies)
}
