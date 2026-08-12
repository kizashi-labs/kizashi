// Package siem forwards EDR alerts to external SIEM platforms.
// Supports: Syslog/CEF (RFC5424), Splunk HEC, Elastic ECS over HTTP, Syslog/LEEF.
package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AlertPayload is the normalized alert data forwarded to SIEMs.
type AlertPayload struct {
	ID             string    `json:"id"`
	AgentID        string    `json:"agent_id"`
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	RuleName       string    `json:"rule_name"`
	Severity       int       `json:"severity"`
	Status         string    `json:"status"`
	MITRETechnique string    `json:"mitre_technique,omitempty"`
	AIThreatName   string    `json:"ai_threat_name,omitempty"`
	AISummary      string    `json:"ai_summary,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Target represents one SIEM forwarding destination.
type Target struct {
	ID              string
	Name            string
	Type            string // syslog_cef | splunk_hec | elastic_ecs | syslog_leef
	Host            string
	Port            int
	Protocol        string // udp | tcp | https
	Token           string
	TLSEnabled      bool
	IndexName       string
	Enabled         bool
	MinSeverity     int
	FilterRules     []string // 空=全ルール対象。非空=いずれかにマッチするもののみ転送
	FilterHostnames []string // 空=全端末対象。非空=いずれかにマッチするもののみ転送
	FilterMitre     []string // 空=全MITRE対象。非空=いずれかにマッチするもののみ転送
}

// Forwarder manages SIEM target forwarding.
type Forwarder struct {
	mu      sync.RWMutex
	targets []*Target
	client  *http.Client
}

// NewForwarder creates a new Forwarder.
func NewForwarder() *Forwarder {
	return &Forwarder{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false},
			},
		},
	}
}

// LoadTargets replaces the active target list.
func (f *Forwarder) LoadTargets(targets []*Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = targets
}

// Forward sends an alert to all enabled SIEM targets.
func (f *Forwarder) Forward(ctx context.Context, alert *AlertPayload) {
	f.mu.RLock()
	targets := f.targets
	f.mu.RUnlock()

	for _, t := range targets {
		if !t.Enabled || alert.Severity < t.MinSeverity {
			continue
		}
		// ルール名フィルター（ホワイトリスト）
		if len(t.FilterRules) > 0 {
			matched := false
			for _, r := range t.FilterRules {
				if strings.EqualFold(r, alert.RuleName) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		// 端末ホスト名フィルター（ホワイトリスト）
		if len(t.FilterHostnames) > 0 {
			matched := false
			for _, h := range t.FilterHostnames {
				if strings.EqualFold(h, alert.Hostname) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		// MITREテクニックフィルター（ホワイトリスト）
		if len(t.FilterMitre) > 0 && alert.MITRETechnique != "" {
			matched := false
			for _, m := range t.FilterMitre {
				if strings.EqualFold(m, alert.MITRETechnique) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		t := t // capture loop variable
		go func() {
			if err := f.forward(ctx, t, alert); err != nil {
				slog.Warn("SIEM forward failed", "target", t.Name, "type", t.Type, "error", err)
			} else {
				slog.Debug("SIEM forwarded", "target", t.Name, "alert", alert.ID)
			}
		}()
	}
}

func (f *Forwarder) forward(ctx context.Context, t *Target, alert *AlertPayload) error {
	switch t.Type {
	case "syslog_cef":
		return f.forwardSyslogCEF(t, alert)
	case "syslog_leef":
		return f.forwardSyslogLEEF(t, alert)
	case "splunk_hec":
		return f.forwardSplunkHEC(ctx, t, alert)
	case "elastic_ecs":
		return f.forwardElasticECS(ctx, t, alert)
	default:
		return fmt.Errorf("unknown SIEM type: %s", t.Type)
	}
}

// ─── CEF (Common Event Format) ────────────────────────────────────────────────

// cefSeverity maps a platform alert severity (1-10 scale, matching
// alerts.severity / AUTO_ISOLATE_MIN_SEVERITY) onto the CEF/LEEF severity range
// (0-10). The scales are aligned, so this is an identity map clamped to [0,10];
// a critical sev-9 alert becomes CEF severity 9, not 0.
func cefSeverity(sev int) int {
	if sev < 0 {
		return 0
	}
	if sev > 10 {
		return 10
	}
	return sev
}

// formatCEF produces an RFC5424 syslog line with a CEF body.
func formatCEF(alert *AlertPayload) string {
	// Severity mapping: alert severity 1-10 → CEF 0-10 (aligned scales)
	cefSev := cefSeverity(alert.Severity)

	// Escape pipe and backslash in CEF header fields
	escape := func(s string) string {
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "|", "\\|")
		return s
	}

	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	cef := fmt.Sprintf("CEF:0|FalconEDR|EDR Platform|1.0|%s|%s|%d|",
		escape(alert.ID[:8]),
		escape(alert.RuleName),
		cefSev,
	)

	// Extension key=value pairs
	ext := []string{
		fmt.Sprintf("src=%s", alert.AgentID),
		fmt.Sprintf("dhost=%s", alert.Hostname),
		fmt.Sprintf("act=%s", alert.Status),
		fmt.Sprintf("rt=%d", alert.CreatedAt.UnixMilli()),
	}
	if alert.MITRETechnique != "" {
		ext = append(ext, fmt.Sprintf("cs1=%s cs1Label=MITRETechnique", alert.MITRETechnique))
	}
	if alert.AIThreatName != "" {
		ext = append(ext, fmt.Sprintf("cs2=%s cs2Label=ThreatName", alert.AIThreatName))
	}

	cef += strings.Join(ext, " ")

	// Wrap in syslog envelope
	// facility=local0(16) severity=info(6): (16*8)+6=134
	return fmt.Sprintf("<%d>1 %s FalconEDR - - - - %s",
		134,
		alert.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		cef,
	)
}

func (f *Forwarder) forwardSyslogCEF(t *Target, alert *AlertPayload) error {
	msg := formatCEF(alert)
	return f.sendSyslog(t, msg)
}

// ─── LEEF (Log Event Extended Format) ─────────────────────────────────────────

func formatLEEF(alert *AlertPayload) string {
	// Severity mapping: alert severity 1-10 → LEEF sev 0-10 (aligned scales)
	leefSev := cefSeverity(alert.Severity)
	return fmt.Sprintf(
		"LEEF:2.0|FalconEDR|EDR Platform|1.0|%s|\tsev=%d\thostname=%s\tname=%s\tstatus=%s",
		alert.ID[:8], leefSev, alert.Hostname, alert.RuleName, alert.Status,
	)
}

func (f *Forwarder) forwardSyslogLEEF(t *Target, alert *AlertPayload) error {
	return f.sendSyslog(t, formatLEEF(alert))
}

// sendSyslog sends a raw syslog message via UDP or TCP.
func (f *Forwarder) sendSyslog(t *Target, msg string) error {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	var conn net.Conn
	var err error

	if t.Protocol == "tcp" {
		if t.TLSEnabled {
			conn, err = tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12})
		} else {
			conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		}
	} else {
		conn, err = net.DialTimeout("udp", addr, 5*time.Second)
	}
	if err != nil {
		return fmt.Errorf("syslog dial %s: %w", addr, err)
	}
	defer conn.Close()
	_, err = fmt.Fprintln(conn, msg)
	return err
}

// ─── Splunk HEC ───────────────────────────────────────────────────────────────

func (f *Forwarder) forwardSplunkHEC(ctx context.Context, t *Target, alert *AlertPayload) error {
	scheme := "http"
	if t.TLSEnabled {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/services/collector/event", scheme, t.Host, t.Port)

	body, _ := json.Marshal(map[string]interface{}{
		"time":       alert.CreatedAt.Unix(),
		"host":       alert.Hostname,
		"source":     "kizashi-edr",
		"sourcetype": "edr:alert",
		"index":      t.IndexName,
		"event": map[string]interface{}{
			"id":              alert.ID,
			"agent_id":        alert.AgentID,
			"hostname":        alert.Hostname,
			"os":              alert.OS,
			"rule_name":       alert.RuleName,
			"severity":        alert.Severity,
			"status":          alert.Status,
			"mitre_technique": alert.MITRETechnique,
			"threat_name":     alert.AIThreatName,
			"summary":         alert.AISummary,
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+t.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("splunk HEC returned %d", resp.StatusCode)
	}
	return nil
}

// ─── Elastic ECS ──────────────────────────────────────────────────────────────

func (f *Forwarder) forwardElasticECS(ctx context.Context, t *Target, alert *AlertPayload) error {
	scheme := "http"
	if t.TLSEnabled {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/%s/_doc", scheme, t.Host, t.Port, t.IndexName)

	body, _ := json.Marshal(map[string]interface{}{
		"@timestamp": alert.CreatedAt.UTC().Format(time.RFC3339Nano),
		"event": map[string]interface{}{
			"id":       alert.ID,
			"kind":     "alert",
			"severity": alert.Severity,
			"outcome":  alert.Status,
		},
		"host": map[string]interface{}{
			"name": alert.Hostname,
			"os":   map[string]interface{}{"name": alert.OS},
		},
		"rule":         map[string]interface{}{"name": alert.RuleName},
		"threat":       map[string]interface{}{"technique": map[string]interface{}{"id": alert.MITRETechnique}},
		"edr.agent_id": alert.AgentID,
		"edr.threat":   alert.AIThreatName,
		"edr.summary":  alert.AISummary,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "ApiKey "+t.Token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("elastic returned %d", resp.StatusCode)
	}
	return nil
}
