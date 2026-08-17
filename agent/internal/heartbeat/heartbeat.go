// Package heartbeat sends periodic health reports to the EDR server.
package heartbeat

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Reporter sends periodic heartbeat messages to the EDR server.
type Reporter struct {
	agentID   string
	version   string
	osVersion func() string // called each heartbeat so service-startup failures are retried
	hostname  string
	sender    HeartbeatSender
	interval  time.Duration
	isolated  func() bool
	buffered  func() int
	unisolate func() error
	// protectionMode is the host's detected kernel-protection tier
	// (enforce/observe/poll), reported each heartbeat. Set via SetProtectionMode
	// after construction so the constructor signature stays stable.
	protectionMode string
	// telemetryMode reports which mechanism the collectors are *actually* running
	// on (ebpf/poll/off). Distinct from protectionMode, which describes what the
	// host is capable of: a capable host still degrades to polling when the binary
	// lacks the ebpf tag or a consumer fails to load, and that difference is
	// invisible without this. Read through a func so each heartbeat picks up the
	// current value rather than one latched at startup.
	telemetryMode func() string
	// applyGuard persists uninstall-guard material handed back by the server.
	// Injected rather than called directly so this package keeps no dependency
	// on the on-disk layout, and so tests can observe delivery without touching
	// a filesystem. Nil until SetUninstallGuardApplier is called.
	applyGuard func(*UninstallGuardMaterial) error
}

// SetUninstallGuardApplier installs the callback that persists uninstall-guard
// material received on a heartbeat. Set after construction, alongside the other
// optional wiring, to keep the constructor signature stable.
func (r *Reporter) SetUninstallGuardApplier(f func(*UninstallGuardMaterial) error) {
	r.applyGuard = f
}

// SetProtectionMode sets the protection capability tier reported in heartbeats.
func (r *Reporter) SetProtectionMode(mode string) {
	r.protectionMode = mode
}

// SetTelemetryModeFunc sets the source of the effective-collection-mode value
// reported in heartbeats. Collectors settle into their mode asynchronously after
// startup, so this is a func rather than a value.
func (r *Reporter) SetTelemetryModeFunc(f func() string) {
	r.telemetryMode = f
}

// HeartbeatSender abstracts the transport layer.
type HeartbeatSender interface {
	SendHeartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error)
}

// HeartbeatRequest contains agent health information.
type HeartbeatRequest struct {
	AgentID      string
	AgentVersion string
	// OSType is runtime.GOOS ("windows"|"linux"|"darwin"), matching the
	// agents.os_type CHECK constraint. Without it the server had to guess, and
	// its fallback mislabeled every heartbeat-created agent as Linux.
	OSType         string
	OSVersion      string
	Hostname       string
	IPAddresses    []string
	EventsBuffered int
	CPUUsage       float64
	MemoryUsageMB  float64
	Status         string // online|isolated|error
	ConfigVersion  uint64
	ProtectionMode string // enforce|observe|poll (kernel protection tier — host capability)
	TelemetryMode  string // ebpf|poll|off (collection mechanism actually in use)
}

// HeartbeatResponse from the server.
type HeartbeatResponse struct {
	ConfigUpdateAvailable bool
	LatestConfigVersion   uint64
	PendingCommandCount   int
	// ShouldUnisolate is set by the server when the DB shows the agent should no
	// longer be isolated (e.g. an admin clicked "unisolate") but the agent is still
	// reporting status=isolated. This allows the agent to self-unisolate even when
	// the gRPC command stream is unavailable.
	ShouldUnisolate bool
	// UninstallGuard carries the tenant's uninstall-password material (a PBKDF2
	// salt and digest — never the password). Nil when the tenant has not set
	// one, or when talking to a server that predates the feature.
	//
	// It rides the heartbeat rather than a dedicated fetch because the guard has
	// to be on disk *before* it is needed: verification happens with the network
	// plausibly cut, so there is no opportunity to go and get it at uninstall
	// time. The heartbeat already runs on every agent on a short interval, which
	// is exactly the delivery property required.
	UninstallGuard *UninstallGuardMaterial
}

// UninstallGuardMaterial is the wire form of the uninstall guard. Field names
// match the on-disk guard file so the agent can persist it without a lossy
// translation step in between.
type UninstallGuardMaterial struct {
	Version    int       `json:"version"`
	Algorithm  string    `json:"algorithm"`
	Iterations int       `json:"iterations"`
	SaltB64    string    `json:"salt"`
	DigestB64  string    `json:"digest"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func NewReporter(agentID, version string, osVersion func() string, hostname string, sender HeartbeatSender,
	interval time.Duration, isolated func() bool, buffered func() int, unisolate func() error) *Reporter {
	return &Reporter{
		agentID:   agentID,
		version:   version,
		osVersion: osVersion,
		hostname:  hostname,
		sender:    sender,
		interval:  interval,
		isolated:  isolated,
		buffered:  buffered,
		unisolate: unisolate,
	}
}

// Run sends heartbeats at the configured interval until context is cancelled.
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Send one immediately
	r.sendOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sendOnce(ctx)
		}
	}
}

func (r *Reporter) sendOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	status := "online"
	if r.isolated != nil && r.isolated() {
		status = "isolated"
	}

	req := &HeartbeatRequest{
		AgentID:      r.agentID,
		AgentVersion: r.version,
		// runtime.GOOS は "windows"/"linux"/"darwin" を返し、
		// agents.os_type の CHECK 制約とそのまま一致する。
		OSType:         runtime.GOOS,
		OSVersion:      r.osVersion(),
		Hostname:       r.hostname,
		IPAddresses:    getLocalIPs(),
		EventsBuffered: 0,
		CPUUsage:       getCPUUsage(),
		MemoryUsageMB:  getMemUsageMB(),
		Status:         status,
		ProtectionMode: r.protectionMode,
	}

	if r.telemetryMode != nil {
		req.TelemetryMode = r.telemetryMode()
	}

	if r.buffered != nil {
		req.EventsBuffered = r.buffered()
	}

	resp, err := r.sender.SendHeartbeat(ctx, req)
	if err != nil {
		slog.Debug("heartbeat failed", "error", err)
		return
	}

	if resp.ConfigUpdateAvailable {
		slog.Info("config update available", "version", resp.LatestConfigVersion)
	}
	if resp.PendingCommandCount > 0 {
		slog.Info("pending commands from server", "count", resp.PendingCommandCount)
	}
	// Persist the uninstall guard before anything else that could fail: the
	// whole point is for it to be on disk ahead of the moment it is needed, and
	// that moment may be a few seconds from now.
	if resp.UninstallGuard != nil && r.applyGuard != nil {
		if err := r.applyGuard(resp.UninstallGuard); err != nil {
			slog.Warn("アンインストール保護の設定を保存できませんでした", "error", err)
		}
	}
	if resp.ShouldUnisolate && r.unisolate != nil {
		slog.Info("サーバーからの隔離解除指示を受信しました（ハートビート経由）")
		if err := r.unisolate(); err != nil {
			slog.Error("ハートビート経由の隔離解除に失敗しました", "error", err)
		} else {
			slog.Info("ハートビート経由の隔離解除が完了しました")
		}
	}
}

// ─── System Metrics ───────────────────────────────────────────

func getCPUUsage() float64 {
	// Simplified - real implementation reads /proc/stat on Linux,
	// GetSystemTimes on Windows, host_cpu_load_info on macOS
	return 0.0
}

func getMemUsageMB() float64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.Sys) / 1024 / 1024
}

func getLocalIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}
	}
	var ips []string
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.To4() != nil {
			ips = append(ips, ip.String())
		}
	}

	// NATやクラウド環境ではNICにパブリックIPが見えないため、
	// メタデータサービスからパブリックIPを取得してフォールバック。
	// EC2 (169.254.169.254) と Azure IMDS (169.254.169.254/metadata) の両方を試みる。
	if pub := fetchPublicIP(); pub != "" {
		// 重複追加を避ける
		for _, existing := range ips {
			if existing == pub {
				return ips
			}
		}
		ips = append(ips, pub)
	}

	return ips
}

const (
	// metadataTimeout はメタデータサービス1エンドポイントあたりの上限。
	// IMDSはlink-local上にあり正常時は数ミリ秒で応答するため、これ以上待つ意味はない。
	// 非クラウド環境（特にWindows）では169.254.169.254へのTCP接続が即座には
	// 失敗せずブロックするため、この上限がハートビート送信の遅延を決める。
	metadataTimeout = 300 * time.Millisecond
	// publicIPTTL は取得成功時のキャッシュ有効期間。パブリックIPはほぼ変化しない。
	publicIPTTL = time.Hour
	// publicIPFailureTTL は取得失敗時のキャッシュ有効期間（ネガティブキャッシュ）。
	// 非クラウド環境でハートビート毎（既定30秒）にプローブし続けないための短めのTTL。
	// ネットワーク復帰やクラウド移行を取りこぼさない程度に短く保つ。
	publicIPFailureTTL = 10 * time.Minute
)

var (
	publicIPMu     sync.Mutex
	publicIPCached string
	publicIPExpiry time.Time
)

// fetchPublicIP はクラウドメタデータサービスからパブリックIPを取得する。
// 結果はTTL付きでキャッシュされ、ハートビート毎のプローブを避ける。
// 取得できない場合は空文字を返す。
func fetchPublicIP() string {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()

	if time.Now().Before(publicIPExpiry) {
		return publicIPCached
	}

	ip := probePublicIP()
	publicIPCached = ip
	if ip != "" {
		publicIPExpiry = time.Now().Add(publicIPTTL)
	} else {
		publicIPExpiry = time.Now().Add(publicIPFailureTTL)
	}
	return ip
}

// probePublicIP は各クラウドのメタデータエンドポイントを順に試す。キャッシュは見ない。
func probePublicIP() string {
	client := &http.Client{Timeout: metadataTimeout}

	// AWS EC2 IMDSv2（トークン取得 → パブリックIP取得）
	if ip := fetchAWSIMDSv2(client); ip != "" {
		return ip
	}

	// AWS EC2 IMDSv1（フォールバック）
	if ip := fetchURL(client, "http://169.254.169.254/latest/meta-data/public-ipv4", nil); ip != "" {
		return ip
	}

	// Azure IMDS
	if ip := fetchURL(client, "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text",
		map[string]string{"Metadata": "true"}); ip != "" {
		return ip
	}

	// GCP メタデータ
	if ip := fetchURL(client, "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
		map[string]string{"Metadata-Flavor": "Google"}); ip != "" {
		return ip
	}

	return ""
}

func fetchAWSIMDSv2(client *http.Client) string {
	// Step 1: トークン取得
	tokenReq, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return ""
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return ""
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		return ""
	}
	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return ""
	}
	token := strings.TrimSpace(string(tokenBytes))

	// Step 2: パブリックIP取得
	return fetchURL(client, "http://169.254.169.254/latest/meta-data/public-ipv4",
		map[string]string{"X-aws-ec2-metadata-token": token})
}

func fetchURL(client *http.Client, url string, headers map[string]string) string {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
