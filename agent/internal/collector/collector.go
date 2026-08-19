// Package collector defines the platform-agnostic collection interfaces.
// Each OS implements these interfaces in the platform/ subdirectory.
package collector

import (
	"context"
	"time"
)

// ─── Event Types ──────────────────────────────────────────────

type FileHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

type ProcessEvent struct {
	ID          string
	Timestamp   time.Time
	PID         uint32
	PPID        uint32
	ProcessName string
	CommandLine string
	ImagePath   string
	Username    string
	SessionID   string
	Hashes      FileHashes
	Action      string   // create|terminate|inject|hollow
	EnvVars     []string // security-relevant env vars only (LD_PRELOAD etc.)
	// PE VERSIONINFO (Windows only, best-effort). Drives SigmaHQ renamed-binary /
	// LOLBin process_creation rules that identify a binary by its embedded version
	// metadata rather than its path. Empty when unavailable.
	OriginalFileName string // Sigma OriginalFileName
	FileDescription  string // Sigma Description
	ProductName      string // Sigma Product
	CompanyName      string // Sigma Company
	// Windows process token integrity level as the Sysmon label
	// (Untrusted|Low|Medium|High|System). Drives UAC-bypass / privesc rules.
	IntegrityLevel string // Sigma IntegrityLevel
	// Windows logon session ID as the Sysmon hex LUID (e.g. "0x3e7" = SYSTEM).
	LogonID string // Sigma LogonId
	// The parent process, resolved on the endpoint by ParentResolver (parent.go)
	// while the parent is still alive, and filled centrally from PPID. A sensor
	// that gets the parent from the kernel alongside the child may set these
	// directly instead; none does today. Empty when the parent exited before the
	// child was observed. See parent.go for why ppid alone was never enough.
	ParentName  string // Sigma ParentImage (basename)
	ParentImage string // Sigma ParentImage (full path)
	// Container containment, derived from /proc on Linux (container.go). Zero
	// when the process is not in a container, or on a platform where the agent
	// cannot tell. container_name / image_name are not here: they are runtime
	// bookkeeping rather than kernel state and would need a runtime API client.
	Container ContainerContext
}

type FileEvent struct {
	ID          string
	Timestamp   time.Time
	Path        string
	OldPath     string // for renames
	Action      string // create|modify|delete|rename|execute
	Hashes      FileHashes
	PID         uint32
	ProcessName string
	FileSize    int64
}

type NetworkEvent struct {
	ID          string
	Timestamp   time.Time
	SrcIP       string
	SrcPort     uint16
	DstIP       string
	DstPort     uint16
	Protocol    string // tcp|udp|icmp
	Direction   string // inbound|outbound
	BytesSent   uint64
	BytesRecv   uint64
	PID         uint32
	ProcessName string
	Hostname    string
}

type DNSEvent struct {
	ID          string
	Timestamp   time.Time
	Query       string
	QueryType   string
	Answers     []string
	PID         uint32
	ProcessName string
}

type RegistryEvent struct {
	ID          string
	Timestamp   time.Time
	KeyPath     string
	ValueName   string
	ValueData   string
	Action      string // create|modify|delete|query
	PID         uint32
	ProcessName string
}

type AuthEvent struct {
	ID         string
	Timestamp  time.Time
	Username   string
	Action     string // login|logout|privilege|failed
	Success    bool
	SourceIP   string
	AuthMethod string
	FailReason string
	LogonType  string // Windows 4624/4625 LogonType (e.g. "3"=Network, "10"=RDP); "" on non-Windows
	// EventID is the raw Windows Security-log event id (4624/4625/4634/4672/
	// 4765/4766/4768/4769); 0 on non-Windows.
	//
	// 数値で持つ。読む側 (detection の auth_attack と、SID-History を Sigma の
	// EventID に出す門) が toFloat64 を通しており、文字列を受け取らない。
	// SID-History (4765/4766) は他に区別できる欄が無いため、これが無いと
	// ルールの書き方に関わらず検知できない。
	EventID uint32
	// Kerberos service-ticket fields, from Security 4769 (TGS-REQ). Empty for
	// every other kind of authentication. TargetSPN is the ServiceName; the
	// encryption type is the hex string Windows logs (0x17/0x18 = RC4, i.e.
	// crackable offline — the Kerberoasting signal). See kerberos.go.
	TargetSPN            string
	TicketEncryptionType string
}

// ImageLoadEvent records a module/DLL load (for DLL side-loading detection).
type ImageLoadEvent struct {
	ID              string
	Timestamp       time.Time
	ImagePath       string // loaded module/DLL
	PID             uint32
	ProcessName     string
	Signed          bool
	SignatureStatus string // valid|invalid|unsigned|expired|unknown
	Signer          string
	Hashes          FileHashes
}

// ScriptContentEvent records deobfuscated script content (PowerShell
// ScriptBlock / AMSI) for fileless/obfuscated-execution detection.
type ScriptContentEvent struct {
	ID          string
	Timestamp   time.Time
	Engine      string // powershell|amsi|wscript|jscript|vba
	Content     string // deobfuscated script text
	PID         uint32
	ProcessName string
	ContentHash string // sha256 of content
	BlockNumber uint32
	BlockTotal  uint32
}

// ─── Collector Interfaces ─────────────────────────────────────

// ProcessCollector monitors process lifecycle events.
type ProcessCollector interface {
	Start(ctx context.Context, out chan<- ProcessEvent) error
	Stop() error
}

// FileCollector monitors filesystem changes.
type FileCollector interface {
	Start(ctx context.Context, out chan<- FileEvent) error
	Stop() error
	SetPaths(monitored []string, excluded []string)
}

// NetworkCollector monitors network connections.
type NetworkCollector interface {
	Start(ctx context.Context, out chan<- NetworkEvent) error
	Stop() error
}

// DNSCollector monitors DNS queries.
type DNSCollector interface {
	Start(ctx context.Context, out chan<- DNSEvent) error
	Stop() error
}

// RegistryCollector monitors Windows registry (Windows only; no-op on others).
type RegistryCollector interface {
	Start(ctx context.Context, out chan<- RegistryEvent) error
	Stop() error
}

// AuthCollector monitors authentication events.
type AuthCollector interface {
	Start(ctx context.Context, out chan<- AuthEvent) error
	Stop() error
}

// ImageLoadCollector monitors module/DLL loads (Windows ETW; no-op elsewhere).
type ImageLoadCollector interface {
	Start(ctx context.Context, out chan<- ImageLoadEvent) error
	Stop() error
}

// ScriptContentCollector monitors script content (Windows ETW; no-op elsewhere).
type ScriptContentCollector interface {
	Start(ctx context.Context, out chan<- ScriptContentEvent) error
	Stop() error
}

// ─── Response Interface ───────────────────────────────────────

// IsolationManager handles network isolation of the endpoint.
type IsolationManager interface {
	// Isolate blocks all traffic except the given allowed IPs/ports + EDR server.
	Isolate(allowedIPs []string, allowedPorts []uint16) error
	// Unisolate restores normal network access.
	Unisolate() error
	// IsIsolated returns the current isolation state.
	//
	// 注意: これはエージェントのメモリ上の状態であって、ホストの実態ではない。
	// 実際にルールが入っているかは VerifyIsolation で確かめる。
	IsIsolated() bool
	// VerifyIsolation reads the host's actual firewall state.
	//
	// Isolate() が終了コード 0 を返しても、ルールが入っている保証はない。
	// 適用後に別の何かが流すこともある（iptables -F は珍しくない）。
	// 「隔離した」と報告する前に、ここで実態を確かめる。
	//
	// 第 2 返り値が非 nil のときは、状態を確認できなかったということ。
	// 「隔離されていない」と混同してはいけない — 前者は分からない、
	// 後者は分かったうえで入っていない、で対処が違う。
	VerifyIsolation() (bool, error)
}

// ProcessManager handles process response actions.
type ProcessManager interface {
	// Kill terminates a process by PID.
	Kill(pid uint32) error
}

// FileQuarantine handles file quarantine operations.
type FileQuarantine interface {
	// Quarantine moves a file to the quarantine directory and returns a quarantine ID.
	Quarantine(path string) (quarantineID string, err error)
	// Restore moves a quarantined file back to its original (or specified) path.
	Restore(quarantineID string, restorePath string) error
	// List returns all quarantined files.
	List() ([]QuarantinedFile, error)
}

type QuarantinedFile struct {
	ID            string
	OriginalPath  string
	QuarantinedAt time.Time
	Hashes        FileHashes
	AlertID       string
}
