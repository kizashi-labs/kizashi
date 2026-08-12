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
	IsIsolated() bool
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
