// Package sync provides community threat intelligence synchronization.
// SigmaHQSyncer fetches detection rules from the SigmaHQ/sigma GitHub
// repository and imports them into the local rules store.
//
// Strategy:
//  1. Fetch the full git-tree from GitHub API in one request.
//  2. Filter paths to the configured rule categories.
//  3. Download raw file content from raw.githubusercontent.com
//     (not counted against GitHub API rate limits).
//  4. Parse YAML metadata and upsert into the rules table.
package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/edr-platform/server/internal/store"
)

// DefaultSyncPaths lists the SigmaHQ rule directories to import. Scope is
// deliberately limited to categories that map onto telemetry the agent actually
// emits — importing a category we cannot populate (e.g. process_access without
// GrantedAccess) just adds rules that are inert in production (see the
// field-support audit). Each path below has a corresponding event type:
//
//	process_creation → process events    registry → registry ETW
//	network_connection/network → network image_load → image-load ETW
//	dns_query → DNS ETW                  powershell → script (4104) ETW
//	file_event → file events
var DefaultSyncPaths = []string{
	"rules/windows/process_creation",
	"rules/windows/network_connection",
	"rules/windows/file_event",
	"rules/windows/registry",
	"rules/windows/image_load", // DLL sideloading etc. — image-load ETW collector
	"rules/windows/dns_query",  // DNS ETW collector
	"rules/windows/powershell", // ScriptBlock (4104) — script ETW collector
	// Cross-process injection (Sysmon EID8). source_image/target_image/
	// source_pid/target_pid are already field-supported via the alias layer
	// (see alert_pipeline.go addPipelineSigmaAliases), so these rules pass the
	// field-support gate; the ETW thread sensor and the credential-access
	// sensor populate the telemetry. Without this the whole T1055 injection
	// rule family was never imported despite the plumbing being ready.
	"rules/windows/create_remote_thread",
	"rules/linux/process_creation",
	"rules/linux/network",
	"rules/linux/file_event",
	"rules/macos/process_creation", // macOS process telemetry
	// NOTE: "rules/network" is deliberately excluded — it is SigmaHQ's Zeek-only
	// directory (logsource product: zeek). The agent has no Zeek-equivalent
	// collector (no id.orig_h/id.resp_p/DNS Z-flag/qtype fields), so these rules
	// have no real field mapping. Because the evaluator does not gate on
	// logsource and a negated selection over an entirely-missing field trivially
	// evaluates to true (see field_support.go), rules from this path were
	// mis-classified as field-supported and auto-enabled while matching nearly
	// every event of any type — see the FP-storm incident on
	// "Publicly Accessible RDP Service" / "Suspicious DNS Z Flag Bit Set".
}

const (
	sigmaHQOwner  = "SigmaHQ"
	sigmaHQRepo   = "sigma"
	sigmaHQBranch = "master"
	// Concurrency limit for raw content fetches
	fetchConcurrency = 10
)

// SyncStatus is a snapshot of an in-progress or completed sync job.
type SyncStatus struct {
	Running    bool      `json:"running"`
	Imported   int       `json:"imported"`
	Updated    int       `json:"updated"`
	Skipped    int       `json:"skipped"`
	Failed     int       `json:"failed"`
	Total      int       `json:"total"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Errors     []string  `json:"errors,omitempty"`
}

// SigmaHQSyncer fetches and imports community Sigma rules from GitHub.
type SigmaHQSyncer struct {
	store       *store.RuleStore
	client      *http.Client
	githubToken string

	mu     sync.Mutex
	status *SyncStatus
}

// NewSigmaHQSyncer creates a SigmaHQSyncer.
// githubToken is optional but increases the GitHub API rate limit from
// 60 req/hr to 5000 req/hr. Set to "" to use unauthenticated access.
func NewSigmaHQSyncer(s *store.RuleStore, githubToken string) *SigmaHQSyncer {
	return &SigmaHQSyncer{
		store:       s,
		client:      &http.Client{Timeout: 30 * time.Second},
		githubToken: githubToken,
	}
}

// Status returns a snapshot of the current (or last) sync status.
func (s *SigmaHQSyncer) Status() *SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == nil {
		return nil
	}
	cp := *s.status
	cp.Errors = append([]string(nil), s.status.Errors...)
	return &cp
}

// IsRunning reports whether a sync is in progress.
func (s *SigmaHQSyncer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status != nil && s.status.Running
}

// Sync fetches rules from the configured SigmaHQ paths and imports them.
// It runs synchronously and updates the internal status as it progresses.
// autoEnable=true enables imported rules immediately; otherwise they are
// imported as disabled for manual review.
func (s *SigmaHQSyncer) Sync(ctx context.Context, autoEnable bool, paths []string) error {
	if s.IsRunning() {
		return fmt.Errorf("同期は既に実行中です")
	}

	if len(paths) == 0 {
		paths = DefaultSyncPaths
	}

	s.mu.Lock()
	s.status = &SyncStatus{Running: true, StartedAt: time.Now()}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.status.Running = false
		s.status.FinishedAt = time.Now()
		s.mu.Unlock()
	}()

	// Step 1: Fetch the full repository tree in one API call
	slog.Info("SigmaHQのリポジトリツリーを取得中")
	tree, err := s.fetchRepoTree(ctx)
	if err != nil {
		return fmt.Errorf("リポジトリツリーの取得に失敗しました: %w", err)
	}

	// Step 2: Filter to target paths
	var targetFiles []string
	for _, item := range tree {
		if item.Type != "blob" || !strings.HasSuffix(item.Path, ".yml") {
			continue
		}
		for _, prefix := range paths {
			if strings.HasPrefix(item.Path, prefix+"/") {
				targetFiles = append(targetFiles, item.Path)
				break
			}
		}
	}

	s.mu.Lock()
	s.status.Total = len(targetFiles)
	s.mu.Unlock()

	slog.Info("SigmaHQルールファイルを発見しました", "count", len(targetFiles))

	// Step 3: Fetch and parse files with bounded concurrency
	sem := make(chan struct{}, fetchConcurrency)
	var wg sync.WaitGroup

	for _, path := range targetFiles {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.processFile(ctx, p, autoEnable)
		}(path)
	}
	wg.Wait()

	st := s.Status()
	slog.Info("SigmaHQ同期完了",
		"imported", st.Imported,
		"updated", st.Updated,
		"skipped", st.Skipped,
		"failed", st.Failed,
	)
	return nil
}

// processFile fetches a single Sigma YAML file, parses it, and upserts into DB.
func (s *SigmaHQSyncer) processFile(ctx context.Context, path string, autoEnable bool) {
	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/%s/%s/%s/%s",
		sigmaHQOwner, sigmaHQRepo, sigmaHQBranch, path,
	)

	content, err := s.fetchRaw(ctx, rawURL)
	if err != nil {
		s.recordError(fmt.Sprintf("%s: fetch failed: %v", path, err))
		return
	}

	rule, err := parseSigmaYAML(content, path, autoEnable)
	if err != nil {
		// Skip rules with parse errors (experimental/broken rules)
		s.mu.Lock()
		s.status.Skipped++
		s.mu.Unlock()
		return
	}

	created, err := s.store.Upsert(ctx, rule)
	if err != nil {
		s.recordError(fmt.Sprintf("%s: db upsert failed: %v", path, err))
		return
	}

	s.mu.Lock()
	if created {
		s.status.Imported++
	} else {
		s.status.Updated++
	}
	s.mu.Unlock()
}

func (s *SigmaHQSyncer) recordError(msg string) {
	s.mu.Lock()
	s.status.Failed++
	if len(s.status.Errors) < 50 { // cap error list
		s.status.Errors = append(s.status.Errors, msg)
	}
	s.mu.Unlock()
}

// ─── GitHub API ────────────────────────────────────────────────

type treeItem struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" | "tree"
}

func (s *SigmaHQSyncer) fetchRepoTree(ctx context.Context) ([]treeItem, error) {
	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1",
		sigmaHQOwner, sigmaHQRepo, sigmaHQBranch,
	)

	body, err := s.fetch(ctx, url)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Tree      []treeItem `json:"tree"`
		Truncated bool       `json:"truncated"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("tree JSONのパースに失敗しました: %w", err)
	}
	if resp.Truncated {
		slog.Warn("GitHubツリーレスポンスが切り捨てられました — 一部のルールがスキップされます")
	}
	return resp.Tree, nil
}

func (s *SigmaHQSyncer) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "edr-platform-sync/1.0")
	if s.githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.githubToken)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func (s *SigmaHQSyncer) fetchRaw(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "edr-platform-sync/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ─── YAML Parsing ─────────────────────────────────────────────

// sigmaYAML is a minimal representation of a Sigma rule YAML for metadata extraction.
type sigmaYAML struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Status      string   `yaml:"status"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	Level       string   `yaml:"level"`
	Logsource   struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
	} `yaml:"logsource"`
}

func parseSigmaYAML(content []byte, path string, autoEnable bool) (*store.RuleRow, error) {
	var sig sigmaYAML
	if err := yaml.Unmarshal(content, &sig); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	if sig.ID == "" || sig.Title == "" {
		return nil, fmt.Errorf("missing required fields (id or title)")
	}

	// Skip experimental rules unless they're all we have
	if sig.Status == "deprecated" {
		return nil, fmt.Errorf("deprecated rule")
	}

	// Map Sigma level → severity (1-10)
	severity := levelToSeverity(sig.Level)

	// Extract MITRE ATT&CK technique IDs from tags
	var mitreTags []string
	for _, tag := range sig.Tags {
		// tags like "attack.t1059.001" or "attack.lateral_movement"
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			// Normalize: "attack.t1059.001" → "T1059.001"
			tech := strings.TrimPrefix(lower, "attack.")
			mitreTags = append(mitreTags, strings.ToUpper(tech))
		}
	}

	// Infer platform from logsource
	platforms := inferPlatforms(sig.Logsource.Product, path)

	// Only enable stable rules on auto-enable
	enabled := autoEnable && (sig.Status == "stable" || sig.Status == "test")

	desc := sig.Description
	return &store.RuleRow{
		ID:          sig.ID,
		Name:        sig.Title,
		Type:        "sigma",
		Platform:    platforms,
		Severity:    severity,
		Content:     string(content),
		Enabled:     enabled,
		Source:      "sigmahq",
		MITRETags:   mitreTags,
		AutoIsolate: false,
		AutoKill:    false,
		Description: &desc,
	}, nil
}

func levelToSeverity(level string) int {
	switch strings.ToLower(level) {
	case "informational":
		return 1
	case "low":
		return 3
	case "medium":
		return 5
	case "high":
		return 7
	case "critical":
		return 9
	default:
		return 5
	}
}

func inferPlatforms(product, path string) []string {
	product = strings.ToLower(product)
	switch {
	case product == "windows" || strings.Contains(path, "/windows/"):
		return []string{"windows"}
	case product == "linux" || strings.Contains(path, "/linux/"):
		return []string{"linux"}
	case product == "macos" || product == "darwin":
		return []string{"macos"}
	default:
		return []string{"windows", "linux", "macos"}
	}
}
