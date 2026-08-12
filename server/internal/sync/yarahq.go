// Package sync provides community threat intelligence synchronization.
// YARAHQSyncer fetches detection rules from the Yara-Rules/community GitHub
// repository and imports them into the local yara_rules store.
//
// Strategy:
//  1. Fetch the full git-tree from GitHub API in one request.
//  2. Filter paths to .yar files under the configured directories.
//  3. Download raw file content from raw.githubusercontent.com
//     (not counted against GitHub API rate limits).
//  4. Parse each .yar file, split into individual rules, and upsert into DB.
package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/store"
)

const (
	yaraHQOwner  = "Yara-Rules"
	yaraHQRepo   = "rules"
	yaraHQBranch = "master"

	// 取得先のベース URL。テストから差し替えられるよう、組み立て時は
	// 定数を直接使わず YARAHQSyncer のフィールドを参照する。
	defaultYARAAPIBase = "https://api.github.com"
	defaultYARARawBase = "https://raw.githubusercontent.com"
)

// DefaultYARAPaths lists the Yara-Rules/rules directories to import.
// Directory names in the repo are lowercase (e.g., malware, exploit_kits).
var DefaultYARAPaths = []string{
	"malware",
	"antidebug_antivm",
	"exploit_kits",
	"cve_rules",
	"maldocs",
	"packers",
	"mobile_malware",
}

// Compiled regexes for YARA rule parsing.
var (
	reRuleName   = regexp.MustCompile(`(?m)^\s*rule\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{`)
	reRuleTags   = regexp.MustCompile(`(?m)^\s*rule\s+\w+\s*:\s*([\w\s]+)\s*\{`)
	reMetaDesc   = regexp.MustCompile(`(?i)(?:description|desc)\s*=\s*"([^"]*)"`)
	reMetaSev    = regexp.MustCompile(`(?i)severity\s*=\s*"([^"]*)"`)
	reMetaAuthor = regexp.MustCompile(`(?i)author\s*=\s*"([^"]*)"`)
	reWordBound  = regexp.MustCompile(`[_]+`)
	reCamelBound = regexp.MustCompile(`([a-z])([A-Z])`)
)

// YARAHQSyncer fetches and imports community YARA rules from GitHub.
type YARAHQSyncer struct {
	store       *store.YARAStore
	client      *http.Client
	githubToken string

	// 取得先のベース URL。既定は GitHub 本体で、テストが httptest サーバへ
	// 向けるためだけに差し替える。
	apiBase string
	rawBase string

	mu     sync.Mutex
	status *SyncStatus
}

// NewYARAHQSyncer creates a YARAHQSyncer.
func NewYARAHQSyncer(s *store.YARAStore, githubToken string) *YARAHQSyncer {
	return &YARAHQSyncer{
		store:       s,
		client:      &http.Client{Timeout: 30 * time.Second},
		githubToken: githubToken,
		apiBase:     defaultYARAAPIBase,
		rawBase:     defaultYARARawBase,
	}
}

// Status returns a snapshot of the current (or last) sync status.
func (s *YARAHQSyncer) Status() *SyncStatus {
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
func (s *YARAHQSyncer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status != nil && s.status.Running
}

// isRecommendedRule returns true for rules that should be enabled by default.
// Recommended = CVE rules (high specificity) + webshell rules (critical for servers)
// + malware rules with critical severity.
func isRecommendedRule(filePath, name, severity string) bool {
	lower := strings.ToLower(filePath + " " + name)
	switch {
	case strings.Contains(lower, "cve"):
		return true // 特定CVEに対応する精度の高いルール
	case strings.Contains(lower, "webshell"):
		return true // Webサーバー運用環境で必須
	case severity == "critical":
		return true // クリティカル重要度のルール
	}
	return false
}

// Sync fetches YARA rules from the configured paths and imports them.
// autoEnable=true enables all imported rules; false imports as disabled except
// recommended rules (CVE, webshell, critical severity) which are always enabled.
func (s *YARAHQSyncer) Sync(ctx context.Context, autoEnable bool, paths []string) error {
	if s.IsRunning() {
		return fmt.Errorf("同期は既に実行中です")
	}
	if len(paths) == 0 {
		paths = DefaultYARAPaths
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

	slog.Info("Yara-Rules/rulesのリポジトリツリーを取得中")
	tree, err := s.fetchYARARepoTree(ctx)
	if err != nil {
		s.mu.Lock()
		s.status.Failed++
		s.status.Errors = append(s.status.Errors, fmt.Sprintf("リポジトリツリーの取得に失敗: %v", err))
		s.mu.Unlock()
		return fmt.Errorf("リポジトリツリーの取得に失敗しました: %w", err)
	}

	var targetFiles []string
	for _, item := range tree {
		if item.Type != "blob" || !strings.HasSuffix(item.Path, ".yar") {
			continue
		}
		for _, prefix := range paths {
			if strings.HasPrefix(item.Path, prefix+"/") || strings.HasPrefix(item.Path, prefix) {
				targetFiles = append(targetFiles, item.Path)
				break
			}
		}
	}

	s.mu.Lock()
	s.status.Total = len(targetFiles)
	s.mu.Unlock()

	slog.Info("YARAルールファイルを発見しました", "count", len(targetFiles))

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
			s.processYARAFile(ctx, p, autoEnable)
		}(path)
	}
	wg.Wait()

	st := s.Status()
	slog.Info("Yara-Rules/community同期完了",
		"imported", st.Imported,
		"updated", st.Updated,
		"skipped", st.Skipped,
		"failed", st.Failed,
	)
	return nil
}

// processYARAFile fetches a single .yar file, splits it into individual rules,
// and upserts each rule into the DB.
func (s *YARAHQSyncer) processYARAFile(ctx context.Context, path string, autoEnable bool) {
	rawURL := fmt.Sprintf(
		"%s/%s/%s/%s/%s",
		s.rawBase, yaraHQOwner, yaraHQRepo, yaraHQBranch, path,
	)

	content, err := s.fetchRaw(ctx, rawURL)
	if err != nil {
		s.recordYARAError(fmt.Sprintf("%s: fetch failed: %v", path, err))
		return
	}

	rules := parseYARARules(content, path, autoEnable)
	if len(rules) == 0 {
		s.mu.Lock()
		s.status.Skipped++
		s.mu.Unlock()
		return
	}

	for _, rule := range rules {
		created, err := s.store.Upsert(ctx, rule)
		if err != nil {
			s.recordYARAError(fmt.Sprintf("%s [%s]: db upsert failed: %v", path, rule.Name, err))
			continue
		}
		s.mu.Lock()
		if created {
			s.status.Imported++
		} else {
			s.status.Updated++
		}
		s.mu.Unlock()
	}
}

func (s *YARAHQSyncer) recordYARAError(msg string) {
	s.mu.Lock()
	s.status.Failed++
	if len(s.status.Errors) < 50 {
		s.status.Errors = append(s.status.Errors, msg)
	}
	s.mu.Unlock()
}

func (s *YARAHQSyncer) fetchYARARepoTree(ctx context.Context) ([]treeItem, error) {
	url := fmt.Sprintf(
		"%s/repos/%s/%s/git/trees/%s?recursive=1",
		s.apiBase, yaraHQOwner, yaraHQRepo, yaraHQBranch,
	)
	body, err := s.fetchYARA(ctx, url)
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

func (s *YARAHQSyncer) fetchYARA(ctx context.Context, url string) ([]byte, error) {
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
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func (s *YARAHQSyncer) fetchRaw(ctx context.Context, url string) ([]byte, error) {
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
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ─── YARA Parsing ─────────────────────────────────────────────────────────────

// parseYARARules splits a .yar file into individual rules and extracts metadata.
// Each rule is returned as an UpsertYARARuleInput ready for DB upsert.
func parseYARARules(content []byte, filePath string, autoEnable bool) []store.UpsertYARARuleInput {
	text := string(content)

	// Find all rule start positions
	matches := reRuleName.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	var results []store.UpsertYARARuleInput

	for i, m := range matches {
		name := text[m[2]:m[3]]

		// Extract rule body: from this match start to next rule start (or end of file)
		ruleStart := m[0]
		ruleEnd := len(text)
		if i+1 < len(matches) {
			ruleEnd = matches[i+1][0]
		}
		ruleBody := text[ruleStart:ruleEnd]

		// Extract meta block (between "meta:" and next section keyword)
		desc := extractMeta(reMetaDesc, ruleBody)
		if desc == "" {
			// メタブロックに description/desc がない場合、ルール名から説明文を生成
			desc = ruleNameToDescription(name, filePath, extractMeta(reMetaAuthor, ruleBody))
		}
		// 有効化ガイダンスをすべてのルールに追記
		desc = desc + " ▶ " + whenToEnableGuidance(filePath, name)
		// normalizeSeverityはwazuh.goで定義された共通関数を使用
		sev := normalizeSeverity(extractMeta(reMetaSev, ruleBody))
		if sev == "" {
			sev = severityFromPath(filePath)
		}

		// Extract YARA tags from rule declaration: rule Foo : tag1 tag2 {
		tags := extractYARATags(text[m[0] : m[3]+1])

		// autoEnable=true → 全ルールを有効化
		// autoEnable=false → 推奨ルールのみ有効化（CVE・Webシェル・Critical）
		enabled := autoEnable || isRecommendedRule(filePath, name, sev)

		results = append(results, store.UpsertYARARuleInput{
			Name:        name,
			Description: desc,
			Content:     strings.TrimSpace(ruleBody),
			Tags:        tags,
			Enabled:     enabled,
			Severity:    sev,
			Category:    inferCategory(filePath, name, tags),
		})
	}
	return results
}

func extractMeta(re *regexp.Regexp, body string) string {
	m := re.FindStringSubmatch(body)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractYARATags(ruleHeader string) []string {
	m := reRuleTags.FindStringSubmatch(ruleHeader)
	if len(m) < 2 {
		return []string{}
	}
	var tags []string
	for _, t := range strings.Fields(m[1]) {
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// InferCategory is the exported version of inferCategory for use outside this package.
func InferCategory(filePath, name string, tags []string) string {
	return inferCategory(filePath, name, tags)
}

// inferCategory maps a file path and rule name to a DB category string.
// Priority: path-based → name-based → tags-based → default "malware".
func inferCategory(filePath, name string, tags []string) string {
	lower := strings.ToLower(filePath + " " + name)

	switch {
	case strings.Contains(lower, "ransomware") || strings.Contains(lower, "ransom") ||
		strings.Contains(lower, "locker") || strings.Contains(lower, "cryptolocker"):
		return "ransomware"
	case strings.Contains(lower, "webshell") || strings.Contains(lower, "web_shell"):
		return "webshell"
	case strings.Contains(lower, "backdoor") || strings.Contains(lower, "back_door"):
		return "backdoor"
	case strings.Contains(lower, "trojan"):
		return "trojan"
	case strings.Contains(lower, "worm"):
		return "worm"
	case strings.Contains(lower, "rootkit") || strings.Contains(lower, "root_kit"):
		return "rootkit"
	case strings.Contains(lower, "exploit") || strings.Contains(lower, "exploit_kit"):
		return "exploit"
	case strings.Contains(lower, "cve"):
		return "exploit"
	case strings.Contains(lower, "maldoc") || strings.Contains(lower, "maldocument") ||
		strings.Contains(lower, "office_macro") || strings.Contains(lower, "macro"):
		return "maldoc"
	case strings.Contains(lower, "packer"):
		return "packer"
	case strings.Contains(lower, "antidebug") || strings.Contains(lower, "antivm") ||
		strings.Contains(lower, "anti_debug") || strings.Contains(lower, "anti_vm"):
		return "evasion"
	case strings.Contains(lower, "spyware") || strings.Contains(lower, "keylog") ||
		strings.Contains(lower, "infostealer") || strings.Contains(lower, "stealer"):
		return "spyware"
	case strings.Contains(lower, "mobile") || strings.Contains(lower, "android") ||
		strings.Contains(lower, "ios_"):
		return "mobile"
	case strings.Contains(lower, "apt") || strings.Contains(lower, "targeted"):
		return "apt"
	}

	// Tag-based fallback
	for _, t := range tags {
		tl := strings.ToLower(t)
		switch tl {
		case "ransomware":
			return "ransomware"
		case "webshell", "web_shell":
			return "webshell"
		case "backdoor":
			return "backdoor"
		case "trojan":
			return "trojan"
		case "rootkit":
			return "rootkit"
		case "exploit":
			return "exploit"
		case "apt":
			return "apt"
		case "spyware", "infostealer":
			return "spyware"
		case "evasion", "antidebug", "antivm":
			return "evasion"
		}
	}

	return "malware"
}

// ruleNameToDescription generates a human-readable description from a YARA rule name
// when no description is found in the meta block.
func ruleNameToDescription(name, filePath, author string) string {
	// Convert snake_case and CamelCase to readable words
	// e.g. "AntiDebug_CheckRemoteDebugger" → "AntiDebug Check Remote Debugger"
	readable := reWordBound.ReplaceAllString(name, " ")
	readable = reCamelBound.ReplaceAllString(readable, "$1 $2")
	readable = strings.TrimSpace(readable)

	// Infer category from path
	category := ""
	lower := strings.ToLower(filePath)
	switch {
	case strings.Contains(lower, "malware"):
		category = "マルウェア"
	case strings.Contains(lower, "antidebug"), strings.Contains(lower, "antivm"):
		category = "アンチデバッグ/アンチVM"
	case strings.Contains(lower, "exploit"):
		category = "エクスプロイト"
	case strings.Contains(lower, "cve"):
		category = "CVE"
	case strings.Contains(lower, "maldoc"):
		category = "悪意あるドキュメント"
	case strings.Contains(lower, "packer"):
		category = "パッカー"
	case strings.Contains(lower, "mobile"):
		category = "モバイルマルウェア"
	case strings.Contains(lower, "webshell"):
		category = "Webシェル"
	}

	desc := readable + " の検知ルール"
	if category != "" {
		desc = "[" + category + "] " + desc
	}
	if author != "" {
		desc += " (by " + author + ")"
	}
	return desc
}

// whenToEnableGuidance returns a Japanese guidance string indicating when to enable the rule.
func whenToEnableGuidance(filePath, name string) string {
	lower := strings.ToLower(filePath + " " + name)

	switch {
	// APT / Nation-state / targeted attack
	case strings.Contains(lower, "apt") || strings.Contains(lower, "nation") ||
		strings.Contains(lower, "targeted"):
		return "有効化の目安: 標的型攻撃・国家支援型APTが懸念される重要インフラ・金融・官公庁環境"

	// Ransomware
	case strings.Contains(lower, "ransomware") || strings.Contains(lower, "ransom") ||
		strings.Contains(lower, "locker") || strings.Contains(lower, "encrypt"):
		return "有効化の目安: ランサムウェア対策として全エンドポイントへの有効化を強く推奨"

	// CVE specific exploit
	case strings.Contains(lower, "cve"):
		return "有効化の目安: 対応するCVEの影響を受けるソフトウェアを使用している環境（パッチ適用前の緊急対策としても有効）"

	// Maldoc / Office / macro
	case strings.Contains(lower, "maldoc") || strings.Contains(lower, "office") ||
		strings.Contains(lower, "macro") || strings.Contains(lower, "word") ||
		strings.Contains(lower, "excel") || strings.Contains(lower, "pdf"):
		return "有効化の目安: メール添付ファイルやOffice文書を扱う環境・メールゲートウェイとの連携時"

	// Webshell
	case strings.Contains(lower, "webshell") || strings.Contains(lower, "web_shell"):
		return "有効化の目安: Webサーバーを運用している環境での有効化を強く推奨（侵害後のバックドア検知）"

	// Exploit kit / browser exploit
	case strings.Contains(lower, "exploit_kit") || strings.Contains(lower, "exploit kit") ||
		strings.Contains(lower, "browser") || strings.Contains(lower, "flash"):
		return "有効化の目安: Webブラウジングを行うエンドポイントや、ドライブバイダウンロード攻撃が懸念される環境"

	// AntiDebug / AntiVM
	case strings.Contains(lower, "antidebug") || strings.Contains(lower, "antivm") ||
		strings.Contains(lower, "debugger") || strings.Contains(lower, "sandbox"):
		return "有効化の目安: マルウェア解析・サンドボックス環境、またはアンチ解析回避技術の検知が必要な場合"

	// Packer / obfuscation
	case strings.Contains(lower, "packer") || strings.Contains(lower, "obfuscat") ||
		strings.Contains(lower, "upx") || strings.Contains(lower, "themida"):
		return "有効化の目安: 難読化・パッキングされたマルウェアの検知が必要な高セキュリティ環境"

	// Crypto mining / cryptojacking
	case strings.Contains(lower, "coin") || strings.Contains(lower, "miner") ||
		strings.Contains(lower, "mining") || strings.Contains(lower, "crypto"):
		return "有効化の目安: 仮想通貨マイニングマルウェア（クリプトジャッキング）が懸念されるサーバー・クラウド環境"

	// Rootkit / bootkit
	case strings.Contains(lower, "rootkit") || strings.Contains(lower, "bootkit") ||
		strings.Contains(lower, "bootsect"):
		return "有効化の目安: 高度な持続的侵害（ルートキット）が懸念される重要システム・サーバー環境"

	// Backdoor / RAT
	case strings.Contains(lower, "backdoor") || strings.Contains(lower, "rat") ||
		strings.Contains(lower, "remote_access") || strings.Contains(lower, "trojan"):
		return "有効化の目安: リモートアクセス型マルウェア（RAT・バックドア）の検知が必要な全エンドポイント"

	// Infostealer / credential
	case strings.Contains(lower, "stealer") || strings.Contains(lower, "credential") ||
		strings.Contains(lower, "keylog") || strings.Contains(lower, "password"):
		return "有効化の目安: 情報窃取マルウェアの検知が必要な全エンドポイント（特に機密情報を扱う端末）"

	// Mobile
	case strings.Contains(lower, "mobile") || strings.Contains(lower, "android") ||
		strings.Contains(lower, "ios"):
		return "有効化の目安: モバイルデバイス関連ファイルを扱う環境やMDM連携が必要な場合"

	// General malware
	case strings.Contains(lower, "malware"):
		return "有効化の目安: マルウェア対策として全エンドポイントへの有効化を推奨"

	default:
		return "有効化の目安: セキュリティリスク評価に基づき管理者が判断（不審なファイル検査や脅威調査時に活用）"
	}
}

// severityFromPath infers severity from the directory name.
func severityFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "malware"):
		return "high"
	case strings.Contains(lower, "exploit"):
		return "critical"
	case strings.Contains(lower, "webshell"):
		return "high"
	case strings.Contains(lower, "antidebug"), strings.Contains(lower, "antivm"):
		return "medium"
	case strings.Contains(lower, "packer"):
		return "medium"
	default:
		return "medium"
	}
}
