package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/proxy"
)

// ransomware.live の victims.json エントリ形式
type rlVictim struct {
	PostTitle   string `json:"post_title"`
	GroupName   string `json:"group_name"`
	Discovered  string `json:"discovered"`
	Published   string `json:"published"`
	Website     string `json:"website"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	Description string `json:"description"`
	PostURL     string `json:"post_url"`
}

// ransomwatch の groups.json 形式
type rwGroup struct {
	Name      string `json:"name"`
	Locations []struct {
		FQDN      string `json:"fqdn"`
		Available bool   `json:"available"`
	} `json:"locations"`
	Posts []struct {
		PostTitle string `json:"post_title"`
	} `json:"posts"`
}

// DarkWebScheduler はランサムウェアリークサイトを監視するスケジューラー。
//   - A: ransomwatch GitHub から .onion URL と被害者リストを毎日同期
//   - B: Tor SOCKS5 を使った死活監視（fail_count >= 5 で自動無効化）
type DarkWebScheduler struct {
	pool     *pgxpool.Pool
	torProxy string // "socks5://tor:9050"
	// 取得先 URL。既定は defaultRansomwatchURL で、テストが httptest サーバへ
	// 向けるためだけに差し替える。
	ransomwatchURL string
	enabled        bool
	slackURL       string // DARKWEB_ALERT_SLACK_WEBHOOK_URL（空なら送信しない）
	webhookURL     string // DARKWEB_ALERT_WEBHOOK_URL（空なら送信しない）
	emailCfg       *emailConfig
}

// ransomwatch の被害者リスト取得先。テストから差し替えられるよう、
// 取得時は定数を直接使わず DarkWebScheduler.ransomwatchURL を参照する。
const defaultRansomwatchURL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

// NewDarkWebScheduler はスケジューラーを生成する。
// torProxy が空の場合はヘルスチェックをスキップ（GitHub同期のみ実行）。
func NewDarkWebScheduler(pool *pgxpool.Pool, torProxy string, enabled bool) *DarkWebScheduler {
	return &DarkWebScheduler{
		pool:           pool,
		torProxy:       torProxy,
		enabled:        enabled,
		ransomwatchURL: defaultRansomwatchURL,
	}
}

// WithAlertNotify は検知時の即時通知先を設定する。
func (s *DarkWebScheduler) WithAlertNotify(slackURL, webhookURL string, ec *emailConfig) *DarkWebScheduler {
	s.slackURL = slackURL
	s.webhookURL = webhookURL
	s.emailCfg = ec
	return s
}

// sendUrgentAlert は検知時に即時通知を送信する。
func (s *DarkWebScheduler) sendUrgentAlert(title, description string) {
	if s.slackURL != "" {
		body, _ := json.Marshal(map[string]any{
			"text": fmt.Sprintf(":rotating_light: *ダークウェブ検知アラート*\n*%s*\n%s", title, description),
		})
		resp, err := http.Post(s.slackURL, "application/json", bytes.NewReader(body)) //nolint:noctx
		if err == nil {
			resp.Body.Close()
			slog.Info("DarkWebScheduler: Slack緊急通知を送信しました", "title", title)
		} else {
			slog.Warn("DarkWebScheduler: Slack緊急通知に失敗しました", "error", err)
		}
	}
	if s.webhookURL != "" {
		body, _ := json.Marshal(map[string]any{
			"event":       "darkweb_finding",
			"title":       title,
			"description": description,
			"severity":    9,
			"timestamp":   time.Now().Format(time.RFC3339),
		})
		resp, err := http.Post(s.webhookURL, "application/json", bytes.NewReader(body)) //nolint:noctx
		if err == nil {
			resp.Body.Close()
		}
	}
	if s.emailCfg != nil {
		subject := fmt.Sprintf("[緊急] ダークウェブ検知: %s", title)
		body := fmt.Sprintf("%s\n\n%s", title, description)
		if err := SendEmailViaSMTP(s.emailCfg, subject, body); err != nil {
			slog.Warn("DarkWebScheduler: 緊急メール送信に失敗しました", "error", err)
		} else {
			slog.Info("DarkWebScheduler: 緊急メール送信成功", "to", s.emailCfg.To)
		}
	}
}

// Run は以下のスケジュールで実行する。
//   - 毎日3:00: ransomwatch 同期 + Tor ヘルスチェック（重め）
//   - 6時間ごと: ransomware.live 同期（軽量・近リアルタイム）
func (s *DarkWebScheduler) Run(ctx context.Context) {
	if !s.enabled {
		slog.Info("DarkWebScheduler: 無効化されています (DARKWEB_MONITOR_ENABLED=false)")
		return
	}
	slog.Info("DarkWebScheduler: 開始", "tor_proxy", s.torProxy)

	// 起動直後に両方実行
	s.runOnce(ctx)
	s.syncRansomwareLive(ctx)

	// ransomware.live は6時間ごと
	rlTicker := time.NewTicker(6 * time.Hour)
	defer rlTicker.Stop()

	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		wait := next.Sub(now)

		select {
		case <-ctx.Done():
			return
		case <-rlTicker.C:
			// 6時間ごとに ransomware.live だけ実行（軽量）
			s.syncRansomwareLive(ctx)
		case <-time.After(wait):
			// 毎日3:00に全スキャン
			s.runOnce(ctx)
			s.syncRansomwareLive(ctx)
		}
	}
}

func (s *DarkWebScheduler) runOnce(ctx context.Context) {
	slog.Info("DarkWebScheduler: スキャン開始")
	s.syncRansomwatch(ctx)  // A: URL + 被害者リスト同期
	s.checkPostMatches(ctx) // A+: 被害者リストと監視キーワードの照合
	if s.torProxy != "" {
		s.healthCheck(ctx) // B: 死活監視
	}
	slog.Info("DarkWebScheduler: スキャン完了")
}

// ── A: ransomwatch GitHub 同期 ─────────────────────────────────────────────

func (s *DarkWebScheduler) syncRansomwatch(ctx context.Context) {
	slog.Info("DarkWebScheduler: ransomwatch 同期開始")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(s.ransomwatchURL)
	if err != nil {
		slog.Warn("DarkWebScheduler: ransomwatch 取得に失敗しました", "error", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("DarkWebScheduler: ransomwatch 読み込みに失敗しました", "error", err)
		return
	}

	var groups []rwGroup
	if err := json.Unmarshal(body, &groups); err != nil {
		slog.Warn("DarkWebScheduler: ransomwatch パースに失敗しました", "error", err)
		return
	}

	added, skipped := 0, 0
	for _, g := range groups {
		for _, loc := range g.Locations {
			if loc.FQDN == "" {
				continue
			}
			onionURL := loc.FQDN
			if !strings.HasSuffix(onionURL, ".onion") {
				onionURL = onionURL + ".onion"
			}
			_, err := s.pool.Exec(ctx, `
				INSERT INTO darkweb_ransomware_sites (group_name, onion_url, source)
				VALUES ($1, $2, 'ransomwatch')
				ON CONFLICT (onion_url) DO UPDATE SET
					group_name = EXCLUDED.group_name,
					updated_at = NOW()`,
				g.Name, onionURL,
			)
			if err != nil {
				skipped++
			} else {
				added++
			}
		}
	}

	// 取得したグループデータをキャッシュとして保存（posts照合用）
	rawJSON, _ := json.Marshal(groups)
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO darkweb_ransomware_sites (group_name, onion_url, source, raw_posts)
		SELECT 'ransomwatch_cache', '__cache__', 'system', $1
		WHERE NOT EXISTS (SELECT 1 FROM darkweb_ransomware_sites WHERE onion_url = '__cache__')
		ON CONFLICT (onion_url) DO UPDATE SET
			raw_posts = $1, updated_at = NOW()`,
		rawJSON,
	)

	slog.Info("DarkWebScheduler: ransomwatch 同期完了", "groups", len(groups), "added", added, "skipped", skipped)
}

// ── A+: 被害者リストと監視キーワードの照合 ─────────────────────────────────

func (s *DarkWebScheduler) checkPostMatches(ctx context.Context) {
	// 監視キーワード取得
	rows, err := s.pool.Query(ctx, `SELECT id, monitor_type, value FROM darkweb_monitors WHERE enabled = TRUE`)
	if err != nil || rows == nil {
		return
	}
	type monitor struct{ id, mtype, value string }
	var monitors []monitor
	for rows.Next() {
		var m monitor
		if rows.Scan(&m.id, &m.mtype, &m.value) == nil {
			monitors = append(monitors, m)
		}
	}
	rows.Close()
	if len(monitors) == 0 {
		return
	}

	// キャッシュされた groups.json を取得
	var rawPosts []byte
	_ = s.pool.QueryRow(ctx,
		`SELECT raw_posts FROM darkweb_ransomware_sites WHERE onion_url = '__cache__'`,
	).Scan(&rawPosts)
	if len(rawPosts) == 0 {
		return
	}

	var groups []rwGroup
	if err := json.Unmarshal(rawPosts, &groups); err != nil {
		return
	}

	for _, g := range groups {
		for _, post := range g.Posts {
			title := strings.ToLower(post.PostTitle)
			for _, m := range monitors {
				keyword := strings.ToLower(m.value)
				if !strings.Contains(title, keyword) {
					continue
				}
				desc := fmt.Sprintf(
					"ランサムウェアグループ「%s」の被害者リストに「%s」が含まれています。"+
						"自社情報が公開されている可能性があります。",
					g.Name, post.PostTitle,
				)
				alertTitle := fmt.Sprintf("[ランサムウェア被害確認] %s - %s", g.Name, post.PostTitle)

				// 既存の検知と重複チェック。
				//
				// 比較対象は「これから INSERT する値」でなければならない。
				// 以前は darkweb_findings.title を post.PostTitle と突き合わせて
				// いたが、実際に格納されるのは装飾済みの alertTitle
				// ("[ランサムウェア被害確認] グループ - 投稿タイトル") なので
				// 両者は永久に一致せず、重複チェックが常に false になっていた。
				// スケジューラは定期実行されるため、同じ被害について実行のたびに
				// 検知行・アラート・緊急通知 (Slack/Webhook/メール) が作られ続ける。
				var exists bool
				_ = s.pool.QueryRow(ctx,
					`SELECT EXISTS(
						SELECT 1 FROM darkweb_findings
						WHERE source = 'ransomwatch_posts'
						  AND group_name = $1
						  AND monitor_value = $2
						  AND title = $3
					)`, g.Name, m.value, alertTitle,
				).Scan(&exists)
				if exists {
					continue
				}

				_, _ = s.pool.Exec(ctx, `
					INSERT INTO darkweb_findings
					    (source, group_name, severity, title, description, monitor_value)
					VALUES ($1, $2, $3, $4, $5, $6)`,
					"ransomwatch_posts", g.Name, 9,
					alertTitle, desc, m.value,
				)
				// アラートページにも登録
				s.createAlert(ctx, alertTitle, desc, 9)
				// 即時通知
				s.sendUrgentAlert(alertTitle, desc)
				slog.Warn("DarkWebScheduler: 被害者リストにキーワードを検出しました",
					"group", g.Name, "post", post.PostTitle, "keyword", m.value,
				)
			}
		}
	}
}

// ── B: Tor 死活監視 ────────────────────────────────────────────────────────

func (s *DarkWebScheduler) healthCheck(ctx context.Context) {
	slog.Info("DarkWebScheduler: ヘルスチェック開始")

	torDialer, err := s.buildTorDialer()
	if err != nil {
		slog.Warn("DarkWebScheduler: Tor ダイヤラー作成に失敗しました", "error", err)
		return
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, group_name, onion_url, fail_count FROM darkweb_ransomware_sites
		WHERE onion_url != '__cache__'
		  AND (is_active = TRUE OR last_checked_at < NOW() - INTERVAL '7 days')
		ORDER BY last_checked_at ASC NULLS FIRST
		LIMIT 50`)
	if err != nil {
		return
	}
	defer rows.Close()

	type site struct {
		id, group, url string
		fails          int
	}
	var sites []site
	for rows.Next() {
		var s site
		if rows.Scan(&s.id, &s.group, &s.url, &s.fails) == nil {
			sites = append(sites, s)
		}
	}
	rows.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return torDialer.Dial(network, addr)
			},
		},
		Timeout: 30 * time.Second,
	}

	alive, dead := 0, 0
	for _, site := range sites {
		url := "http://" + site.url
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
		}
		isAlive := err == nil && resp.StatusCode < 500

		if isAlive {
			_, _ = s.pool.Exec(ctx, `
				UPDATE darkweb_ransomware_sites
				SET fail_count = 0, is_active = TRUE,
				    last_alive_at = NOW(), last_checked_at = NOW()
				WHERE id = $1`, site.id)
			alive++
		} else {
			newFails := site.fails + 1
			isActive := newFails < 5
			_, _ = s.pool.Exec(ctx, `
				UPDATE darkweb_ransomware_sites
				SET fail_count = $1, is_active = $2, last_checked_at = NOW()
				WHERE id = $3`, newFails, isActive, site.id)
			dead++
			if !isActive {
				slog.Info("DarkWebScheduler: サイトを無効化しました",
					"group", site.group, "url", site.url, "fails", newFails)
			}
		}
	}
	slog.Info("DarkWebScheduler: ヘルスチェック完了", "alive", alive, "dead", dead)
}

func (s *DarkWebScheduler) buildTorDialer() (proxy.Dialer, error) {
	addr := strings.TrimPrefix(s.torProxy, "socks5://")
	return proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
}

// createAlert はダークウェブ検知をアラートテーブルにも登録する。
// SOCワークキュー・アラート一覧から確認できるようになる。
func (s *DarkWebScheduler) createAlert(ctx context.Context, title, description string, severity int) {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (severity, status, title, description, mitre_technique, tenant_id)
		VALUES ($1, 'open', $2, $3, 'T1486',
			COALESCE((SELECT id FROM tenants LIMIT 1), '00000000-0000-0000-0000-000000000001'))
		ON CONFLICT DO NOTHING`,
		severity, title, description,
	)
	if err != nil {
		slog.Warn("DarkWebScheduler: アラート登録に失敗しました", "error", err)
	}
}

// ── ransomware.live 統合 ───────────────────────────────────────────────────

const ransomwareLiveURL = "https://data.ransomware.live/victims.json"

// syncRansomwareLive は ransomware.live の被害者リストを取得し、
// 監視キーワードと照合して検知結果を生成する。
// 直近30日の被害者のみ対象にして処理量を制限する。
func (s *DarkWebScheduler) syncRansomwareLive(ctx context.Context) {
	slog.Info("DarkWebScheduler: ransomware.live 同期開始")

	client := &http.Client{Timeout: 180 * time.Second} // victims.json は数MB超のため余裕を持たせる
	resp, err := client.Get(ransomwareLiveURL)
	if err != nil {
		slog.Warn("DarkWebScheduler: ransomware.live 取得に失敗しました", "error", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("DarkWebScheduler: ransomware.live 読み込みに失敗しました", "error", err)
		return
	}

	var victims []rlVictim
	if err := json.Unmarshal(body, &victims); err != nil {
		slog.Warn("DarkWebScheduler: ransomware.live パースに失敗しました", "error", err)
		return
	}

	// 監視キーワード取得
	rows, err := s.pool.Query(ctx, `SELECT monitor_type, value FROM darkweb_monitors WHERE enabled = TRUE`)
	if err != nil {
		return
	}
	type monitor struct{ mtype, value string }
	var monitors []monitor
	for rows.Next() {
		var m monitor
		if rows.Scan(&m.mtype, &m.value) == nil {
			monitors = append(monitors, m)
		}
	}
	rows.Close()
	if len(monitors) == 0 {
		slog.Info("DarkWebScheduler: ransomware.live — 監視キーワードなし、スキップ")
		return
	}

	// 直近30日の被害者のみ処理
	cutoff := time.Now().AddDate(0, 0, -30)
	matched, checked := 0, 0
	for _, v := range victims {
		discovered, err := time.Parse(time.RFC3339Nano, v.Discovered)
		if err != nil {
			// パース失敗は古いデータとして扱う
			continue
		}
		if discovered.Before(cutoff) {
			continue
		}
		checked++

		titleLower := strings.ToLower(v.PostTitle)
		websiteLower := strings.ToLower(v.Website)
		descLower := strings.ToLower(v.Description)

		for _, m := range monitors {
			keyword := strings.ToLower(m.value)

			// ドメイン監視: website フィールドと一致
			// メール・キーワード: post_title / description で検索
			hit := false
			switch m.mtype {
			case "domain":
				hit = strings.Contains(websiteLower, keyword) ||
					strings.Contains(titleLower, keyword)
			case "email":
				domain := keyword
				if idx := strings.Index(keyword, "@"); idx >= 0 {
					domain = keyword[idx+1:]
				}
				hit = strings.Contains(websiteLower, domain) ||
					strings.Contains(descLower, keyword)
			default: // keyword
				hit = strings.Contains(titleLower, keyword) ||
					strings.Contains(websiteLower, keyword) ||
					strings.Contains(descLower, keyword)
			}

			if !hit {
				continue
			}

			// 重複チェック
			var exists bool
			_ = s.pool.QueryRow(ctx,
				`SELECT EXISTS(
					SELECT 1 FROM darkweb_findings
					WHERE source = 'ransomware_live'
					  AND group_name = $1
					  AND monitor_value = $2
					  AND title = $3
				)`, v.GroupName, m.value, v.PostTitle,
			).Scan(&exists)
			if exists {
				continue
			}

			// 国情報を付加した説明文
			country := v.Country
			if country == "" {
				country = "不明"
			}
			desc := fmt.Sprintf(
				"[ransomware.live] ランサムウェアグループ「%s」の被害者リストに「%s」(%s)が掲載されています。"+
					"キーワード「%s」が一致しました。",
				v.GroupName, v.PostTitle, country, m.value,
			)
			if v.Description != "" && len(v.Description) > 20 {
				maxLen := 200
				d := v.Description
				if len(d) > maxLen {
					d = d[:maxLen] + "..."
				}
				desc += "\n概要: " + d
			}

			rawData, _ := json.Marshal(map[string]any{
				"post_url": v.PostURL,
				"country":  v.Country,
				"activity": v.Activity,
				"website":  v.Website,
			})
			rlTitle := fmt.Sprintf("[ransomware.live 被害確認] %s — %s (%s)", v.GroupName, v.PostTitle, country)
			_, _ = s.pool.Exec(ctx, `
				INSERT INTO darkweb_findings
				    (source, group_name, severity, title, description, monitor_value, raw_data)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				"ransomware_live", v.GroupName, 9,
				rlTitle, desc, m.value, rawData,
			)
			// アラートページにも登録
			s.createAlert(ctx, rlTitle, desc, 9)
			// 即時通知
			s.sendUrgentAlert(rlTitle, desc)
			matched++
			slog.Warn("DarkWebScheduler: ransomware.live でキーワードを検出しました",
				"group", v.GroupName, "victim", v.PostTitle, "keyword", m.value, "country", country,
			)
		}
	}
	slog.Info("DarkWebScheduler: ransomware.live 同期完了",
		"total_victims", len(victims), "checked_30d", checked, "matched", matched,
	)
}
