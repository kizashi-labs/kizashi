// edr-seed — Kizashi demo data seeder
//
// Usage:
//
//	DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=full
//	DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=ransomware
//	DATABASE_URL=postgres://... go run ./cmd/seed/ --clear
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	scenario := flag.String("scenario", "full", "シナリオ: full, ransomware, apt, insider, minimal")
	clear := flag.Bool("clear", false, "シード前にデモデータをクリア")
	quiet := flag.Bool("quiet", false, "進捗出力を抑制")
	flag.Parse()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		slog.Error("DATABASE_URL が設定されていません")
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		slog.Error("データベース接続に失敗しました", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	s := &Seeder{pool: pool, quiet: *quiet, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}

	if *clear {
		if err := s.Clear(ctx); err != nil {
			slog.Error("データのクリアに失敗しました", "error", err)
			os.Exit(1)
		}
	}

	if err := s.Seed(ctx, *scenario); err != nil {
		slog.Error("シードに失敗しました", "error", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ デモデータのシードが完了しました")
}

// ── Seeder ───────────────────────────────────────────────────────

type Seeder struct {
	pool  *pgxpool.Pool
	quiet bool
	rng   *rand.Rand
}

// severityToInt は "critical"/"high"/... を DB の重大度 (smallint, 1-10) に写す。
//
// alerts.severity / rules.severity / incidents.severity はいずれも数値列で、
// CHECK (severity BETWEEN 1 AND 10) が付いている。ここに文字列を渡していたため
// `invalid input syntax for type smallint: "high"` で INSERT が全て失敗し、
// デモデータは 1 行も作られていなかった。
//
// しきい値はコードベースの他所 (dashboard_stats / ops_report / notification)
// が使っている >= 9 = critical, >= 7 = high に合わせる。
func severityToInt(label string) int {
	switch label {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 5
	}
}

func (s *Seeder) log(msg string, args ...any) {
	if !s.quiet {
		fmt.Printf(msg+"\n", args...)
	}
}

func (s *Seeder) Clear(ctx context.Context) error {
	s.log("デモデータをクリア中...")
	// IOC の実表は ioc_entries (`iocs` というテーブルは無い)。
	// events は hypertable で id 列を持たず (event_id / time)、
	// created_at も無いので条件列を表ごとに変える。
	tables := []struct{ name, timeCol string }{
		{"alert_comments", "created_at"},
		{"alerts", "created_at"},
		{"agents", "created_at"},
		{"rules", "created_at"},
		{"ioc_entries", "created_at"},
		{"incidents", "created_at"},
		{"events", "time"},
	}
	for _, t := range tables {
		_, err := s.pool.Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE %s > NOW() - INTERVAL '365 days'`, t.name, t.timeCol))
		if err != nil {
			s.log("  警告: %s のクリアをスキップしました: %v", t.name, err)
		}
	}
	s.log("✓ デモデータをクリアしました")
	return nil
}

func (s *Seeder) Seed(ctx context.Context, scenario string) error {
	s.log("シナリオ: %s", scenario)

	switch scenario {
	case "ransomware":
		return s.seedRansomware(ctx)
	case "apt":
		return s.seedAPT(ctx)
	case "insider":
		return s.seedInsider(ctx)
	case "minimal":
		return s.seedMinimal(ctx)
	default: // full
		return s.seedFull(ctx)
	}
}

// ── Scenario: Full ───────────────────────────────────────────────

func (s *Seeder) seedFull(ctx context.Context) error {
	s.log("\n━━ フルデモデータ生成 ━━")

	agentIDs, err := s.seedAgents(ctx, 50)
	if err != nil {
		return fmt.Errorf("エージェント: %w", err)
	}
	s.log("✓ エージェント: %d 台", len(agentIDs))

	ruleIDs, err := s.seedRules(ctx, 30)
	if err != nil {
		return fmt.Errorf("ルール: %w", err)
	}
	s.log("✓ 検知ルール: %d 件", len(ruleIDs))

	alertCount, err := s.seedAlerts(ctx, agentIDs, ruleIDs, 200)
	if err != nil {
		return fmt.Errorf("アラート: %w", err)
	}
	s.log("✓ アラート: %d 件", alertCount)

	incidentCount, err := s.seedIncidents(ctx, 15)
	if err != nil {
		return fmt.Errorf("インシデント: %w", err)
	}
	s.log("✓ インシデント: %d 件", incidentCount)

	iocCount, err := s.seedIOCs(ctx, 500)
	if err != nil {
		return fmt.Errorf("IOC: %w", err)
	}
	s.log("✓ IOC: %d 件", iocCount)

	return nil
}

// ── Scenario: Ransomware Attack ──────────────────────────────────

func (s *Seeder) seedRansomware(ctx context.Context) error {
	s.log("\n━━ ランサムウェア攻撃シナリオ ━━")
	s.log("  攻撃者: LockBit 3.0 affiliate")
	s.log("  ベクター: フィッシングメール → マクロ実行 → ラテラルムーブメント → 暗号化")

	// 20 agents, several infected
	agentIDs, err := s.seedAgents(ctx, 20)
	if err != nil {
		return err
	}

	// High-severity alerts following kill chain
	ransomwareAlerts := []struct {
		title     string
		severity  string
		technique string
		status    string
		hoursAgo  int
	}{
		{"Phishing Email Attachment Opened", "medium", "T1566.001", "resolved", 72},
		{"Macro Execution via Office Document", "high", "T1059.005", "resolved", 71},
		{"PowerShell Download Cradle Detected", "high", "T1059.001", "resolved", 70},
		{"Credential Dumping via LSASS Access", "critical", "T1003.001", "investigating", 48},
		{"Lateral Movement via PSExec", "critical", "T1570", "investigating", 47},
		{"Shadow Copy Deletion Detected", "critical", "T1490", "open", 24},
		{"Ransomware - Mass File Encryption", "critical", "T1486", "open", 23},
		{"C2 Beacon to Known Malicious IP", "critical", "T1071.001", "open", 22},
		{"Data Exfiltration via HTTPS", "high", "T1041", "open", 20},
		{"Firewall Rules Modified", "high", "T1562.004", "open", 18},
	}

	for i, a := range ransomwareAlerts {
		agentID := agentIDs[i%len(agentIDs)]
		ts := time.Now().Add(-time.Duration(a.hoursAgo) * time.Hour)
		// alerts に rule_name / mitre_technique_id 列は無い。
		// テクニックの実列は mitre_technique。シナリオ側は rules 表を作らない
		// ので、ルール名は description に残す (捨てると何が鳴ったか追えない)。
		_, err := s.pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, title, description, severity, status,
				mitre_technique, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
			ON CONFLICT DO NOTHING`,
			agentID, a.title,
			fmt.Sprintf("LockBit 3.0 キャンペーン検知: %s [LockBit-Detection-%d]", a.title, i+1),
			severityToInt(a.severity), a.status,
			a.technique, ts,
		)
		if err != nil {
			s.log("  警告: アラート '%s' の挿入をスキップ: %v", a.title, err)
		}
	}

	// Create a critical incident
	//
	// incidents.severity も数値列。文字列を渡していたため INSERT は毎回
	// 失敗していたが、戻り値を捨てていたので「1 インシデント」と表示
	// されるだけで実際には 0 件だった。
	incidents := 0
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO incidents (title, description, severity, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT DO NOTHING`,
		"ランサムウェア攻撃 — LockBit 3.0",
		"製造部門のWindowsサーバー群でLockBit 3.0によるファイル暗号化を確認。シャドウコピーが削除され、C2通信が継続中。",
		severityToInt("critical"), "investigating", time.Now().Add(-23*time.Hour),
	); err != nil {
		s.log("  警告: インシデントの挿入をスキップ: %v", err)
	} else {
		incidents = 1
	}

	s.log("✓ ランサムウェアシナリオ: %d エージェント, %d アラート, %d インシデント",
		len(agentIDs), len(ransomwareAlerts), incidents)
	return nil
}

// ── Scenario: APT ────────────────────────────────────────────────

func (s *Seeder) seedAPT(ctx context.Context) error {
	s.log("\n━━ APT攻撃シナリオ ━━")
	s.log("  攻撃者: APT29 (Cozy Bear) TTP")
	s.log("  手法: スピアフィッシング → WMI永続化 → DCSync → 長期潜伏")

	agentIDs, err := s.seedAgents(ctx, 30)
	if err != nil {
		return err
	}

	aptAlerts := []struct {
		title     string
		severity  string
		technique string
		daysAgo   int
	}{
		{"Spearphishing Link Clicked", "low", "T1566.002", 30},
		{"WMI Subscription Created for Persistence", "medium", "T1546.003", 28},
		{"Registry Run Key Modified", "medium", "T1547.001", 27},
		{"LDAP Reconnaissance Query Detected", "medium", "T1018", 20},
		{"Kerberoasting Attack Detected", "high", "T1558.003", 15},
		{"DCSync Attack — Replication Rights Abuse", "critical", "T1003.006", 10},
		{"Golden Ticket Creation Detected", "critical", "T1558.001", 8},
		{"Long-term C2 via DNS Tunneling", "high", "T1071.004", 5},
		{"Staged Data in Temp Directory", "high", "T1074.001", 3},
		{"Exfiltration via Encrypted Channel", "high", "T1048.003", 1},
	}

	for i, a := range aptAlerts {
		agentID := agentIDs[i%len(agentIDs)]
		ts := time.Now().AddDate(0, 0, -a.daysAgo)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, title, description, severity, status,
				mitre_technique, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
			ON CONFLICT DO NOTHING`,
			agentID, a.title,
			fmt.Sprintf("APT29 TTPs検知: %s [APT29-TTP-%d]", a.title, i+1),
			severityToInt(a.severity), "open", a.technique, ts,
		); err != nil {
			s.log("  警告: アラート '%s' の挿入をスキップ: %v", a.title, err)
		}
	}

	s.log("✓ APTシナリオ: %d エージェント, %d アラート", len(agentIDs), len(aptAlerts))
	return nil
}

// ── Scenario: Insider Threat ─────────────────────────────────────

func (s *Seeder) seedInsider(ctx context.Context) error {
	s.log("\n━━ 内部脅威シナリオ ━━")

	agentIDs, err := s.seedAgents(ctx, 10)
	if err != nil {
		return err
	}

	insiderAlerts := []struct {
		title    string
		severity string
		daysAgo  int
	}{
		{"Abnormal Data Access Volume Detected", "medium", 14},
		{"Sensitive File Access Outside Business Hours", "medium", 12},
		{"USB Storage Device Connected", "low", 10},
		{"Large Data Upload to Cloud Storage", "high", 7},
		{"Access to Restricted Financial Records", "high", 5},
		{"Bulk Email with Attachments Sent", "high", 3},
		{"VPN Access from Unusual Location", "medium", 2},
		{"Active Directory Group Membership Changed", "critical", 1},
	}

	for i, a := range insiderAlerts {
		agentID := agentIDs[i%len(agentIDs)]
		ts := time.Now().AddDate(0, 0, -a.daysAgo)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, title, description, severity, status,
				created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)
			ON CONFLICT DO NOTHING`,
			agentID, a.title,
			fmt.Sprintf("UEBA行動異常検知: %s [UEBA-Insider-%d]", a.title, i+1),
			severityToInt(a.severity), "open", ts,
		); err != nil {
			s.log("  警告: アラート '%s' の挿入をスキップ: %v", a.title, err)
		}
	}

	s.log("✓ 内部脅威シナリオ: %d エージェント, %d アラート", len(agentIDs), len(insiderAlerts))
	return nil
}

// ── Scenario: Minimal ───────────────────────────────────────────

func (s *Seeder) seedMinimal(ctx context.Context) error {
	s.log("\n━━ 最小デモデータ ━━")

	agentIDs, err := s.seedAgents(ctx, 5)
	if err != nil {
		return err
	}
	_, err = s.seedAlerts(ctx, agentIDs, nil, 10)
	return err
}

// ── Helpers ──────────────────────────────────────────────────────

var hostnames = []string{
	"WIN-DC01", "WIN-FS01", "WIN-APP01", "WIN-DB01", "WIN-WEB01",
	"LINUX-SVR-01", "LINUX-SVR-02", "LINUX-WEB-01", "MACBOOK-CEO", "MACBOOK-DEV01",
	"WIN-WORKSTATION-01", "WIN-WORKSTATION-02", "WIN-WORKSTATION-03", "WIN-LAPTOP-01",
	"WIN-LAPTOP-02", "LINUX-KUBE-01", "LINUX-KUBE-02", "WIN-EXCHANGE-01",
	"WIN-SHAREPOINT-01", "LINUX-JENKINS-01",
}

// agents.os_type は CHECK (windows|linux|darwin|unknown) が付いた正規値。
// "Windows" / "Ubuntu" / "macOS" のような表示名を入れると
// agents_os_type_check に弾かれ、エージェントが 1 台も作られなかった。
// 表示名はディストリビューション名として os_version 側に残す。
var osTypes = []struct{ osType, name, version string }{
	{"windows", "Windows", "10.0.19045"},
	{"windows", "Windows", "10.0.22621"},
	{"windows", "Windows Server", "2022"},
	{"windows", "Windows Server", "2019"},
	{"linux", "Ubuntu", "22.04.3"},
	{"linux", "CentOS", "7.9.2009"},
	{"darwin", "macOS", "14.2.1"},
}

func (s *Seeder) seedAgents(ctx context.Context, count int) ([]string, error) {
	var ids []string
	for i := 0; i < count; i++ {
		hostname := hostnames[i%len(hostnames)]
		if i >= len(hostnames) {
			hostname = fmt.Sprintf("%s-%02d", hostname, i/len(hostnames)+1)
		}
		osInfo := osTypes[s.rng.Intn(len(osTypes))]
		status := "online"
		if s.rng.Float32() < 0.15 {
			status = "offline"
		}
		lastSeen := time.Now().Add(-time.Duration(s.rng.Intn(300)) * time.Second)

		var id string
		// agents の実際の列は os_type / agent_version / ip_addresses(inet[]) /
		// last_seen。os / version / ip_address / last_seen_at は存在しない。
		//
		// hostname に UNIQUE 制約は無い (マルチテナントで同名ホストが有り得る)
		// ため ON CONFLICT (hostname) は使えず、以前は
		// "there is no unique or exclusion constraint matching the ON CONFLICT
		// specification" で全件失敗していた。既存行を先に引く形にする
		// (ingest_handler の upsertAgent と同じ)。
		var err error
		_ = s.pool.QueryRow(ctx,
			`SELECT id::text FROM agents WHERE hostname = $1 LIMIT 1`, hostname).Scan(&id)
		if id != "" {
			_, err = s.pool.Exec(ctx, `
				UPDATE agents SET status = $2, last_seen = $3, updated_at = NOW()
				WHERE id = $1`, id, status, lastSeen)
		} else {
			err = s.pool.QueryRow(ctx, `
				INSERT INTO agents (hostname, os_type, os_version, ip_addresses, status,
					agent_version, enrolled_at, last_seen, created_at, updated_at)
				VALUES ($1, $2, $3, ARRAY[$4::inet], $5, $6, $7, $8, $9, $9)
				RETURNING id`,
				hostname, osInfo.osType, osInfo.name+" "+osInfo.version,
				fmt.Sprintf("10.0.%d.%d", s.rng.Intn(5)+1, s.rng.Intn(254)+1),
				status, "1.0.0",
				time.Now().AddDate(0, -s.rng.Intn(6), 0),
				lastSeen,
				time.Now().AddDate(0, -s.rng.Intn(6), 0),
			).Scan(&id)
		}
		if err != nil {
			s.log("  警告: エージェント '%s' の挿入をスキップ: %v", hostname, err)
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

var ruleSeverities = []string{"critical", "high", "high", "medium", "medium", "medium", "low"}

// rules.type は CHECK (yara|sigma|behavioral)。"custom" は弾かれる。
var ruleTypes = []string{"sigma", "sigma", "sigma", "yara", "behavioral"}
var ruleNames = []string{
	"Mimikatz Credential Dumping", "PSExec Remote Execution", "PowerShell Obfuscation",
	"WMI Persistence", "Registry Run Key", "Scheduled Task Creation",
	"Shadow Copy Deletion", "Mass File Encryption", "LSASS Memory Access",
	"DCSync Attack", "Kerberoasting", "Pass-the-Hash",
	"Suspicious Network Connection", "DNS Tunneling", "HTTP Beacon",
	"USB Storage Device", "Abnormal Process Parent", "Privilege Escalation UAC Bypass",
	"Remote Desktop Brute Force", "SQL Injection Attempt",
	"Log Clearing", "Firewall Rule Modification", "AV Tampering",
	"Living off the Land - certutil", "Living off the Land - mshta",
	"Lateral Movement SMB", "Token Impersonation", "Injection via CreateRemoteThread",
	"Suspicious PowerShell Download", "Encoded Command Execution",
}

func (s *Seeder) seedRules(ctx context.Context, count int) ([]string, error) {
	var ids []string
	for i := 0; i < count; i++ {
		name := ruleNames[i%len(ruleNames)]
		var id string
		// rules に condition 列は無い (ルール本文は content)。
		// severity は smallint なので数値に写す。platform は既定値に任せる。
		//
		// name にも UNIQUE 制約は無いので ON CONFLICT (name) は使えない。
		// ruleNames を巡回して使い回すため、同名は先に引いて再利用する。
		_ = s.pool.QueryRow(ctx,
			`SELECT id::text FROM rules WHERE name = $1 LIMIT 1`, name).Scan(&id)
		if id != "" {
			ids = append(ids, id)
			continue
		}
		err := s.pool.QueryRow(ctx, `
			INSERT INTO rules (name, description, type, severity, enabled, content, created_at, updated_at)
			VALUES ($1, $2, $3, $4, true, $5, $6, $6)
			RETURNING id`,
			name,
			fmt.Sprintf("%s の検知ルール (デモデータ)", name),
			ruleTypes[s.rng.Intn(len(ruleTypes))],
			severityToInt(ruleSeverities[s.rng.Intn(len(ruleSeverities))]),
			fmt.Sprintf(`{"detection": {"keywords": ["%s"]}}`, name),
			time.Now().AddDate(0, -s.rng.Intn(3), -s.rng.Intn(30)),
		).Scan(&id)
		if err != nil {
			s.log("  警告: ルール '%s' の挿入をスキップ: %v", name, err)
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

var alertTitles = []string{
	"Suspicious PowerShell Execution",
	"Credential Dumping Detected",
	"Lateral Movement via SMB",
	"Ransomware File Encryption Activity",
	"C2 Communication Detected",
	"Privilege Escalation Attempt",
	"Data Exfiltration via DNS",
	"Malicious Process Injection",
	"Registry Persistence Mechanism",
	"Unusual Parent-Child Process",
	"Network Reconnaissance Scan",
	"Shadow Copy Deletion",
	"LSASS Memory Access",
	"Scheduled Task Created by Attacker",
	"Phishing Email Attachment Executed",
}

var alertSeverities = []string{"critical", "critical", "high", "high", "high", "medium", "medium", "medium", "low"}
var alertStatuses = []string{"open", "open", "open", "investigating", "resolved", "false_positive"}

func (s *Seeder) seedAlerts(ctx context.Context, agentIDs, ruleIDs []string, count int) (int, error) {
	created := 0
	for i := 0; i < count; i++ {
		if len(agentIDs) == 0 {
			continue
		}
		agentID := agentIDs[s.rng.Intn(len(agentIDs))]
		title := alertTitles[s.rng.Intn(len(alertTitles))]
		severity := alertSeverities[s.rng.Intn(len(alertSeverities))]
		status := alertStatuses[s.rng.Intn(len(alertStatuses))]
		ts := time.Now().Add(-time.Duration(s.rng.Intn(30*24)) * time.Hour)

		// alerts に rule_name 列は無い。ルールとの紐付けは rule_id で、
		// 表示名は rules との JOIN が担う (store/alerts.go の GetAlert と同じ)。
		// ルールを 1 件も作れていない場合だけ NULL にする。
		var ruleID any
		if len(ruleIDs) > 0 {
			ruleID = ruleIDs[s.rng.Intn(len(ruleIDs))]
		}

		if _, err := s.pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, rule_id, title, description, severity, status,
				created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
			ON CONFLICT DO NOTHING`,
			agentID, ruleID, title,
			fmt.Sprintf("デモ検知: %s。調査対象エンドポイントでの不審な活動を検出しました。", title),
			severityToInt(severity), status, ts,
		); err != nil {
			s.log("  警告: アラート '%s' の挿入をスキップ: %v", title, err)
			continue
		}
		created++
	}
	return created, nil
}

var incidentTitles = []string{
	"ランサムウェア感染 — 財務部門",
	"APT攻撃 — 認証情報盗取の疑い",
	"内部不正 — 大量データ持ち出し",
	"Webサーバー侵害 — SQLインジェクション",
	"メール経由のマルウェア感染",
	"VPN認証情報総当たり攻撃",
	"サプライチェーン攻撃の疑い",
	"クラウドストレージ不正アクセス",
	"ドメインコントローラー侵害",
	"横展開攻撃 — 複数端末感染",
}

func (s *Seeder) seedIncidents(ctx context.Context, count int) (int, error) {
	severities := []string{"critical", "critical", "high", "high", "medium"}
	statuses := []string{"open", "investigating", "contained", "resolved"}
	created := 0
	for i := 0; i < count; i++ {
		title := incidentTitles[i%len(incidentTitles)]
		_, err := s.pool.Exec(ctx, `
			INSERT INTO incidents (title, description, severity, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $5)
			ON CONFLICT DO NOTHING`,
			title,
			fmt.Sprintf("インシデント詳細: %s。SOCチームが調査中です。", title),
			severityToInt(severities[s.rng.Intn(len(severities))]),
			statuses[s.rng.Intn(len(statuses))],
			time.Now().Add(-time.Duration(s.rng.Intn(14*24))*time.Hour),
		)
		if err != nil {
			s.log("  警告: インシデント '%s' の挿入をスキップ: %v", title, err)
			continue
		}
		created++
	}
	return created, nil
}

var iocValues = []struct{ iocType, value string }{
	{"ip", "185.220.101.47"},
	{"ip", "194.165.16.29"},
	{"ip", "45.142.212.100"},
	{"ip", "193.106.191.162"},
	{"domain", "malware-c2.example.ru"},
	{"domain", "beacon.evil-apt.net"},
	{"domain", "exfil.data-stealer.com"},
	{"hash", "5f4dcc3b5aa765d61d8327deb882cf99"},
	{"hash", "d8e8fca2dc0f896fd7cb4cb0031ba249"},
	{"hash", "aab3238922bcc25a6f606eb525ffdc56"},
	{"url", "http://185.220.101.47/payload.exe"},
	{"url", "https://pastebin.com/raw/malicious"},
}

func (s *Seeder) seedIOCs(ctx context.Context, count int) (int, error) {
	created := 0
	for i := 0; i < count; i++ {
		base := iocValues[i%len(iocValues)]
		iocType := base.iocType
		value := base.value
		if i >= len(iocValues) {
			// Generate variations
			value = fmt.Sprintf("%s-%d", value, i)
		}
		// IOC の実表は ioc_entries (`iocs` というテーブルは無い)。
		// 出どころの列は source_feed、severity は integer。
		_, err := s.pool.Exec(ctx, `
			INSERT INTO ioc_entries (type, value, description, severity, source_feed, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)
			ON CONFLICT (type, value) DO NOTHING`,
			iocType, value,
			fmt.Sprintf("デモIOC: %s", value),
			severityToInt([]string{"critical", "high", "medium"}[s.rng.Intn(3)]),
			"demo-seed",
			time.Now().Add(-time.Duration(s.rng.Intn(90*24))*time.Hour),
		)
		if err == nil {
			created++
		}
	}
	return created, nil
}
