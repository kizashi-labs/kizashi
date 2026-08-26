package main

import "strings"

// techniqueTactics は ATT&CK technique(ベース T番号) から該当 tactic 集合への
// マッピング。本ツールが採点対象とする Tier1/Tier2 のテクニックを内蔵する
// (サーバ側に technique->tactic マップが存在しないため、ここで自前に持つ)。
// 1つの technique が複数 tactic に属する場合は複数列挙する。
// 出典: MITRE ATT&CK Enterprise。新規テクニックを採点したい場合はここに追記する。
var techniqueTactics = map[string][]string{
	// --- Execution ---
	"T1059": {"execution"},                                        // Command and Scripting Interpreter
	"T1203": {"execution"},                                        // Exploitation for Client Execution
	"T1569": {"execution"},                                        // System Services
	"T1053": {"execution", "persistence", "privilege-escalation"}, // Scheduled Task/Job
	"T1047": {"execution"},                                        // Windows Management Instrumentation
	"T1106": {"execution"},                                        // Native API
	"T1204": {"execution"},                                        // User Execution
	"T1129": {"execution"},                                        // Shared Modules
	"T1559": {"execution"},                                        // Inter-Process Communication
	// --- Persistence ---
	"T1547": {"persistence", "privilege-escalation"}, // Boot or Logon Autostart
	"T1505": {"persistence"},                         // Server Software Component (web shell)
	"T1136": {"persistence"},                         // Create Account
	"T1098": {"persistence"},                         // Account Manipulation
	"T1543": {"persistence", "privilege-escalation"}, // Create or Modify System Process
	"T1546": {"persistence", "privilege-escalation"}, // Event Triggered Execution
	"T1037": {"persistence", "privilege-escalation"}, // Boot or Logon Initialization Scripts
	"T1197": {"persistence", "defense-evasion"},      // BITS Jobs
	"T1133": {"persistence", "initial-access"},       // External Remote Services
	// --- Privilege Escalation / Defense Evasion ---
	"T1055": {"defense-evasion", "privilege-escalation"},                                  // Process Injection
	"T1620": {"defense-evasion"},                                                          // Reflective Code Loading
	"T1014": {"defense-evasion"},                                                          // Rootkit
	"T1542": {"defense-evasion", "persistence"},                                           // Pre-OS Boot (Bootkit)
	"T1207": {"defense-evasion"},                                                          // Rogue Domain Controller (DCShadow)
	"T1218": {"defense-evasion"},                                                          // System Binary Proxy Execution (LOLBin)
	"T1562": {"defense-evasion"},                                                          // Impair Defenses
	"T1578": {"defense-evasion"},                                                          // Modify Cloud Compute Infrastructure
	"T1070": {"defense-evasion"},                                                          // Indicator Removal
	"T1027": {"defense-evasion"},                                                          // Obfuscated Files or Information
	"T1574": {"defense-evasion", "persistence", "privilege-escalation"},                   // Hijack Execution Flow (side-loading)
	"T1548": {"privilege-escalation", "defense-evasion"},                                  // Abuse Elevation Control (sudo/UAC/SUID)
	"T1611": {"privilege-escalation"},                                                     // Escape to Host (container breakout)
	"T1553": {"defense-evasion"},                                                          // Subvert Trust Controls (root cert)
	"T1220": {"defense-evasion"},                                                          // XSL Script Processing
	"T1036": {"defense-evasion"},                                                          // Masquerading
	"T1564": {"defense-evasion"},                                                          // Hide Artifacts (hidden window/ADS)
	"T1134": {"privilege-escalation", "defense-evasion"},                                  // Access Token Manipulation
	"T1112": {"defense-evasion"},                                                          // Modify Registry
	"T1140": {"defense-evasion"},                                                          // Deobfuscate/Decode Files or Information
	"T1497": {"defense-evasion", "discovery"},                                             // Virtualization/Sandbox Evasion
	"T1480": {"defense-evasion"},                                                          // Execution Guardrails
	"T1222": {"defense-evasion"},                                                          // File and Directory Permissions Modification
	"T1127": {"defense-evasion"},                                                          // Trusted Developer Utilities Proxy Execution
	"T1006": {"defense-evasion"},                                                          // Direct Volume Access
	"T1166": {"privilege-escalation", "defense-evasion"},                                  // (legacy) Setuid/Setgid → now T1548.001
	"T1078": {"defense-evasion", "persistence", "privilege-escalation", "initial-access"}, // Valid Accounts
	// --- Credential Access ---
	"T1003": {"credential-access"},               // OS Credential Dumping (LSASS)
	"T1555": {"credential-access"},               // Credentials from Password Stores (Credential Manager)
	"T1552": {"credential-access"},               // Unsecured Credentials
	"T1557": {"credential-access", "collection"}, // Adversary-in-the-Middle (LLMNR/NBT-NS poisoning)
	"T1558": {"credential-access"},               // Steal or Forge Kerberos Tickets (Kerberoasting)
	"T1649": {"credential-access"},               // Steal or Forge Authentication Certificates (AD CS abuse)
	"T1110": {"credential-access"},               // Brute Force
	"T1212": {"credential-access"},               // Exploitation for Credential Access
	"T1187": {"credential-access"},               // Forced Authentication
	"T1040": {"credential-access", "discovery"},  // Network Sniffing
	// --- Discovery ---
	"T1033": {"discovery"},       // System Owner/User Discovery
	"T1057": {"discovery"},       // Process Discovery
	"T1082": {"discovery"},       // System Information Discovery
	"T1016": {"discovery"},       // System Network Configuration Discovery
	"T1018": {"discovery"},       // Remote System Discovery
	"T1087": {"discovery"},       // Account Discovery
	"T1518": {"discovery"},       // Software Discovery
	"T1069": {"discovery"},       // Permission Groups Discovery (net localgroup)
	"T1049": {"discovery"},       // System Network Connections Discovery (netstat)
	"T1007": {"discovery"},       // System Service Discovery (sc/systemctl)
	"T1012": {"discovery"},       // Query Registry
	"T1135": {"discovery"},       // Network Share Discovery (net view/share)
	"T1046": {"discovery"},       // Network Service Discovery (port scan)
	"T1613": {"discovery"},       // Container and Resource Discovery (kubectl/docker/crictl)
	"T1612": {"defense-evasion"}, // Build Image on Host (bypass registry-side image scanning)
	"T1083": {"discovery"},       // File and Directory Discovery
	"T1482": {"discovery"},       // Domain Trust Discovery (nltest)
	"T1124": {"discovery"},       // System Time Discovery
	"T1010": {"discovery"},       // Application Window Discovery
	"T1201": {"discovery"},       // Password Policy Discovery (net accounts)
	"T1615": {"discovery"},       // Group Policy Discovery (gpresult / Get-DomainGPO)
	"T1580": {"discovery"},       // Cloud Infrastructure Discovery (aws ec2 / az vm / gcloud compute)
	"T1526": {"discovery"},       // Cloud Service Discovery (aws iam/sts/org, az ad/role, gcloud iam)
	"T1619": {"discovery"},       // Cloud Storage Object Discovery (aws s3 / az storage / gsutil)
	"T1217": {"discovery"},       // Browser Information Discovery
	"T1614": {"discovery"},       // System Location Discovery
	"T1120": {"discovery"},       // Peripheral Device Discovery
	// --- Collection ---
	"T1115": {"collection"},                      // Clipboard Data
	"T1113": {"collection"},                      // Screen Capture
	"T1056": {"collection", "credential-access"}, // Input Capture (keylogging)
	"T1114": {"collection"},                      // Email Collection
	"T1137": {"persistence"},                     // Office Application Startup
	"T1560": {"collection"},                      // Archive Collected Data
	"T1005": {"collection"},                      // Data from Local System
	"T1039": {"collection"},                      // Data from Network Shared Drive
	"T1119": {"collection"},                      // Automated Collection
	"T1074": {"collection"},                      // Data Staged
	"T1123": {"collection"},                      // Audio Capture
	"T1125": {"collection"},                      // Video Capture
	// --- Lateral Movement ---
	"T1021": {"lateral-movement"},                    // Remote Services (RDP/SMB/WinRM)
	"T1210": {"lateral-movement"},                    // Exploitation of Remote Services
	"T1570": {"lateral-movement"},                    // Lateral Tool Transfer
	"T1550": {"lateral-movement", "defense-evasion"}, // Use Alternate Authentication Material (PtH/PtT)
	"T1563": {"lateral-movement"},                    // Remote Service Session Hijacking
	"T1091": {"lateral-movement", "initial-access"},  // Replication Through Removable Media
	// --- Command and Control ---
	"T1071": {"command-and-control"}, // Application Layer Protocol (DNS/HTTP C2)
	"T1090": {"command-and-control"}, // Proxy (netsh portproxy internal pivot)
	"T1572": {"command-and-control"}, // Protocol Tunneling
	"T1219": {"command-and-control"}, // Remote Access Software
	"T1105": {"command-and-control"}, // Ingress Tool Transfer
	"T1095": {"command-and-control"}, // Non-Application Layer Protocol
	"T1571": {"command-and-control"}, // Non-Standard Port
	"T1568": {"command-and-control"}, // Dynamic Resolution (DGA)
	"T1102": {"command-and-control"}, // Web Service
	"T1132": {"command-and-control"}, // Data Encoding
	"T1573": {"command-and-control"}, // Encrypted Channel
	"T1008": {"command-and-control"}, // Fallback Channels
	"T1104": {"command-and-control"}, // Multi-Stage Channels
	// --- Initial Access ---
	"T1566": {"initial-access"}, // Phishing
	"T1190": {"initial-access"}, // Exploit Public-Facing Application
	"T1199": {"initial-access"}, // Trusted Relationship
	"T1195": {"initial-access"}, // Supply Chain Compromise
	// --- Exfiltration ---
	"T1041": {"exfiltration"}, // Exfiltration Over C2 Channel
	"T1048": {"exfiltration"}, // Exfiltration Over Alternative Protocol
	"T1567": {"exfiltration"}, // Exfiltration Over Web Service (rclone/cloud)
	"T1020": {"exfiltration"}, // Automated Exfiltration
	"T1011": {"exfiltration"}, // Exfiltration Over Other Network Medium
	"T1052": {"exfiltration"}, // Exfiltration Over Physical Medium
	"T1029": {"exfiltration"}, // Scheduled Transfer
	"T1030": {"exfiltration"}, // Data Transfer Size Limits
	// --- Impact ---
	"T1490": {"impact"}, // Inhibit System Recovery (vssadmin)
	"T1496": {"impact"}, // Resource Hijacking (cryptomining)
	"T1561": {"impact"}, // Disk Wipe
	"T1531": {"impact"}, // Account Access Removal
	"T1485": {"impact"}, // Data Destruction
	"T1486": {"impact"}, // Data Encrypted for Impact (ransomware)
	"T1489": {"impact"}, // Service Stop
	"T1491": {"impact"}, // Defacement
	"T1529": {"impact"}, // System Shutdown/Reboot
	"T1565": {"impact"}, // Data Manipulation
	"T1499": {"impact"}, // Endpoint Denial of Service
	"T1498": {"impact"}, // Network Denial of Service

	// Precision fill (2026-07-09): base techniques the platform's builtin rules detect
	// but that were absent here, so the scorer could not even Tactic-rank them (a
	// detected alert scored None for lack of a tactic). Adding them lets those
	// detections earn at least Tactic credit — closing a silent precision gap.
	"T1068": {"privilege-escalation"},                                // Exploitation for Privilege Escalation
	"T1202": {"defense-evasion"},                                     // Indirect Command Execution
	"T1216": {"defense-evasion"},                                     // System Script Proxy Execution
	"T1484": {"defense-evasion", "privilege-escalation"},             // Domain Policy Modification
	"T1539": {"credential-access"},                                   // Steal Web Session Cookie
	"T1556": {"credential-access", "defense-evasion", "persistence"}, // Modify Authentication Process
	"T1609": {"execution"},                                           // Container Administration Command
	"T1610": {"defense-evasion", "execution"},                        // Deploy Container
}

// extractTechnique は文字列中から最初の ATT&CK technique トークン(T+数字、
// サブテク含む)を抽出する。"attack.t1059.001" -> "T1059.001"、"T1003" -> "T1003"。
// "attack"(ATTACK)等に含まれる T は数字が続かないため誤抽出しない。該当無しは空。
func extractTechnique(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	for i := 0; i+1 < len(u); i++ {
		if u[i] != 'T' || u[i+1] < '0' || u[i+1] > '9' {
			continue
		}
		j := i + 1
		for j < len(u) && ((u[j] >= '0' && u[j] <= '9') || u[j] == '.') {
			j++
		}
		// 末尾の "." は落とす ("T1003." -> "T1003")。
		return strings.TrimRight(u[i:j], ".")
	}
	return ""
}

// baseTechnique は "T1059.001" -> "T1059" のようにサブテクニックを基底に正規化する。
func baseTechnique(t string) string {
	t = strings.ToUpper(strings.TrimSpace(t))
	if i := strings.Index(t, "."); i >= 0 {
		return t[:i]
	}
	return t
}

// tacticsOf は technique(サブテク可) が属する tactic 集合を返す。未知なら空。
func tacticsOf(t string) []string {
	return techniqueTactics[baseTechnique(t)]
}

// sameTechnique は2つの technique が Technique レベルで一致するかを判定する。
// MITRE Evaluations 流の精度に合わせ、サブテクニックを区別する:
//   - 完全一致 (T1059.001 == T1059.001) → true
//   - 一方が基底のみ (T1059.001 vs T1059) → true
//     (基底の検知は「どの technique か」を正しく特定しているため Technique 相当)
//   - 両方がサブテクで異なる (T1059.001 vs T1059.003) → **false**
//     (同一 technique ファミリだが別のサブテク=誤特定。Technique 加点はせず、
//     呼び出し側の shareTactic 経由で Tactic 止まりにする)
//   - 別ファミリ (T1059.001 vs T1003.001) → false
func sameTechnique(a, b string) bool {
	a = strings.ToUpper(strings.TrimSpace(a))
	b = strings.ToUpper(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true // 完全一致(サブテク含む)
	}
	ba, bb := baseTechnique(a), baseTechnique(b)
	if ba != bb {
		return false // 別ファミリ
	}
	// 同一基底: 少なくとも一方が基底のみなら Technique 一致とみなす。
	// 両方がサブテクで値が違う場合(上の a==b で弾かれている)は誤特定 → false。
	return a == ba || b == bb
}

// shareTactic は2つの technique が tactic を1つでも共有するかを判定する。
func shareTactic(a, b string) bool {
	ta, tb := tacticsOf(a), tacticsOf(b)
	for _, x := range ta {
		for _, y := range tb {
			if x == y {
				return true
			}
		}
	}
	return false
}
