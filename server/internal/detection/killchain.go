// Package detection — killchain.go: cross-signal kill-chain risk scoring.
//
// Individual techniques often score only "tactic" or telemetry level and never
// raise a high-confidence alert on their own (measured: mixed set Technique 75%,
// with many discovery/evasion steps stuck at tactic — see
// docs/results/live-20260702-linux-evasion-adversarial.md). But an intrusion is a
// SEQUENCE: recon → credential access → persistence → C2 → exfil. This stateful
// scorer aggregates the ATT&CK TACTICS behind every match (even weak ones) per
// host over a sliding window and raises a correlated high-severity alert when a
// single host exhibits several distinct kill-chain stages — catching the
// multi-stage attack the per-event detectors each saw only a fragment of. The
// existing correlation engine links ALERTS; this links the weaker per-event
// signals that never became alerts.
package detection

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// chainWindow is the sliding window over which distinct tactics are counted.
	chainWindow = 10 * time.Minute
	// chainMinTactics is the number of distinct kill-chain tactics from one host
	// within the window that raises a correlated alert.
	chainMinTactics = 4
	chainMaxKeys    = 8192
)

// tacticForTechnique maps an ATT&CK technique (T####[.###]) to its primary
// tactic. Base-technique keyed; sub-techniques inherit the base. Not exhaustive —
// covers the techniques the detectors emit — with an "unknown" fallback that the
// scorer ignores.
func tacticForTechnique(t string) string {
	t = strings.ToUpper(strings.TrimSpace(t))
	if i := strings.Index(t, "."); i >= 0 {
		t = t[:i]
	}
	switch t {
	case "T1595", "T1592", "T1590", "T1589", "T1598", "T1597":
		return "reconnaissance"
	case "T1189", "T1190", "T1133", "T1200", "T1566", "T1078", "T1091":
		return "initial-access"
	case "T1059", "T1204", "T1203", "T1053", "T1129", "T1569", "T1047", "T1106", "T1620",
		"T1072", "T1559", "T1648", "T1609", "T1651":
		return "execution"
	case "T1547", "T1543", "T1546", "T1136", "T1098", "T1197", "T1505", "T1574",
		"T1037", "T1176", "T1554", "T1525", "T1653", "T1556":
		return "persistence"
	case "T1548", "T1134", "T1484", "T1068", "T1055", "T1611":
		return "privilege-escalation"
	case "T1562", "T1070", "T1027", "T1140", "T1036", "T1564", "T1218", "T1497", "T1222", "T1112", "T1006", "T1211",
		"T1014", "T1202", "T1207", "T1220", "T1480", "T1535", "T1542", "T1553", "T1578", "T1599", "T1600", "T1601", "T1610", "T1612", "T1656":
		return "defense-evasion"
	case "T1003", "T1552", "T1555", "T1110", "T1212", "T1187", "T1056", "T1558", "T1621",
		"T1040", "T1539", "T1606", "T1649":
		return "credential-access"
	case "T1087", "T1082", "T1083", "T1057", "T1016", "T1018", "T1046", "T1518", "T1201", "T1033", "T1069", "T1049", "T1007", "T1614", "T1526", "T1580",
		"T1010", "T1120", "T1124", "T1135", "T1217", "T1482", "T1538", "T1613", "T1622", "T1652":
		return "discovery"
	case "T1021", "T1080", "T1550", "T1563", "T1570", "T1210", "T1534":
		return "lateral-movement"
	case "T1005", "T1039", "T1025", "T1114", "T1213", "T1560", "T1119", "T1113", "T1115", "T1074",
		"T1123", "T1125", "T1530", "T1602", "T1557", "T1185":
		return "collection"
	case "T1071", "T1090", "T1095", "T1105", "T1132", "T1219", "T1568", "T1571", "T1573", "T1102",
		"T1001", "T1008", "T1092", "T1104", "T1572", "T1659", "T1665":
		return "command-and-control"
	case "T1041", "T1048", "T1567", "T1052", "T1011", "T1029", "T1020", "T1030", "T1537":
		return "exfiltration"
	case "T1485", "T1486", "T1490", "T1489", "T1491", "T1529", "T1561", "T1499", "T1498", "T1531",
		"T1496", "T1495", "T1488", "T1565", "T1657":
		return "impact"
	default:
		return ""
	}
}

type chainState struct {
	tactics    map[string]int64 // tactic -> last-seen unix seconds
	lastAlertN int              // distinct-tactic count at the last alert (for escalation)
}

// KillChainScorer is a stateful, concurrency-safe multi-stage-attack detector.
type KillChainScorer struct {
	mu       sync.Mutex
	entities map[string]*chainState
}

func newKillChainScorer() *KillChainScorer {
	return &KillChainScorer{entities: make(map[string]*chainState)}
}

// Observe folds the tactics behind one event's matches into the host's chain and
// returns a correlated alert when the host has shown chainMinTactics distinct
// kill-chain tactics within the window. now is injected for deterministic tests.
func (k *KillChainScorer) Observe(agentID string, mitreTags []string, now time.Time) []*detectionrules.RuleMatch {
	if agentID == "" || len(mitreTags) == 0 {
		return nil
	}
	nu := now.Unix()
	winSec := int64(chainWindow / time.Second)

	k.mu.Lock()
	defer k.mu.Unlock()

	if len(k.entities) > chainMaxKeys {
		k.evictStale(nu, winSec*2)
	}
	st := k.entities[agentID]
	if st == nil {
		st = &chainState{tactics: make(map[string]int64)}
		k.entities[agentID] = st
	}
	// Expire tactics outside the window.
	for tac, ts := range st.tactics {
		if nu-ts > winSec {
			delete(st.tactics, tac)
		}
	}
	for _, tag := range mitreTags {
		if tac := tacticForTechnique(tag); tac != "" {
			st.tactics[tac] = nu
		}
	}

	n := len(st.tactics)
	if n < chainMinTactics {
		// Chain fell back below threshold (tactics expired) — allow a fresh alert
		// if it climbs again.
		st.lastAlertN = 0
		return nil
	}
	// Fire on first crossing and ESCALATE as the chain grows (a longer chain is a
	// more complete, higher-confidence attack). Re-firing only on growth naturally
	// dedups repeated same-size observations.
	if n <= st.lastAlertN {
		return nil
	}
	st.lastAlertN = n

	tactics := make([]string, 0, len(st.tactics))
	for tac := range st.tactics {
		tactics = append(tactics, tac)
	}
	sort.Strings(tactics)
	sev := 7
	if n >= 6 {
		sev = 9 // a near-complete kill chain
	} else if n >= 5 {
		sev = 8
	}
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "キルチェーン相関: 多段攻撃の疑い",
		RuleType: "correlation",
		Severity: sev,
		Title:    "[KILLCHAIN] 多段攻撃の疑い: 複数段のATT&CK戦術を観測",
		Description: fmt.Sprintf("単一ホストが%d分以内に%d個の異なるATT&CK戦術を跨いで活動: %s。個別の弱い信号を横断集約した相関検知(単発ではアラート未満でも、キルチェーンとして高信頼)。",
			int(chainWindow/time.Minute), n, strings.Join(tactics, " → ")),
		MITRETags: []string{"TA0000"}, // correlation marker (not a single technique)
	}}
}

func (k *KillChainScorer) evictStale(nowUnix, maxAgeSec int64) {
	for key, st := range k.entities {
		var newest int64
		for _, ts := range st.tactics {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(k.entities, key)
		}
	}
}

// TacticForTechnique は tacticForTechnique の公開版。
//
// ATT&CK テクニック (T####[.###]) を主タクティクへ写す。網羅ではなく、
// 検知器が出すテクニックを対象にした表で、**表に無いものは空文字を返す**
// ("unknown" ではない)。呼び出し側は空文字を「タクティク不明」として
// 扱うこと。
//
// コンプライアンススコアの「カバー済みタクティク数」の算出でも同じ写像が
// 要るため公開した。scorer 側で別の表を持つと、片方だけ更新されて数字が
// 食い違う。
func TacticForTechnique(technique string) string { return tacticForTechnique(technique) }
