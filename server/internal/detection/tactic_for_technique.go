// tactic_for_technique.go — MITRE テクニック→戦術の対応表。
//
// killchain.go から切り出してある。alerts_handler・コンプライアンススコアなど
// kept 側が参照する一方、killchain.go は公開版が同梱しない側（EXCLUDE §20.4）のため。
package detection

import "strings"

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
