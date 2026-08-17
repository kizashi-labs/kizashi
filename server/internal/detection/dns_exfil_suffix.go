package detection

import "strings"

// dns_exfil_suffix.go — どこまでが「攻撃者が選んだ部分」かを決める。
//
// AnalyzeDNSQuery のスコアは payload（登録可能ドメインより下のラベル）の長さ・
// エントロピー・ラベル数で決まる。その payload を「末尾2ラベルを落とした残り」と
// 近似していたため、サービスエンドポイントのラベルが payload に混入していた。
//
// 実測(WIN-ENDPOINT-01, 2026-08-05):
//
//	inspector2-oval-prod-ap-northeast-1.s3.dualstack.ap-northeast-1.amazonaws.com
//	  → payload = "inspector2-oval-prod-ap-northeast-1" + "s3" + "dualstack" + "ap-northeast-1"
//	  → 長さ60・エントロピー4.02・6ラベル → score 4（閾値3）で誤検知
//
// 攻撃者が選べるのはバケット名の1ラベルだけで、s3 / dualstack / リージョンは
// AWS が決める固定部分である。これらを payload に含めるのは、宛先サービスの名前を
// 持ち出しデータとして数えているのと同じ。
//
// これは dns_aggregate.go の co.jp 問題と同型で、あちらだけ直してこちらが
// 残っていた。
//
// 未知のサフィックスでは従来どおり末尾2ラベルを落とす。既知のものだけ精度が
// 上がる、純粋に追加的な変更になる。

// serviceEndpointSuffixes are multi-label suffixes where everything below them is
// the customer-chosen part and everything from them up is fixed by the provider.
//
// "*" matches exactly one label (a region). Entries must be listed longest-first
// so the most specific one wins — s3.dualstack.*.amazonaws.com before
// s3.*.amazonaws.com.
//
// 網羅は狙わない。ここに無いサフィックスは従来の近似に落ちるだけで、
// 「検知が甘くなる」方向には倒れない。
var serviceEndpointSuffixes = [][]string{
	{"s3", "dualstack", "*", "amazonaws", "com"},
	{"s3", "*", "amazonaws", "com"},
	{"s3-accelerate", "amazonaws", "com"},
	{"s3", "amazonaws", "com"},
	{"blob", "core", "windows", "net"},
	{"file", "core", "windows", "net"},
	{"queue", "core", "windows", "net"},
	{"table", "core", "windows", "net"},
	{"storage", "googleapis", "com"},
	{"r2", "cloudflarestorage", "com"},
}

// exfilPayloadLabels returns the labels of q that lie below its suffix — the part
// an attacker could have filled with encoded data.
//
// Returns nil when the whole name is suffix (there is nothing an attacker chose).
func exfilPayloadLabels(q string) []string {
	labels := strings.Split(q, ".")

	if n := matchServiceSuffix(labels); n > 0 && len(labels) > n {
		return labels[:len(labels)-n]
	}

	// Fallback: the original approximation — drop domain + TLD.
	if len(labels) > 2 {
		return labels[:len(labels)-2]
	}
	return nil
}

// matchServiceSuffix returns the label count of the longest matching service
// suffix, or 0 when none matches.
func matchServiceSuffix(labels []string) int {
	for _, suf := range serviceEndpointSuffixes {
		if len(labels) <= len(suf) {
			continue // the name would be entirely suffix; not a payload carrier
		}
		tail := labels[len(labels)-len(suf):]
		if suffixMatches(tail, suf) {
			return len(suf)
		}
	}
	return 0
}

func suffixMatches(tail, pattern []string) bool {
	for i, want := range pattern {
		if want == "*" {
			if tail[i] == "" {
				return false
			}
			continue
		}
		if tail[i] != want {
			return false
		}
	}
	return true
}
