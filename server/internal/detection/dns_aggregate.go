// Package detection — dns_aggregate.go: stateful cross-query DNS tunneling
// detection.
//
// dns_exfil.go / dns_dga.go score ONE query's structure (entropy, encoding,
// label length). That misses tunnels whose individual labels look moderate but
// whose *volume* betrays them: a DNS tunnel (iodine/dnscat2) generates hundreds of
// DISTINCT subdomains under a single registrable domain in a short window, because
// each carries a different encoded chunk. This detector aggregates distinct
// subdomains per parent domain per host over a window and fires T1071.004 when the
// fan-out crosses a threshold — the cross-query dimension the per-query analyzers
// cannot see (docs/results/live-20260702-linux-evasion-adversarial.md).
package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// dnsAggWindow is the sliding window for counting distinct subdomains.
	dnsAggWindow = 60 * time.Second
	// dnsAggDistinctSubdomains is the number of distinct subdomains under one
	// registrable domain within the window that trips a tunneling alert. Set high
	// enough that ordinary apps (which reuse a handful of hostnames) do not trip it,
	// but well below the hundreds a real tunnel generates.
	dnsAggDistinctSubdomains = 30
	dnsAggDedup              = 5 * time.Minute
	dnsAggMaxKeys            = 8192
)

// dnsAggBenignParents are registrable domains that legitimately spread traffic
// across many distinct subdomains (CDNs, cloud object stores, telemetry). Prefix/
// suffix matched on the registrable domain to keep false positives low.
var dnsAggBenignParents = []string{
	"cloudfront.net", "akamai.net", "akamaiedge.net", "akamaihd.net",
	"amazonaws.com", "googleusercontent.com", "googleapis.com", "gvt1.com",
	"azureedge.net", "windows.net", "fastly.net", "fastlylb.net",
	"cdn.cloudflare.net", "cloudflare.com", "edgekey.net", "edgesuite.net",
	"1e100.net", "doubleclick.net", "gstatic.com", "office.com", "office365.com",
	"in-addr.arpa", "ip6.arpa",
}

type dnsAggState struct {
	subdomains map[string]int64 // subdomain -> last-seen unix seconds
	lastAlert  int64
}

// DNSTunnelAggregator is a stateful, concurrency-safe DNS-tunneling detector.
type DNSTunnelAggregator struct {
	mu   sync.Mutex
	keys map[string]*dnsAggState
}

func newDNSTunnelAggregator() *DNSTunnelAggregator {
	return &DNSTunnelAggregator{keys: make(map[string]*dnsAggState)}
}

// multiLabelPublicSuffixes are public suffixes made of two labels, under which
// anyone can register a name. Without them the "last two labels" rule collapses
// every Japanese corporate domain onto `co.jp`, every British one onto `co.uk`,
// and so on — the FP soak caught exactly that, reporting a fast-flux alert for
// the registrable domain "co.jp" because all *.co.jp answers had merged into one
// bucket. That is worse than noisy: unrelated organisations share a counter, so a
// real tunnel or flux hides inside the aggregate of everything else.
//
// This is a curated subset of the Public Suffix List covering the ccTLD
// second-level domains common in enterprise fleets, not the full list. Hosting
// suffixes where each subdomain is a separate owner (github.io, herokuapp.com,
// …) are a further gap; a full PSL would need a vendored data file and periodic
// refresh, which is a bigger change than this fix.
var multiLabelPublicSuffixes = map[string]bool{
	// 日本
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	"go.jp": true, "ad.jp": true, "ed.jp": true, "gr.jp": true, "lg.jp": true,
	// 英国
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"me.uk": true, "net.uk": true, "sch.uk": true, "ltd.uk": true, "plc.uk": true,
	// オーストラリア / ニュージーランド
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
	"gov.au": true, "id.au": true, "asn.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "ac.nz": true, "govt.nz": true,
	// アジア
	"co.kr": true, "or.kr": true, "ne.kr": true, "go.kr": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.tw": true, "com.hk": true, "com.sg": true, "com.my": true,
	"co.th": true, "com.vn": true, "co.id": true, "co.in": true, "net.in": true,
	"org.in": true, "co.il": true, "com.ph": true,
	// 欧州 / 中東 / 南米 / アフリカ
	"co.za": true, "com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.mx": true, "com.ar": true, "com.co": true,
	"com.tr": true, "com.pl": true, "com.ua": true, "co.ru": true,
	"com.es": true, "com.pt": true, "com.gr": true, "co.at": true, "or.at": true,
	// 逆引き。/8・/16 はそれぞれ別の委任先なので、"in-addr.arpa" ひとつに
	// まとめると無関係なネットワークのPTRが1バケットに載る。
	"in-addr.arpa": true, "ip6.arpa": true,
}

// registrableAndSub splits a query into (registrable domain, subdomain part).
//
// The registrable domain is the last two labels, except where those two labels
// are themselves a public suffix (see multiLabelPublicSuffixes), in which case
// three labels are taken. Approximating with a fixed two labels merges every
// organisation under a ccTLD second-level domain into a single bucket.
func registrableAndSub(query string) (reg, sub string) {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	labels := strings.Split(q, ".")

	take := 2
	if len(labels) >= 2 && multiLabelPublicSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		take = 3
	}
	if len(labels) <= take {
		return q, ""
	}
	reg = strings.Join(labels[len(labels)-take:], ".")
	sub = strings.Join(labels[:len(labels)-take], ".")
	return reg, sub
}

func isBenignDNSParent(reg string) bool {
	for _, b := range dnsAggBenignParents {
		if reg == b || strings.HasSuffix(reg, "."+b) {
			return true
		}
	}
	return false
}

// Observe records one DNS query and returns a T1071.004 match when a single host
// has queried dnsAggDistinctSubdomains distinct subdomains under one registrable
// domain within the window. now is injected for deterministic tests.
func (d *DNSTunnelAggregator) Observe(agentID, query string, now time.Time) []*detectionrules.RuleMatch {
	reg, sub := registrableAndSub(query)
	if sub == "" || isBenignDNSParent(reg) {
		return nil
	}
	key := agentID + "|" + reg
	nu := now.Unix()
	winSec := int64(dnsAggWindow / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > dnsAggMaxKeys {
		d.evictStale(nu, winSec*4)
	}
	st := d.keys[key]
	if st == nil {
		st = &dnsAggState{subdomains: make(map[string]int64)}
		d.keys[key] = st
	}
	for s, ts := range st.subdomains {
		if nu-ts > winSec {
			delete(st.subdomains, s)
		}
	}
	st.subdomains[sub] = nu

	if len(st.subdomains) < dnsAggDistinctSubdomains {
		return nil
	}
	if nu-st.lastAlert < int64(dnsAggDedup/time.Second) {
		return nil
	}
	st.lastAlert = nu
	n := len(st.subdomains)
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "DNSトンネリング（大量ユニークサブドメイン）",
		RuleType: "heuristic",
		Severity: 7,
		Title:    fmt.Sprintf("[HEURISTIC] DNSトンネリング検知: '%s' 配下に%d秒内で多数の異なるサブドメイン", reg, winSec),
		Description: fmt.Sprintf("単一ホストが登録ドメイン '%s' の配下に%d秒以内で%d個の異なるサブドメインを問い合わせ。DNSトンネリング/持ち出し(iodine/dnscat2 等)の疑い。クエリ単体の構造ではなくクロスクエリの量で判定するため、ラベルが中程度のエントロピーでも捕捉する。",
			reg, winSec, n),
		MITRETags: []string{"T1071.004", "T1048.003"}, // DNS C2 / Exfil over alternative protocol
	}}
}

func (d *DNSTunnelAggregator) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, ts := range st.subdomains {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}
