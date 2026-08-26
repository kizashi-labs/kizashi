// Package detection — dns_exfil.go implements a heuristic detector for DNS
// tunneling / exfiltration (ATT&CK T1048.003 / T1071.004).
//
// Volume-based behavioral rules (see migration 004) catch high-rate beaconing,
// but low-and-slow data exfiltration over DNS hides in a small number of
// individual queries whose *structure* gives them away: very long names, long
// individual labels, deep label nesting, and high-entropy encoded payloads
// (base32/base64/hex) in the subdomain.
//
// This analyzer scores those structural signals per query. It is intentionally
// conservative — a single high-entropy CDN hostname should not trip it; the
// signal must combine length and entropy to fire.
package detection

import (
	"math"
	"strings"
)

// DNSExfilVerdict is the result of analyzing a single DNS query.
type DNSExfilVerdict struct {
	Suspicious bool
	Score      int
	Reasons    []string
}

// dnsExfilThreshold is the score at or above which a query is flagged.
const dnsExfilThreshold = 3

// benignDNSSuffixes are internal / cloud-infrastructure DNS suffixes that resolve
// only within the host or VPC (the query is never forwarded to an external
// authoritative server), so they CANNOT be a DNS-exfil channel even when their
// structure superficially resembles tunneling. The classic false positive seen in
// production: a probe for "metadata.google.internal" gets the EC2 VPC search domain
// appended by the resolver, yielding the 56-char, 6-label name
// "metadata.google.internal.ap-northeast-1.compute.internal" — long + deep but
// entirely benign and fired every ~30s as a CRITICAL alert.
var benignDNSSuffixes = []string{
	".compute.internal",          // AWS VPC private DNS (region search domain)
	".ec2.internal",              // AWS EC2 classic private DNS
	".svc.cluster.local",         // Kubernetes service DNS
	".cluster.local",             // Kubernetes
	".in-addr.arpa", ".ip6.arpa", // reverse DNS
	"metadata.google.internal", // GCP metadata probe
	"metadata.goog",            // GCP metadata
}

// shannonEntropy returns the Shannon entropy (bits per character) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// hexBase32Ratio returns the fraction of characters in s that belong to the
// hex/base32 alphabet (a-z, 0-9), the typical charset of encoded DNS payloads.
func hexBase32Ratio(s string) float64 {
	if s == "" {
		return 0
	}
	enc := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			enc++
		}
	}
	return float64(enc) / float64(len(s))
}

// AnalyzeDNSQuery scores a DNS query for tunneling/exfiltration structure.
// The query is the full name (e.g. "M3JlYWxs.aGVsbG8.exfil.evil.com").
func AnalyzeDNSQuery(query string) DNSExfilVerdict {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	if q == "" {
		return DNSExfilVerdict{}
	}

	// Internal / cloud-infrastructure DNS resolves only within the host or VPC and
	// can never be an external exfil channel — exclude it before structural scoring
	// so VPC search-domain names (…compute.internal) don't false-positive.
	for _, suf := range benignDNSSuffixes {
		if q == strings.TrimPrefix(suf, ".") || strings.HasSuffix(q, suf) {
			return DNSExfilVerdict{}
		}
	}

	payloadLabels := exfilPayloadLabels(q)
	payload := strings.Join(payloadLabels, "")

	// Longest label among the PAYLOAD labels only. A suffix label cannot be an
	// encoded chunk, so including it only inflates the score.
	longestLabel := 0
	longestPayloadLabel := ""
	for _, l := range payloadLabels {
		if len(l) > longestLabel {
			longestLabel = len(l)
			longestPayloadLabel = l
		}
	}

	var score int
	var reasons []string
	add := func(pts int, reason string) {
		score += pts
		reasons = append(reasons, reason)
	}

	// Total length: tunneling crams data into the name, making it unusually long.
	if len(q) > 80 {
		add(2, "query length >80")
	} else if len(q) > 52 {
		add(1, "query length >52")
	}

	// A single very long label is a strong encoded-chunk indicator — but only when
	// the label actually looks encoded. Cloud storage bucket names are routinely
	// past 40 characters while being plain hyphenated words
	// ("aws-ssm-document-attachments-ap-northeast-1"), and length alone scored them
	// as if they carried a base32 chunk.
	if longestLabel > 40 && hexBase32Ratio(longestPayloadLabel) > 0.92 {
		add(1, "encoded-looking label >40")
	}

	// Deep subdomain nesting is used to pack multiple encoded chunks. Counted over
	// payload labels: with a two-label suffix this is the old "≥6 labels", but a
	// service endpoint like s3.dualstack.<region>.amazonaws.com contributes five
	// suffix labels that no attacker chose.
	if len(payloadLabels) >= 4 {
		add(1, "≥4 payload labels")
	}

	// High-entropy payload: encoded data, not human-readable hostnames.
	if len(payload) >= 25 {
		switch e := shannonEntropy(payload); {
		case e > 4.0:
			add(2, "high payload entropy >4.0")
		case e > 3.5:
			add(1, "elevated payload entropy >3.5")
		}
	} else if len(payload) >= 20 && shannonEntropy(payload) > 3.5 {
		add(1, "elevated payload entropy >3.5")
	}

	// Encoded-charset-dominated payload (base32/hex) of meaningful length.
	if len(payload) >= 20 && hexBase32Ratio(payload) > 0.92 && shannonEntropy(payload) > 3.0 {
		add(1, "encoded-charset payload")
	}

	return DNSExfilVerdict{
		Suspicious: score >= dnsExfilThreshold,
		Score:      score,
		Reasons:    reasons,
	}
}
