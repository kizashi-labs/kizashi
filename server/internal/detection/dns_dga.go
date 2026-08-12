// Package detection — dns_dga.go scores a DNS query's registrable domain for being
// algorithmically generated (DGA, ATT&CK T1568.002).
//
// This complements dns_exfil.go: the exfil analyzer flags long, high-entropy *subdomain
// payloads* (data tunneled below a normal domain); the DGA analyzer flags the *registrable
// domain label itself* looking machine-generated (kq3v9z7x1p.com), the rendezvous pattern
// of malware that cycles through generated C2 domains. CDN random *subdomains*
// (d3akx9p2qz.cloudfront.net) are NOT flagged because the analyzed label is the SLD
// ("cloudfront"), not the subdomain.
package detection

import "strings"

// DGAVerdict is the result of DGA analysis of one DNS query.
type DGAVerdict struct {
	Suspicious bool
	Score      int
	Domain     string // the SLD label that was scored
	Reasons    []string
}

// dgaThreshold is the score at or above which a domain is flagged as likely DGA.
const dgaThreshold = 4

func isVowel(c byte) bool {
	switch c {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}

func vowelRatio(s string) float64 {
	if s == "" {
		return 0
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if isVowel(s[i]) {
			v++
		}
	}
	return float64(v) / float64(len(s))
}

func digitRatio(s string) float64 {
	if s == "" {
		return 0
	}
	d := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			d++
		}
	}
	return float64(d) / float64(len(s))
}

// maxConsonantRun returns the longest run of consecutive consonant letters.
func maxConsonantRun(s string) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' && !isVowel(c) {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best
}

// AnalyzeDGA scores the registrable-domain label of query for DGA characteristics:
// random-looking strings have high entropy, long consonant runs, few vowels, and often a
// digit mix. Multiple signals must combine to fire (conservative, to limit false positives
// on legitimate but unusual domains).
func AnalyzeDGA(query string) DGAVerdict {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	if q == "" {
		return DGAVerdict{}
	}
	labels := strings.Split(q, ".")
	if len(labels) < 2 {
		return DGAVerdict{}
	}
	// Registrable-domain label ≈ second-from-last (no public-suffix list; multi-part TLDs
	// like co.uk are mis-handled, an accepted limitation — most DGA C2 uses single TLDs).
	sld := labels[len(labels)-2]
	// Too short = ordinary short domains; too long = exfil territory (dns_exfil handles it).
	if len(sld) < 8 || len(sld) > 30 {
		return DGAVerdict{Domain: sld}
	}

	e := shannonEntropy(sld)
	vr := vowelRatio(sld)
	cons := maxConsonantRun(sld)
	dr := digitRatio(sld)

	var score int
	var reasons []string
	add := func(p int, r string) { score += p; reasons = append(reasons, r) }

	switch {
	case e >= 3.6:
		add(2, "high entropy ≥3.6")
	case e >= 3.2:
		add(1, "entropy ≥3.2")
	}
	switch {
	case cons >= 5:
		add(2, "consonant run ≥5")
	case cons >= 4:
		add(1, "consonant run ≥4")
	}
	switch {
	case vr < 0.15:
		add(2, "very few vowels")
	case vr < 0.26:
		add(1, "few vowels")
	}
	if dr >= 0.30 {
		add(1, "high digit ratio")
	}

	return DGAVerdict{
		Suspicious: score >= dgaThreshold,
		Score:      score,
		Domain:     sld,
		Reasons:    reasons,
	}
}
