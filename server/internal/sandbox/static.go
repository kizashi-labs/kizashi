// Package sandbox — static.go: local static file analysis ("sandbox-lite").
//
// A full dynamic sandbox detonates a sample in an isolated VM and observes its
// behaviour. That needs disposable-VM infrastructure and is dangerous to run on a
// shared host, so this module does STATIC multi-signal analysis instead: it hashes
// the file, measures byte entropy (packers/encryption), identifies the file type
// from magic bytes, flags suspicious structural traits, and extracts embedded IOCs
// (URLs/IPs/domains) that the caller can correlate against threat intelligence. It
// produces a verdict WITHOUT executing the file, so it is safe and works offline
// and on unknown (zero-day) samples — the gap the hash-only VirusTotal path leaves.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
)

// StaticVerdict is the result of static analysis.
type StaticVerdict struct {
	SHA256   string   `json:"sha256"`
	Size     int      `json:"size"`
	FileType string   `json:"file_type"` // pe | elf | macho | script | archive | document | unknown
	Entropy  float64  `json:"entropy"`   // 0-8 (Shannon bits/byte)
	Score    int      `json:"score"`     // 0-100
	Verdict  string   `json:"verdict"`   // malicious | suspicious | benign
	Reasons  []string `json:"reasons"`
	URLs     []string `json:"embedded_urls"`
	IPs      []string `json:"embedded_ips"`
	Domains  []string `json:"embedded_domains"`
}

var (
	reURL    = regexp.MustCompile(`https?://[a-zA-Z0-9./_\-?=&%:@]+`)
	reIP     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
	// Obfuscation / living-off-the-land markers common in malicious scripts.
	scriptMarkers = []string{
		"eval(", "base64", "FromBase64String", "IEX", "Invoke-Expression",
		"powershell -e", "-enc ", "-EncodedCommand", "wget ", "curl ",
		"/dev/tcp/", "exec(", "os.system", "socket.socket", "chmod +x",
		"Add-MpPreference", "DownloadString", "New-Object Net.WebClient",
	}
)

// AnalyzeStatic runs static analysis over the file bytes. name is used only for a
// weak extension hint; the verdict is driven by content.
func AnalyzeStatic(name string, data []byte) StaticVerdict {
	sum := sha256.Sum256(data)
	v := StaticVerdict{
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     len(data),
		Entropy:  shannonEntropy(data),
		FileType: detectFileType(data),
		Reasons:  []string{},
		URLs:     []string{},
		IPs:      []string{},
		Domains:  []string{},
	}

	score := 0

	// Packed / encrypted: high whole-file entropy is a classic evasion signal
	// (excluding already-compressed archives, where high entropy is expected).
	if v.Entropy >= 7.2 && v.FileType != "archive" {
		score += 30
		v.Reasons = append(v.Reasons, "高エントロピー(パッカー/暗号化の疑い)")
	}

	// A PE/ELF embedded inside a non-executable container (dropper / packed loader).
	if v.FileType != "pe" && containsAt(data, mzMagic, 1) {
		score += 25
		v.Reasons = append(v.Reasons, "非実行ファイル内に埋め込まれた PE(ドロッパの疑い)")
	}

	// Script obfuscation / LOLBin markers.
	if v.FileType == "script" || v.Size < 1<<20 { // scan text-ish/small files
		lower := strings.ToLower(string(data))
		hits := 0
		for _, m := range scriptMarkers {
			if strings.Contains(lower, strings.ToLower(m)) {
				hits++
			}
		}
		if hits >= 3 {
			score += 30
			v.Reasons = append(v.Reasons, "スクリプト難読化/LOLBin マーカー多数")
		} else if hits > 0 {
			score += 10
			v.Reasons = append(v.Reasons, "スクリプト難読化/LOLBin マーカー")
		}
	}

	// Embedded IOCs — extracted for the caller to correlate with threat intel.
	v.URLs = uniqLimit(reURL.FindAllString(string(data), -1), 50)
	v.IPs = uniqLimit(filterPublicIPs(reIP.FindAllString(string(data), -1)), 50)
	v.Domains = uniqLimit(filterDomains(reDomain.FindAllString(string(data), -1)), 50)
	if len(v.URLs) > 0 || len(v.IPs) > 0 {
		score += 5
		v.Reasons = append(v.Reasons, "埋め込み URL/IP を検出(脅威インテリ相関を推奨)")
	}

	if score > 100 {
		score = 100
	}
	v.Score = score
	switch {
	case score >= 55:
		v.Verdict = "malicious"
	case score >= 25:
		v.Verdict = "suspicious"
	default:
		v.Verdict = "benign"
	}
	return v
}

var mzMagic = []byte{0x4D, 0x5A} // "MZ"

func detectFileType(d []byte) string {
	switch {
	case len(d) >= 2 && d[0] == 0x4D && d[1] == 0x5A:
		return "pe"
	case len(d) >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F':
		return "elf"
	case len(d) >= 4 && (u32(d) == 0xFEEDFACE || u32(d) == 0xFEEDFACF || u32(d) == 0xCAFEBABE):
		return "macho"
	case len(d) >= 2 && d[0] == '#' && d[1] == '!':
		return "script"
	case len(d) >= 4 && d[0] == 'P' && d[1] == 'K':
		return "archive"
	case len(d) >= 4 && d[0] == '%' && d[1] == 'P' && d[2] == 'D' && d[3] == 'F':
		return "document"
	case isMostlyText(d):
		return "script"
	default:
		return "unknown"
	}
}

func u32(d []byte) uint32 {
	return uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
}

// shannonEntropy returns the Shannon entropy of data in bits per byte (0-8).
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func isMostlyText(d []byte) bool {
	if len(d) == 0 {
		return false
	}
	sample := d
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	printable := 0
	for _, b := range sample {
		if b == 0x09 || b == 0x0a || b == 0x0d || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) > 0.85
}

// containsAt reports whether pattern appears anywhere at or after offset minOff.
func containsAt(data, pattern []byte, minOff int) bool {
	if len(data) < minOff+len(pattern) {
		return false
	}
	for i := minOff; i+len(pattern) <= len(data); i++ {
		if string(data[i:i+len(pattern)]) == string(pattern) {
			return true
		}
	}
	return false
}

func uniqLimit(in []string, limit int) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out
}

// filterPublicIPs drops obviously-non-routable/version noise (0.x, 127.x, 255.x).
func filterPublicIPs(in []string) []string {
	out := []string{}
	for _, ip := range in {
		if strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "127.") ||
			strings.HasPrefix(ip, "255.") || ip == "0.0.0.0" {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// filterDomains drops common non-IOC noise (version-like tokens, w3.org schemas).
func filterDomains(in []string) []string {
	out := []string{}
	for _, d := range in {
		if strings.HasSuffix(d, ".w3.org") || strings.HasSuffix(d, ".xmlsoap.org") {
			continue
		}
		out = append(out, d)
	}
	return out
}
