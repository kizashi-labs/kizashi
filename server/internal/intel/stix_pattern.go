package intel

import "regexp"

// STIX 2.1 pattern → IOC 抽出。TAXII クライアント(taxii.go)と STIX/TAXII
// ハンドラ(api/handlers)が共有する唯一の実装。以前はハンドラ側に同じ正規表現が
// 二重定義されていたため、対応 IOC 型を増やすたびに両所を直す必要があった。
//
// STIX Indicator の pattern は STIX Patterning 言語(例
// `[ipv4-addr:value = '1.2.3.4']`)。ここでは単一 Comparison Expression の
// 主要オブジェクトパス(ipv4/ipv6-addr, domain-name, url, file:hashes)だけを
// 抽出する。AND/OR や複数観測を含む複雑パターンは最初にマッチした値を返す。
var (
	reSTIXIPv4   = regexp.MustCompile(`ipv4-addr:value\s*=\s*'([^']+)'`)
	reSTIXIPv6   = regexp.MustCompile(`ipv6-addr:value\s*=\s*'([^']+)'`)
	reSTIXDomain = regexp.MustCompile(`domain-name:value\s*=\s*'([^']+)'`)
	reSTIXURL    = regexp.MustCompile(`url:value\s*=\s*'([^']+)'`)
	// ハッシュは producer によってキーの引用有無が揺れる(`'SHA-256'` / `SHA-256`)
	// ため、任意の引用符を許容する。
	reSTIXSHA256 = regexp.MustCompile(`file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'`)
	reSTIXSHA1   = regexp.MustCompile(`file:hashes\.'?SHA-?1'?\s*=\s*'([^']+)'`)
	reSTIXMD5    = regexp.MustCompile(`file:hashes\.'?MD5'?\s*=\s*'([^']+)'`)
)

// ExtractIOCFromSTIXPattern parses a STIX 2.1 indicator pattern and returns the
// canonical IOC type and value. The returned type is one of ip, domain, url,
// sha256, sha1, md5. ok is false when no supported object path is found.
//
// Hash checks run before the generic ones so a file: pattern is never misread,
// and SHA-256/SHA-1 are tested before MD5 because their key strings are distinct.
func ExtractIOCFromSTIXPattern(pattern string) (iocType, value string, ok bool) {
	if m := reSTIXSHA256.FindStringSubmatch(pattern); len(m) == 2 {
		return "sha256", m[1], true
	}
	if m := reSTIXSHA1.FindStringSubmatch(pattern); len(m) == 2 {
		return "sha1", m[1], true
	}
	if m := reSTIXMD5.FindStringSubmatch(pattern); len(m) == 2 {
		return "md5", m[1], true
	}
	if m := reSTIXDomain.FindStringSubmatch(pattern); len(m) == 2 {
		return "domain", m[1], true
	}
	if m := reSTIXIPv4.FindStringSubmatch(pattern); len(m) == 2 {
		return "ip", m[1], true
	}
	if m := reSTIXIPv6.FindStringSubmatch(pattern); len(m) == 2 {
		return "ip", m[1], true
	}
	if m := reSTIXURL.FindStringSubmatch(pattern); len(m) == 2 {
		return "url", m[1], true
	}
	return "", "", false
}
