package detection

import "strings"

// ja3_blocklist.go — matches agent-reported JA3 / JA3S TLS fingerprints against a curated
// set of known C2 / offensive-tooling fingerprints. This is the network-behavioural axis
// the coverage audit calls out as the "真の穴＝プロセス署名を持たないビーコン検知": an
// implant's TLS stack fingerprints consistently regardless of its C2 domain or IP, so a
// JA3 hit flags malware whose 5-tuple and command line are otherwise unremarkable.
//
// The list is intentionally conservative — only fingerprints strongly associated with
// offensive frameworks, since some (e.g. a default Go TLS client JA3) also occur in benign
// software. Each entry records the tool and the ATT&CK technique. JA3 fingerprints are not
// unique identifiers (many clients share one), so a hit is a HIGH-severity lead for
// analyst review / correlation, not an auto-response trigger.

// JA3Signature describes a blocklisted fingerprint.
type JA3Signature struct {
	MD5       string   // JA3 or JA3S MD5 (lowercase hex)
	Tool      string   // associated tool / malware family
	Kind      string   // "ja3" (client) or "ja3s" (server)
	Severity  int      // alert severity
	MITRETags []string // ATT&CK techniques
}

// builtinJA3Blocklist is the shipped fingerprint set. MD5s are stored lowercase; matching
// is case-insensitive. Sourced from public C2 fingerprint research (abuse.ch SSLBL JA3,
// Salesforce ja3er, framework-default TLS stacks).
var builtinJA3Blocklist = []JA3Signature{
	// Metasploit Meterpreter reverse_https default handshake.
	{MD5: "a0e9f5d64349fb13191bc781f81f42e1", Tool: "Metasploit Meterpreter", Kind: "ja3", Severity: 9, MITRETags: []string{"T1071.001", "T1573.002"}},
	// Cobalt Strike default malleable-profile beacon (well-known JA3).
	{MD5: "72a589da586844d7f0818ce684948eea", Tool: "Cobalt Strike Beacon", Kind: "ja3", Severity: 9, MITRETags: []string{"T1071.001", "T1573.002"}},
	// Empire / PowerShell Empire HTTPS listener.
	{MD5: "5d65ea3fb1d4aa7d826733d2f2cbbb1d", Tool: "PowerShell Empire", Kind: "ja3", Severity: 8, MITRETags: []string{"T1071.001", "T1573.002"}},
	// Trickbot loader TLS.
	{MD5: "6734f37431670b3ab4292b8f60f29984", Tool: "Trickbot", Kind: "ja3", Severity: 8, MITRETags: []string{"T1071.001"}},
	// Sliver implant (mTLS listener) default JA3.
	{MD5: "3fed133de60c35724739b913924b6c24", Tool: "Sliver Implant", Kind: "ja3", Severity: 9, MITRETags: []string{"T1071.001", "T1573.002"}},
	// Cobalt Strike team-server JA3S (server side of the beacon handshake).
	{MD5: "ec74a5c51106f0419184d0dd08fb05bc", Tool: "Cobalt Strike Team Server", Kind: "ja3s", Severity: 9, MITRETags: []string{"T1071.001", "T1573.002"}},
	// Metasploit handler JA3S.
	{MD5: "80b3a14bccc8598a1f3bbe83e71f735f", Tool: "Metasploit Handler", Kind: "ja3s", Severity: 9, MITRETags: []string{"T1071.001", "T1573.002"}},
}

// ja3Index is a lowercase-MD5 → signature lookup built once from the blocklist.
var ja3Index = func() map[string]JA3Signature {
	m := make(map[string]JA3Signature, len(builtinJA3Blocklist))
	for _, s := range builtinJA3Blocklist {
		m[strings.ToLower(s.MD5)] = s
	}
	return m
}()

// matchJA3 returns the blocklist signature for a JA3 or JA3S MD5, or (zero,false) if the
// fingerprint is unknown. Empty input never matches.
func matchJA3(md5hex string) (JA3Signature, bool) {
	if md5hex == "" {
		return JA3Signature{}, false
	}
	s, ok := ja3Index[strings.ToLower(strings.TrimSpace(md5hex))]
	return s, ok
}
