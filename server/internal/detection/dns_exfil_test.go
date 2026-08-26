package detection

import "testing"

// Benign hostnames — including high-entropy CDN/cloud names — must NOT be flagged.
func TestAnalyzeDNSQuery_BenignNotFlagged(t *testing.T) {
	benign := []string{
		"google.com",
		"www.microsoft.com",
		"api.github.com",
		"d111111abcdef8.cloudfront.net",
		"myaccount.blob.core.windows.net",
		"s3.us-east-1.amazonaws.com",
		"mail.google.com",
		"outlook.office365.com",
		"pkg-containers.githubusercontent.com",
		// Internal / cloud-infrastructure DNS that resolves only within the VPC and
		// cannot be an exfil channel. The first is the exact production false positive
		// (a metadata probe with the EC2 region search domain appended) that fired a
		// CRITICAL DNS-tunneling alert every ~30s on the server host.
		"metadata.google.internal.ap-northeast-1.compute.internal",
		"ip-10-0-0-10.ap-northeast-1.compute.internal",
		"kizashi-postgres.edr_default.svc.cluster.local",
		"100.4.0.10.in-addr.arpa",
	}
	for _, q := range benign {
		if v := AnalyzeDNSQuery(q); v.Suspicious {
			t.Errorf("benign %q should not be flagged (score %d, reasons %v)", q, v.Score, v.Reasons)
		}
	}
}

// Realistic DNS tunneling / exfiltration queries must be flagged.
func TestAnalyzeDNSQuery_TunnelingFlagged(t *testing.T) {
	malicious := []string{
		// Long base32-encoded payload across deep subdomains.
		"mfrgg2ltelbqcaytufrtg2lteorugk3tufqqgwzlz.aebagbafaydqqcik.exfil.evil.com",
		// Single very long encoded label.
		"a8f3b2c9d1e07f6a5b4c3d2e1f0098765432abcdef0123456789abcdef012345.tunnel.bad.net",
		// Deep nesting of encoded chunks.
		"nbswy3dp.eb2gqzlsmuxa.orsxg5bnnvxg.oZxxe3df.c2.dnscat.attacker.io",
	}
	for _, q := range malicious {
		if v := AnalyzeDNSQuery(q); !v.Suspicious {
			t.Errorf("tunneling query %q should be flagged (score %d, reasons %v)", q, v.Score, v.Reasons)
		}
	}
}

// T1048.003 honest coverage: the single-event Sigma benchmark cannot compute
// entropy, so DNS exfiltration stays a MISS there by design. This dedicated
// detector covers the realistic low-and-slow tunneling signal that the Sigma
// path and the volume-based behavioral rules both leave on the table.
func TestATTACKDNSExfilDetection(t *testing.T) {
	// A representative exfil query: base32-encoded data chunked across subdomains.
	q := "nbswy3dpeb2gqzlsmuxa.orsxg5bnnvxgo3df.payload2of3.exfil.attacker.io"
	v := AnalyzeDNSQuery(q)
	if !v.Suspicious {
		t.Fatalf("T1048.003 DNS exfil should be detected, got score %d reasons %v", v.Score, v.Reasons)
	}
	t.Logf("heuristic detection: T1048.003 DNS tunneling detected (score %d: %v) "+
		"— an honest single-event Sigma MISS now covered by the entropy/structure analyzer",
		v.Score, v.Reasons)
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("empty string entropy should be 0, got %v", e)
	}
	if e := shannonEntropy("aaaa"); e != 0 {
		t.Errorf("uniform string entropy should be 0, got %v", e)
	}
	// A varied string should have meaningfully positive entropy.
	if e := shannonEntropy("abcdefghij0123456789"); e < 4.0 {
		t.Errorf("varied string entropy should be high, got %v", e)
	}
}
