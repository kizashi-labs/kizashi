package detection

import "testing"

func TestAnalyzeDGA_FlagsGeneratedDomains(t *testing.T) {
	dga := []string{
		"kq3v9z7x1p.com",
		"wdfhjklmqv.net",
		"xkcdzqvbnm.biz",
		"3f7k9q2zx8.info",
		"zxqwvbnmkl.org",
	}
	for _, d := range dga {
		if v := AnalyzeDGA(d); !v.Suspicious {
			t.Errorf("expected DGA flag for %q (score=%d reasons=%v)", d, v.Score, v.Reasons)
		}
	}
}

func TestAnalyzeDGA_IgnoresBenign(t *testing.T) {
	benign := []string{
		"google.com",
		"discordapp.com",
		"googleusercontent.com",
		"cloudflare.net",
		"microsoft.com",
		"wikipedia.org",
		"amazonaws.com",
		"github.com",
		"d3akx9p2qz.cloudfront.net", // random SUBDOMAIN, but SLD "cloudfront" is benign
		"a1b2c3.akamaiedge.net",     // CDN subdomain; SLD "akamaiedge" benign
		"t.co",                      // too short
	}
	for _, d := range benign {
		if v := AnalyzeDGA(d); v.Suspicious {
			t.Errorf("false positive DGA flag for %q (score=%d reasons=%v domain=%q)", d, v.Score, v.Reasons, v.Domain)
		}
	}
}

func TestAnalyzeDGA_SLDExtraction(t *testing.T) {
	// The scored label must be the registrable domain, not the subdomain.
	v := AnalyzeDGA("sub.example.com")
	if v.Domain != "example" {
		t.Errorf("SLD extraction wrong: got %q, want example", v.Domain)
	}
}

// TestDGAComplementsExfil documents the division of labour: a long encoded subdomain is
// caught by the exfil analyzer (not DGA), and a short generated registrable domain by DGA
// (not exfil).
func TestDGAComplementsExfil(t *testing.T) {
	exfil := "M3JlYWxsLW9uZS1sb25nLWVuY29kZWQtY2h1bms.tunnel.evil.com"
	if !AnalyzeDNSQuery(exfil).Suspicious {
		t.Error("exfil analyzer should flag the long encoded subdomain")
	}
	dga := "kq3v9z7x1p.com"
	if !AnalyzeDGA(dga).Suspicious {
		t.Error("DGA analyzer should flag the generated registrable domain")
	}
}
