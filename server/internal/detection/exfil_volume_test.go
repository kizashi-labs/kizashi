package detection

import (
	"testing"
	"time"
)

func TestIsExternalIP(t *testing.T) {
	external := []string{"8.8.8.8", "203.0.113.10", "1.1.1.1", "2606:4700:4700::1111"}
	for _, ip := range external {
		if !isExternalIP(ip) {
			t.Errorf("%s should be external", ip)
		}
	}
	internal := []string{
		"10.0.0.5", "192.168.1.10", "172.16.5.4", "172.31.255.1", // RFC1918
		"127.0.0.1", "169.254.1.1", "100.64.0.1", // loopback, link-local, CGNAT
		"::1", "fc00::1", "fe80::1", // IPv6 loopback/ULA/link-local
		"0.0.0.0", "not-an-ip", "",
	}
	for _, ip := range internal {
		if isExternalIP(ip) {
			t.Errorf("%s should NOT be external", ip)
		}
	}
}

func TestExfilVolume_FiresOnLargeUpload(t *testing.T) {
	d := newExfilVolumeDetector()
	base := time.Unix(1_700_000_000, 0)
	chunk := int64(50 << 20) // 50 MiB per flow
	var fired int
	// 11 × 50 MiB = 550 MiB > 500 MiB threshold, to one external host.
	for i := 0; i < 11; i++ {
		m := d.Observe("agent1", "203.0.113.9", chunk, base.Add(time.Duration(i)*time.Second))
		fired += len(m)
		if len(m) > 0 && m[0].MITRETags[0] != "T1048" {
			t.Errorf("exfil should tag T1048, got %v", m[0].MITRETags)
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 exfil alert once cumulative bytes cross the threshold, got %d", fired)
	}
}

func TestExfilVolume_InternalDestinationIgnored(t *testing.T) {
	d := newExfilVolumeDetector()
	base := time.Unix(1_700_000_000, 0)
	// The same volume to an INTERNAL host (backup/file server) must not alert.
	for i := 0; i < 20; i++ {
		if m := d.Observe("agent1", "10.0.0.20", int64(100<<20), base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("exfil to internal destination must not alert (iter %d)", i)
		}
	}
}

func TestExfilVolume_SpreadAcrossHostsNoFire(t *testing.T) {
	d := newExfilVolumeDetector()
	base := time.Unix(1_700_000_000, 0)
	// Large total but spread across many DISTINCT external hosts — each under the
	// per-destination threshold (this is per-destination accumulation).
	for i := 0; i < 20; i++ {
		dst := "203.0.113." + itoa(i+1)
		if m := d.Observe("agent1", dst, int64(100<<20), base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("volume spread thinly across hosts must not alert (iter %d)", i)
		}
	}
}

func TestExfilVolume_WindowExpiry(t *testing.T) {
	d := newExfilVolumeDetector()
	base := time.Unix(1_700_000_000, 0)
	// 50 MiB every 2 minutes: never enough within the 10-minute window to reach
	// 500 MiB (at most ~6 samples = 300 MiB in-window).
	for i := 0; i < 20; i++ {
		if m := d.Observe("agent1", "203.0.113.9", int64(50<<20), base.Add(time.Duration(i)*2*time.Minute)); len(m) > 0 {
			t.Fatalf("slow trickle within window bound must not alert (iter %d)", i)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:            "512B",
		1024:           "1.0KiB",
		500 << 20:      "500.0MiB",
		int64(3) << 30: "3.0GiB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// itoa is a tiny local int→string helper to avoid importing strconv in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
