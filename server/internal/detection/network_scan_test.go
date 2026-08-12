package detection

import (
	"testing"
	"time"
)

func TestNetworkScanDetector_FiresOnFanOut(t *testing.T) {
	d := newNetworkScanDetector()
	base := time.Unix(1_700_000_000, 0)
	var fired []*struct{}
	var lastMatch bool
	// Connect to 20 distinct ports within the window from one source.
	for p := 1000; p < 1020; p++ {
		m := d.Observe("agent1", "bash", "127.0.0.1", p, true, base.Add(time.Duration(p-1000)*time.Second))
		if len(m) > 0 {
			fired = append(fired, &struct{}{})
			lastMatch = true
			if m[0].MITRETags[0] != "T1046" {
				t.Errorf("expected T1046, got %v", m[0].MITRETags)
			}
		}
	}
	if !lastMatch || len(fired) == 0 {
		t.Fatalf("expected a port-scan alert after 15+ distinct ports, got none")
	}
}

func TestNetworkScanDetector_NoFireBelowThreshold(t *testing.T) {
	d := newNetworkScanDetector()
	base := time.Unix(1_700_000_000, 0)
	// Only 6 distinct ports (like the v6 light scan) — below threshold, must not fire.
	for i, p := range []int{22, 80, 443, 5432, 8080, 9091} {
		if m := d.Observe("agent1", "bash", "127.0.0.1", p, false, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("fired at only %d distinct ports; threshold is %d", i+1, scanDistinctPorts)
		}
	}
}

func TestNetworkScanDetector_WindowExpiry(t *testing.T) {
	d := newNetworkScanDetector()
	base := time.Unix(1_700_000_000, 0)
	// Spread 20 ports over > window each so distinct count never accumulates.
	for i := 0; i < 20; i++ {
		at := base.Add(time.Duration(i) * 2 * scanWindow)
		if m := d.Observe("agent1", "curl", "10.0.0.1", 4000+i, false, at); len(m) > 0 {
			t.Fatalf("fired on slow spread-out connections (should be windowed out)")
		}
	}
}

func TestNetworkScanDetector_Dedup(t *testing.T) {
	d := newNetworkScanDetector()
	base := time.Unix(1_700_000_000, 0)
	fireCount := 0
	// 40 ports rapidly — should alert once, not on every port past threshold.
	for i := 0; i < 40; i++ {
		if m := d.Observe("agent1", "nmap", "10.0.0.1", 5000+i, true, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			fireCount++
		}
	}
	if fireCount != 1 {
		t.Errorf("expected exactly 1 alert (dedup), got %d", fireCount)
	}
}

func TestNetworkScanDetector_IgnoresInvalidPort(t *testing.T) {
	d := newNetworkScanDetector()
	if m := d.Observe("a", "p", "1.1.1.1", 0, false, time.Unix(1, 0)); m != nil {
		t.Errorf("expected nil for invalid port 0")
	}
}
