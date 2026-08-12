package detection

import (
	"fmt"
	"testing"
	"time"
)

func TestLateralFanout_FiresOnManyHosts(t *testing.T) {
	d := newLateralFanoutScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	for i := 0; i < lateralMinHosts; i++ {
		dst := fmt.Sprintf("10.0.0.%d", i+1)
		m := d.Observe("agent1", dst, 445, base.Add(time.Duration(i)*time.Second)) // SMB
		fired += len(m)
		if len(m) > 0 && m[0].MITRETags[0] != "T1021" {
			t.Errorf("lateral fan-out should tag T1021, got %v", m[0].MITRETags)
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 lateral alert after %d hosts, got %d", lateralMinHosts, fired)
	}
}

func TestLateralFanout_NonServicePortIgnored(t *testing.T) {
	d := newLateralFanoutScorer()
	base := time.Unix(1_700_000_000, 0)
	// Fan-out to many hosts on a NON-service port (e.g. 443 web) is normal client
	// traffic, not lateral movement.
	for i := 0; i < lateralMinHosts*2; i++ {
		dst := fmt.Sprintf("93.184.216.%d", i+1)
		if m := d.Observe("agent1", dst, 443, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("fan-out on port 443 must not alert (iter %d)", i)
		}
	}
}

func TestLateralFanout_SameHostRepeatedNoFire(t *testing.T) {
	d := newLateralFanoutScorer()
	base := time.Unix(1_700_000_000, 0)
	// Many RDP connections to ONE server (a normal jump-host session) is one
	// distinct host, not a spread.
	for i := 0; i < lateralMinHosts*3; i++ {
		if m := d.Observe("agent1", "10.0.0.5", 3389, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("repeated RDP to one host must not alert (iter %d)", i)
		}
	}
}

func TestLateralFanout_WindowExpiry(t *testing.T) {
	d := newLateralFanoutScorer()
	base := time.Unix(1_700_000_000, 0)
	// Hosts contacted slower than the window never accumulate to the threshold.
	for i := 0; i < lateralMinHosts+3; i++ {
		dst := fmt.Sprintf("10.0.0.%d", i+1)
		if m := d.Observe("agent1", dst, 5985, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("hosts spaced beyond the window must not fan-out (iter %d)", i)
		}
	}
}
