package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
)

func testProfile(t *testing.T, name string) *Profile {
	t.Helper()
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, p := range profiles {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("profile %q not found", name)
	return nil
}

// signature reduces an event to the parts a profile determines, dropping the
// per-event UUID and wall-clock timestamp which are random by design.
func signature(e *v1.Event) string {
	switch p := e.GetPayload().(type) {
	case *v1.Event_Process:
		return fmt.Sprintf("proc|%s|%s|%d|%s", p.Process.GetProcessName(),
			p.Process.GetCommandLine(), p.Process.GetPid(), p.Process.GetUsername())
	case *v1.Event_File:
		return fmt.Sprintf("file|%s|%v|%d", p.File.GetPath(), p.File.GetAction(), p.File.GetFileSize())
	case *v1.Event_Network:
		return fmt.Sprintf("net|%s|%s|%d|%d|%d", p.Network.GetSrcIp(), p.Network.GetDstIp(),
			p.Network.GetDstPort(), p.Network.GetBytesSent(), p.Network.GetBytesRecv())
	case *v1.Event_Dns:
		return fmt.Sprintf("dns|%s|%s", p.Dns.GetQuery(), p.Dns.GetProcessName())
	case *v1.Event_Registry:
		return fmt.Sprintf("reg|%s|%s|%v", p.Registry.GetKeyPath(), p.Registry.GetValueName(),
			p.Registry.GetAction())
	case *v1.Event_Auth:
		return fmt.Sprintf("auth|%s|%v|%t|%s", p.Auth.GetUsername(), p.Auth.GetAction(),
			p.Auth.GetSuccess(), p.Auth.GetSourceIp())
	case *v1.Event_ImageLoad:
		return fmt.Sprintf("img|%s|%s|%t", p.ImageLoad.GetImagePath(),
			p.ImageLoad.GetProcessName(), p.ImageLoad.GetSigned())
	}
	return "unknown"
}

// TestGeneratorIsReproducible underpins the whole measurement: an FP-rate
// change between two runs must mean the detection content changed, not that the
// simulator drew different random numbers. Same seed and index ⇒ byte-identical
// event stream.
func TestGeneratorIsReproducible(t *testing.T) {
	prof := testProfile(t, "office-pc")

	run := func() []string {
		g, err := NewGenerator(prof, "fpsim-wks-0007", 7, 424242)
		if err != nil {
			t.Fatalf("new generator: %v", err)
		}
		out := make([]string, 0, 500)
		for i := 0; i < 500; i++ {
			out = append(out, signature(g.Next(g.PickKind())))
		}
		return out
	}

	a, b := run(), run()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("event %d differs between identical runs:\n  %s\n  %s", i, a[i], b[i])
		}
	}
}

func TestGeneratorDiffersPerHost(t *testing.T) {
	prof := testProfile(t, "office-pc")
	g1, err := NewGenerator(prof, "fpsim-wks-0001", 1, 99)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := NewGenerator(prof, "fpsim-wks-0002", 2, 99)
	if err != nil {
		t.Fatal(err)
	}
	same := 0
	for i := 0; i < 200; i++ {
		if signature(g1.Next(g1.PickKind())) == signature(g2.Next(g2.PickKind())) {
			same++
		}
	}
	if same > 150 {
		t.Errorf("hosts share too much of their event stream (%d/200 identical)", same)
	}
	if g1.SrcIP() == g2.SrcIP() {
		t.Errorf("distinct hosts got the same source address: %s", g1.SrcIP())
	}
}

// TestGeneratorEmitsEveryRatedKind is the simulator-side twin of the profile
// validator: a kind that is configured but never produced would make the soak
// report zero false positives for that entire event type and read as a pass.
func TestGeneratorEmitsEveryRatedKind(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, prof := range profiles {
		t.Run(prof.Name, func(t *testing.T) {
			g, err := NewGenerator(prof, "fpsim-test-0000", 0, 7)
			if err != nil {
				t.Fatalf("new generator: %v", err)
			}
			for i := 0; i < 20000; i++ {
				if evt := g.Next(g.PickKind()); evt == nil {
					t.Fatalf("generator returned a nil event at draw %d", i)
				}
			}
			sent := g.Sent()
			want := map[string]float64{
				"process": prof.Rates.Process, "file": prof.Rates.File,
				"network": prof.Rates.Network, "dns": prof.Rates.DNS,
				"registry": prof.Rates.Registry, "auth": prof.Rates.Auth,
				"image_load": prof.Rates.ImageLoad,
			}
			for kind, rate := range want {
				if rate > 0 && sent[kind] == 0 {
					t.Errorf("rates.%s = %g but no %s event was ever produced", kind, rate, kind)
				}
				if rate == 0 && sent[kind] > 0 {
					t.Errorf("rates.%s = 0 but %d %s events were produced", kind, sent[kind], kind)
				}
			}
		})
	}
}

// TestGeneratorRespectsRateProportions checks the mix, not just presence: a
// profile whose file rate is 7× its process rate must actually deliver roughly
// that ratio, otherwise "alerts per host-day" is normalised against telemetry
// the fleet never sent.
func TestGeneratorRespectsRateProportions(t *testing.T) {
	prof := testProfile(t, "office-pc")
	g, err := NewGenerator(prof, "fpsim-wks-0000", 0, 31337)
	if err != nil {
		t.Fatal(err)
	}
	const draws = 60000
	for i := 0; i < draws; i++ {
		g.Next(g.PickKind())
	}
	sent := g.Sent()

	total := prof.Rates.Total()
	for kind, rate := range map[string]float64{
		"process": prof.Rates.Process, "file": prof.Rates.File,
		"network": prof.Rates.Network, "dns": prof.Rates.DNS,
	} {
		want := rate / total
		got := float64(sent[kind]) / float64(draws)
		if got < want*0.85 || got > want*1.15 {
			t.Errorf("%s share = %.3f, want ≈%.3f (±15%%)", kind, got, want)
		}
	}
}

// TestGeneratorPayloadsAreWellFormed guards the wire contract: an event whose
// payload is empty is dropped or stored blank server-side, again producing a
// silently clean scorecard.
func TestGeneratorPayloadsAreWellFormed(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, prof := range profiles {
		g, err := NewGenerator(prof, "fpsim-test-0001", 1, 11)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5000; i++ {
			evt := g.Next(g.PickKind())
			if evt.GetId() == "" {
				t.Fatalf("%s: event has no id", prof.Name)
			}
			if evt.GetTimestamp() == nil {
				t.Fatalf("%s: event has no timestamp", prof.Name)
			}
			if evt.GetType() == v1.EventType_EVENT_TYPE_UNSPECIFIED {
				t.Fatalf("%s: event type is unspecified", prof.Name)
			}
			if evt.GetPayload() == nil {
				t.Fatalf("%s: event of type %v carries no payload", prof.Name, evt.GetType())
			}
			switch p := evt.GetPayload().(type) {
			case *v1.Event_Process:
				if p.Process.GetProcessName() == "" || p.Process.GetCommandLine() == "" {
					t.Fatalf("%s: process event missing name/cmdline", prof.Name)
				}
			case *v1.Event_File:
				if p.File.GetPath() == "" {
					t.Fatalf("%s: file event missing path", prof.Name)
				}
			case *v1.Event_Network:
				if net.ParseIP(p.Network.GetDstIp()) == nil {
					t.Fatalf("%s: network event has an unparseable dst %q",
						prof.Name, p.Network.GetDstIp())
				}
				if p.Network.GetDstPort() == 0 {
					t.Fatalf("%s: network event has port 0", prof.Name)
				}
			case *v1.Event_Dns:
				if p.Dns.GetQuery() == "" {
					t.Fatalf("%s: dns event missing query", prof.Name)
				}
			case *v1.Event_Auth:
				if p.Auth.GetUsername() == "" {
					t.Fatalf("%s: auth event missing username", prof.Name)
				}
			}
		}
	}
}

// TestSimulatedHostsAreInternal matters for correctness of the exfiltration
// measurement: exfil_volume.go only counts bytes to non-RFC1918 destinations, so
// a simulated host with a public source address would silently change which
// detectors can fire at all.
func TestSimulatedHostsAreInternal(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, prof := range profiles {
		for _, idx := range []int{0, 1, 17, 254, 255, 999} {
			g, err := NewGenerator(prof, "h", idx, 1)
			if err != nil {
				t.Fatalf("%s[%d]: %v", prof.Name, idx, err)
			}
			ip := net.ParseIP(g.SrcIP())
			if ip == nil {
				t.Fatalf("%s[%d]: unparseable source address %q", prof.Name, idx, g.SrcIP())
			}
			if !ip.IsPrivate() {
				t.Errorf("%s[%d]: source address %s is not RFC1918", prof.Name, idx, ip)
			}
		}
	}
}

func TestHostAddrRejectsBadSubnets(t *testing.T) {
	for _, cidr := range []string{"", "not-a-cidr", "10.0.0.1", "2001:db8::/64", "10.0.0.0/31"} {
		if _, err := hostAddr(cidr, 0); err == nil {
			t.Errorf("expected %q to be rejected", cidr)
		}
	}
}

func TestHostAddrIsStableAndInsideSubnet(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		got, err := hostAddr("10.20.0.0/16", i)
		if err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
		if !ipnet.Contains(net.ParseIP(got)) {
			t.Fatalf("index %d: %s is outside 10.20.0.0/16", i, got)
		}
		if seen[got] {
			t.Fatalf("index %d: duplicate address %s within the subnet capacity", i, got)
		}
		seen[got] = true

		again, _ := hostAddr("10.20.0.0/16", i)
		if again != got {
			t.Fatalf("index %d: address not stable (%s vs %s)", i, got, again)
		}
	}
}

func TestExpandSubstitutesPlaceholders(t *testing.T) {
	prof := testProfile(t, "dev-machine")
	g, err := NewGenerator(prof, "fpsim-dev-0003", 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	got := g.expand("/home/{{user}}/{{host}}/{{srcip}}")
	if strings.Contains(got, "{{") {
		t.Fatalf("placeholders left unexpanded: %s", got)
	}
	if !strings.Contains(got, g.Hostname()) || !strings.Contains(got, g.SrcIP()) {
		t.Errorf("expansion dropped host/ip: %s", got)
	}

	// Repeated placeholders must each get their own value, not one shared draw —
	// otherwise every "random" path in a batch collides and the file-burst
	// detector sees one path touched N times instead of N distinct paths.
	multi := g.expand("{{rand}}-{{rand}}-{{rand}}")
	parts := strings.Split(multi, "-")
	if len(parts) != 3 {
		t.Fatalf("unexpected expansion %q", multi)
	}
	if parts[0] == parts[1] && parts[1] == parts[2] {
		t.Errorf("repeated {{rand}} produced identical values: %s", multi)
	}
}

func TestExpandLeavesPlainStringsAlone(t *testing.T) {
	prof := testProfile(t, "dev-machine")
	g, _ := NewGenerator(prof, "h", 0, 1)
	const in = "/usr/bin/git"
	if got := g.expand(in); got != in {
		t.Errorf("expand mangled a plain string: %q -> %q", in, got)
	}
}

func TestPlatformMapping(t *testing.T) {
	cases := map[string]v1.Platform{
		"office-pc":     v1.Platform_PLATFORM_WINDOWS,
		"dev-machine":   v1.Platform_PLATFORM_LINUX,
		"backup-server": v1.Platform_PLATFORM_LINUX,
	}
	for name, want := range cases {
		g, err := NewGenerator(testProfile(t, name), "h", 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got := g.Platform(); got != want {
			t.Errorf("%s: platform = %v, want %v", name, got, want)
		}
	}
}

// TestPidIsStablePerProcessName pins the property correlation and process-tree
// logic depends on: one process name keeps one PID for the life of a host.
func TestPidIsStablePerProcessName(t *testing.T) {
	prof := testProfile(t, "office-pc")
	g, err := NewGenerator(prof, "fpsim-wks-0000", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := g.pidFor("chrome.exe")
	if first == 0 {
		t.Fatal("pidFor returned 0 for a named process")
	}
	for i := 0; i < 100; i++ {
		if got := g.pidFor("chrome.exe"); got != first {
			t.Fatalf("pid drifted: %d then %d", first, got)
		}
	}
	if g.pidFor("OUTLOOK.EXE") == first {
		t.Error("distinct processes share a PID")
	}
	if g.pidFor("") != 0 {
		t.Error("empty process name should map to pid 0")
	}
}
