package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realProfileDir is the committed profile set the soak actually runs with.
const realProfileDir = "../../../tests/fpsoak/profiles"

// TestRealProfilesLoad is the guard that matters most for this tool: the
// committed profiles must parse and validate. A profile that silently fails to
// load would make a soak measure fewer host classes than it reports — and since
// fewer benign edge cases means fewer alerts, the run would look *better*, not
// broken. Validation failures have to surface here, not as a suspiciously clean
// scorecard.
func TestRealProfilesLoad(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("committed profiles failed to load: %v", err)
	}
	if len(profiles) < 5 {
		t.Fatalf("expected at least 5 committed profiles, got %d", len(profiles))
	}

	sawWindows, sawLinux := false, false
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			t.Errorf("profile %q failed validation: %v", p.Name, err)
		}
		if p.Rates.Total() <= 0 {
			t.Errorf("profile %q has zero total rate", p.Name)
		}
		switch p.OS {
		case "windows":
			sawWindows = true
		case "linux":
			sawLinux = true
		}
	}
	if !sawWindows || !sawLinux {
		t.Errorf("profile set must cover both Windows and Linux (windows=%v linux=%v)",
			sawWindows, sawLinux)
	}
}

// TestRealProfilesCoverFPFrontier pins the reason this profile set exists. A
// soak assembled only from quiet desktop noise reports ~0 false positives and
// proves nothing; the value comes from benign behaviour that looks like an
// attack. These are the specific stateful detectors shipped in July 2026
// (discovery / lateral_fanout / file_burst / exfil_volume), and the profile set
// must keep exercising all of them.
func TestRealProfilesCoverFPFrontier(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	var (
		discoveryBurst bool // ≥4 distinct discovery commands from one host
		lateralFanout  bool // one host → many hosts on remote-admin ports
		fileBurst      bool // one process deleting many files
		externalBulk   bool // large cumulative send to a non-RFC1918 destination
		internalBulk   bool // same volume to RFC1918 — must stay silent
	)

	discoveryVerbs := []string{"whoami", "systeminfo", "ipconfig", "net user", "nltest", "tasklist"}
	adminPorts := map[int]bool{3389: true, 5985: true, 5986: true, 445: true, 22: true}

	for _, p := range profiles {
		for _, proc := range p.Processes {
			hits := 0
			for _, verb := range discoveryVerbs {
				for _, cl := range proc.CommandLines {
					if containsFold(cl, verb) {
						hits++
						break
					}
				}
			}
			if hits >= 4 {
				discoveryBurst = true
			}
		}
		for _, spec := range p.Files {
			for _, a := range spec.Actions {
				if a == "delete" && len(spec.Paths) > 0 {
					fileBurst = true
				}
			}
		}
		for _, spec := range p.Network {
			adminPort := false
			for _, port := range spec.Ports {
				if adminPorts[port] {
					adminPort = true
				}
			}
			if adminPort && len(spec.Hosts) >= 8 {
				lateralFanout = true
			}
			if len(spec.BytesSentRange) == 2 && spec.BytesSentRange[1] >= 1_000_000_000 {
				if anyExternal(spec.Hosts) {
					externalBulk = true
				} else {
					internalBulk = true
				}
			}
		}
	}

	checks := []struct {
		name string
		ok   bool
	}{
		{"discovery burst (≥4 discovery verbs from one benign process)", discoveryBurst},
		{"lateral fan-out (admin ports to ≥8 hosts)", lateralFanout},
		{"file burst (bulk deletes)", fileBurst},
		{"bulk send to an external destination", externalBulk},
		{"bulk send to an internal destination (silent control)", internalBulk},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("profile set no longer exercises the FP frontier: %s", c.name)
		}
	}
}

func TestValidateRejectsRateWithoutSpec(t *testing.T) {
	p := &Profile{
		Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
		Rates: Rates{Process: 10},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected an error: process rate is set but no [[processes]] exist")
	}
	if !containsFold(err.Error(), "無音") {
		t.Errorf("error should name the silent-output failure, got: %v", err)
	}
}

func TestValidateRejectsRegistryOnNonWindows(t *testing.T) {
	p := &Profile{
		Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
		Rates:    Rates{Registry: 10},
		Registry: []RegistrySpec{{Weight: 1, Keys: []string{"k"}, Actions: []string{"modify"}}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected registry events on a Linux profile to be rejected")
	}
}

func TestValidateRejectsBadSpecs(t *testing.T) {
	base := func() *Profile {
		return &Profile{
			Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
			Rates:     Rates{Process: 1, Network: 1},
			Processes: []ProcessSpec{{Weight: 1, Name: "p", CommandLines: []string{"p"}}},
			Network: []NetworkSpec{{
				Weight: 1, Hosts: []string{"1.2.3.4"}, Ports: []int{443},
			}},
		}
	}

	cases := map[string]func(*Profile){
		"zero weight":         func(p *Profile) { p.Processes[0].Weight = 0 },
		"empty cmdlines":      func(p *Profile) { p.Processes[0].CommandLines = nil },
		"inverted byte range": func(p *Profile) { p.Network[0].BytesSentRange = []int64{100, 1} },
		"one-element range":   func(p *Profile) { p.Network[0].BytesRecvRange = []int64{100} },
		"negative rate":       func(p *Profile) { p.Rates.File = -1 },
		"empty subnet":        func(p *Profile) { p.Subnet = "" },
		"no users":            func(p *Profile) { p.Users = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(p)
			if err := p.Validate(); err == nil {
				t.Errorf("expected validation to reject %s", name)
			}
		})
	}
}

func TestLoadProfilesRejectsDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	body := `
name = "dup"
os = "linux"
subnet = "10.0.0.0/24"
users = ["u"]
[rates]
process = 1
[[processes]]
weight = 1
name = "sh"
cmdlines = ["sh"]
`
	for _, f := range []string{"a.toml", "b.toml"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadProfiles(dir); err == nil {
		t.Fatal("expected duplicate profile names to be rejected")
	}
}

func TestLoadProfilesRejectsEmptyDir(t *testing.T) {
	if _, err := LoadProfiles(t.TempDir()); err == nil {
		t.Fatal("expected an empty profile directory to be an error, not an empty fleet")
	}
}

// TestAllocateFleetGuaranteesEveryProfile is the regression guard for the floor
// in AllocateFleet: without it, the low-weight noisy profiles (it-admin at 8,
// backup-server at 4) round to zero on a small run and the soak quietly stops
// measuring the behaviour it was built for.
func TestAllocateFleetGuaranteesEveryProfile(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, n := range []int{len(profiles), 10, 20, 50, 200, 1000} {
		got := AllocateFleet(profiles, n)
		if len(got) != n {
			t.Fatalf("n=%d: allocated %d hosts", n, len(got))
		}
		counts := map[string]int{}
		for _, p := range got {
			counts[p.Name]++
		}
		for _, p := range profiles {
			if counts[p.Name] == 0 {
				t.Errorf("n=%d: profile %q got no hosts", n, p.Name)
			}
		}
	}
}

func TestAllocateFleetRespectsWeights(t *testing.T) {
	profiles := []*Profile{
		{Name: "heavy", FleetWeight: 90},
		{Name: "light", FleetWeight: 10},
	}
	got := AllocateFleet(profiles, 100)
	counts := map[string]int{}
	for _, p := range got {
		counts[p.Name]++
	}
	// 2 hosts go to the per-profile floor, the remaining 98 split 90:10.
	if counts["heavy"] <= counts["light"]*5 {
		t.Errorf("weighting not applied: heavy=%d light=%d", counts["heavy"], counts["light"])
	}
	if counts["heavy"]+counts["light"] != 100 {
		t.Errorf("allocation does not sum to n: %v", counts)
	}
}

func TestAllocateFleetIsDeterministic(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	first := AllocateFleet(profiles, 137)
	for i := 0; i < 5; i++ {
		again := AllocateFleet(profiles, 137)
		for j := range first {
			if first[j].Name != again[j].Name {
				t.Fatalf("allocation is not deterministic at host %d: %q vs %q",
					j, first[j].Name, again[j].Name)
			}
		}
	}
}

func TestAllocateFleetSmallerThanProfileCount(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := AllocateFleet(profiles, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(got))
	}
}

// ─── helpers ──────────────────────────────────────────────────

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func anyExternal(hosts []string) bool {
	for _, h := range hosts {
		ip := net.ParseIP(h)
		if ip == nil {
			continue
		}
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return true
		}
	}
	return false
}
