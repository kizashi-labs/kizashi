package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Profile describes one class of simulated endpoint (office PC, build server,
// IT-admin workstation…): what it runs, what it talks to, and how often.
//
// A profile is *benign by construction* — that is the whole point. Every event a
// profile produces is, by definition of the soak, normal business activity, so
// any alert raised from it is a false positive. Profiles therefore deliberately
// include the "FP frontier": the benign behaviour that most resembles an attack
// (admin discovery commands, backup software touching thousands of files, a
// vulnerability scanner fanning out across the subnet, a nightly off-site upload
// measured in gigabytes). A soak built only from quiet desktop noise would report
// a flattering zero and measure nothing.
type Profile struct {
	Name        string `toml:"name"`
	OS          string `toml:"os"`         // windows|linux|darwin
	OSVersion   string `toml:"os_version"` // reported at enrollment
	Description string `toml:"description"`
	// HostPrefix distinguishes hosts of this profile inside the run's global
	// hostname prefix: <global>-<host_prefix>-<NNNN>.
	HostPrefix string `toml:"host_prefix"`
	// FleetWeight is this profile's share of the simulated fleet. Real fleets are
	// mostly ordinary desktops with a handful of admin and backup hosts; dealing
	// hosts evenly across profiles would over-represent exactly the noisy classes
	// and inflate the measured FP rate several-fold. Defaults to 1.
	FleetWeight int `toml:"fleet_weight"`
	// Users the simulated host's activity is attributed to. One is bound per
	// simulated agent, so {{user}} is stable for that host's whole run.
	Users []string `toml:"users"`
	// Subnet is the RFC1918 CIDR this host's own address is drawn from, e.g.
	// "10.20.0.0/16". Used as the source address of network events.
	Subnet string `toml:"subnet"`

	Rates Rates `toml:"rates"`

	Processes  []ProcessSpec   `toml:"processes"`
	Files      []FileSpec      `toml:"files"`
	Network    []NetworkSpec   `toml:"network"`
	DNS        []DNSSpec       `toml:"dns"`
	Registry   []RegistrySpec  `toml:"registry"`
	Auth       []AuthSpec      `toml:"auth"`
	ImageLoads []ImageLoadSpec `toml:"image_loads"`
}

// Rates are per-agent event counts per simulated hour, by event type. They are
// the knob that makes a soak comparable across runs: the report normalises alert
// counts by simulated host-days, and these rates define what one host-day of
// telemetry actually contains.
type Rates struct {
	Process   float64 `toml:"process"`
	File      float64 `toml:"file"`
	Network   float64 `toml:"network"`
	DNS       float64 `toml:"dns"`
	Registry  float64 `toml:"registry"`
	Auth      float64 `toml:"auth"`
	ImageLoad float64 `toml:"image_load"`
}

// Total returns the summed hourly event rate across all types.
func (r Rates) Total() float64 {
	return r.Process + r.File + r.Network + r.DNS + r.Registry + r.Auth + r.ImageLoad
}

// ProcessSpec is one kind of process launch this profile performs.
type ProcessSpec struct {
	Weight           int      `toml:"weight"`
	Name             string   `toml:"name"`
	Path             string   `toml:"path"`
	Parent           string   `toml:"parent"`
	CommandLines     []string `toml:"cmdlines"`
	User             string   `toml:"user"`
	IntegrityLevel   string   `toml:"integrity"`
	Company          string   `toml:"company"`
	Product          string   `toml:"product"`
	OriginalFileName string   `toml:"original_file_name"`
	FileDescription  string   `toml:"file_description"`
}

// FileSpec is one kind of file operation this profile performs.
type FileSpec struct {
	Weight  int      `toml:"weight"`
	Paths   []string `toml:"paths"`
	Actions []string `toml:"actions"` // create|modify|delete|rename|execute
	Process string   `toml:"process"`
	// SizeRange bounds the reported file size in bytes [min,max].
	SizeRange []int64 `toml:"size_range"`
}

// NetworkSpec is one kind of outbound connection this profile makes.
type NetworkSpec struct {
	Weight int      `toml:"weight"`
	Hosts  []string `toml:"hosts"` // destination IPs (literal)
	Ports  []int    `toml:"ports"`
	Proto  string   `toml:"proto"` // tcp|udp
	// Process attributing the connection.
	Process string `toml:"process"`
	// BytesSentRange / BytesRecvRange bound the per-connection byte counters.
	// The cumulative-exfiltration detector sums bytes_sent to external
	// destinations, so a profile that uploads backups off-site drives this
	// deliberately high — that is a benign case the detector must not fire on.
	BytesSentRange []int64 `toml:"bytes_sent_range"`
	BytesRecvRange []int64 `toml:"bytes_recv_range"`
	Hostname       string  `toml:"hostname"`
}

// DNSSpec is one kind of name lookup this profile performs.
type DNSSpec struct {
	Weight  int      `toml:"weight"`
	Queries []string `toml:"queries"`
	Type    string   `toml:"type"` // A|AAAA|TXT|... (default A)
	Process string   `toml:"process"`
}

// RegistrySpec is one kind of registry write (Windows profiles only).
type RegistrySpec struct {
	Weight  int      `toml:"weight"`
	Keys    []string `toml:"keys"`
	Values  []string `toml:"values"`
	Data    []string `toml:"data"`
	Actions []string `toml:"actions"` // create|modify|delete|query
	Process string   `toml:"process"`
}

// AuthSpec is one kind of authentication event.
type AuthSpec struct {
	Weight  int      `toml:"weight"`
	Users   []string `toml:"users"`
	Actions []string `toml:"actions"` // login|logout|privilege|failed
	Success bool     `toml:"success"`
	Methods []string `toml:"methods"` // password|key|token|mfa
	Sources []string `toml:"sources"` // source IPs
	Reason  string   `toml:"failure_reason"`
}

// ImageLoadSpec is one kind of module/DLL load.
type ImageLoadSpec struct {
	Weight  int      `toml:"weight"`
	Paths   []string `toml:"paths"`
	Process string   `toml:"process"`
	Signed  bool     `toml:"signed"`
	Signer  string   `toml:"signer"`
}

// LoadProfiles reads every *.toml in dir as a profile. Profiles are returned in
// filename order so a run with a fixed seed assigns the same profile to the same
// simulated host every time — a soak whose host↔profile mapping drifted between
// runs could not be compared against a baseline.
func LoadProfiles(dir string) ([]*Profile, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.toml"))
	if err != nil {
		return nil, fmt.Errorf("プロファイルディレクトリの走査に失敗しました: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("プロファイルが見つかりません: %s/*.toml", dir)
	}
	sort.Strings(paths)

	profiles := make([]*Profile, 0, len(paths))
	seen := map[string]string{}
	for _, p := range paths {
		prof, err := loadProfile(p)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[prof.Name]; dup {
			return nil, fmt.Errorf("プロファイル名が重複しています: %q (%s と %s)", prof.Name, prev, p)
		}
		seen[prof.Name] = p
		profiles = append(profiles, prof)
	}
	return profiles, nil
}

func loadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("プロファイルの読み込みに失敗しました %s: %w", path, err)
	}
	var prof Profile
	if err := toml.Unmarshal(data, &prof); err != nil {
		return nil, fmt.Errorf("プロファイルのパースに失敗しました %s: %w", path, err)
	}
	if err := prof.Validate(); err != nil {
		return nil, fmt.Errorf("プロファイル %s が不正です: %w", path, err)
	}
	return &prof, nil
}

// Validate rejects a profile that would silently generate nothing.
//
// The failure this guards is specific and has bitten this codebase before in the
// detection path (see the reachability hardening in docs/検知率向上_20260720_*):
// a component that is configured but emits nothing looks identical to a component
// that is working and finding nothing. A soak with a rate set but no matching
// spec would report an FP rate of zero for that event type and read as a pass.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name が空です")
	}
	switch p.OS {
	case "windows", "linux", "darwin":
	default:
		return fmt.Errorf("os は windows|linux|darwin のいずれかである必要があります (実際: %q)", p.OS)
	}
	if len(p.Users) == 0 {
		return fmt.Errorf("users が空です")
	}
	if strings.TrimSpace(p.Subnet) == "" {
		return fmt.Errorf("subnet が空です")
	}
	if p.Rates.Total() <= 0 {
		return fmt.Errorf("rates が全て 0 です — 何も送信されません")
	}
	if p.FleetWeight < 0 {
		return fmt.Errorf("fleet_weight が負値です: %d", p.FleetWeight)
	}

	// Every non-zero rate needs at least one spec to draw from.
	pairs := []struct {
		name  string
		rate  float64
		count int
	}{
		{"process", p.Rates.Process, len(p.Processes)},
		{"file", p.Rates.File, len(p.Files)},
		{"network", p.Rates.Network, len(p.Network)},
		{"dns", p.Rates.DNS, len(p.DNS)},
		{"registry", p.Rates.Registry, len(p.Registry)},
		{"auth", p.Rates.Auth, len(p.Auth)},
		{"image_load", p.Rates.ImageLoad, len(p.ImageLoads)},
	}
	for _, pair := range pairs {
		if pair.rate > 0 && pair.count == 0 {
			return fmt.Errorf("rates.%s = %g ですが [[%s]] の定義がありません — 無音になります",
				pair.name, pair.rate, pair.name)
		}
		if pair.rate < 0 {
			return fmt.Errorf("rates.%s が負値です: %g", pair.name, pair.rate)
		}
	}

	if p.Rates.Registry > 0 && p.OS != "windows" {
		return fmt.Errorf("registry イベントは windows プロファイルのみ有効です (os=%q)", p.OS)
	}

	return p.validateSpecs()
}

func (p *Profile) validateSpecs() error {
	for i, s := range p.Processes {
		if err := checkWeight("processes", i, s.Weight); err != nil {
			return err
		}
		if s.Name == "" {
			return fmt.Errorf("processes[%d].name が空です", i)
		}
		if len(s.CommandLines) == 0 {
			return fmt.Errorf("processes[%d] (%s) の cmdlines が空です", i, s.Name)
		}
	}
	for i, s := range p.Files {
		if err := checkWeight("files", i, s.Weight); err != nil {
			return err
		}
		if len(s.Paths) == 0 {
			return fmt.Errorf("files[%d].paths が空です", i)
		}
		if len(s.Actions) == 0 {
			return fmt.Errorf("files[%d].actions が空です", i)
		}
		if len(s.SizeRange) != 0 && len(s.SizeRange) != 2 {
			return fmt.Errorf("files[%d].size_range は [min,max] の2要素である必要があります", i)
		}
		if len(s.SizeRange) == 2 && s.SizeRange[0] > s.SizeRange[1] {
			return fmt.Errorf("files[%d].size_range の min が max を超えています", i)
		}
	}
	for i, s := range p.Network {
		if err := checkWeight("network", i, s.Weight); err != nil {
			return err
		}
		if len(s.Hosts) == 0 {
			return fmt.Errorf("network[%d].hosts が空です", i)
		}
		if len(s.Ports) == 0 {
			return fmt.Errorf("network[%d].ports が空です", i)
		}
		if err := checkRange(fmt.Sprintf("network[%d].bytes_sent_range", i), s.BytesSentRange); err != nil {
			return err
		}
		if err := checkRange(fmt.Sprintf("network[%d].bytes_recv_range", i), s.BytesRecvRange); err != nil {
			return err
		}
	}
	for i, s := range p.DNS {
		if err := checkWeight("dns", i, s.Weight); err != nil {
			return err
		}
		if len(s.Queries) == 0 {
			return fmt.Errorf("dns[%d].queries が空です", i)
		}
	}
	for i, s := range p.Registry {
		if err := checkWeight("registry", i, s.Weight); err != nil {
			return err
		}
		if len(s.Keys) == 0 {
			return fmt.Errorf("registry[%d].keys が空です", i)
		}
		if len(s.Actions) == 0 {
			return fmt.Errorf("registry[%d].actions が空です", i)
		}
	}
	for i, s := range p.Auth {
		if err := checkWeight("auth", i, s.Weight); err != nil {
			return err
		}
		if len(s.Users) == 0 {
			return fmt.Errorf("auth[%d].users が空です", i)
		}
		if len(s.Actions) == 0 {
			return fmt.Errorf("auth[%d].actions が空です", i)
		}
	}
	for i, s := range p.ImageLoads {
		if err := checkWeight("image_loads", i, s.Weight); err != nil {
			return err
		}
		if len(s.Paths) == 0 {
			return fmt.Errorf("image_loads[%d].paths が空です", i)
		}
	}
	return nil
}

// fleetWeight returns the profile's fleet share, defaulting to 1.
func (p *Profile) fleetWeight() int {
	if p.FleetWeight <= 0 {
		return 1
	}
	return p.FleetWeight
}

// AllocateFleet deals n simulated hosts across profiles by fleet_weight and
// returns the per-host profile assignment, host 0 first.
//
// Every profile is guaranteed at least one host whenever n allows it, before the
// remainder is distributed proportionally. That floor is deliberate: the noisy
// classes (IT-admin workstation, backup server) carry small fleet weights, and a
// purely proportional split would drop them entirely from a modest CI-sized run —
// silently removing the very behaviour the soak exists to measure and turning a
// 20-host smoke run into a measurement of desktops only.
//
// The result is a pure function of (profiles, n), so a run is reproducible.
func AllocateFleet(profiles []*Profile, n int) []*Profile {
	if n <= 0 || len(profiles) == 0 {
		return nil
	}

	counts := make([]int, len(profiles))
	remaining := n
	if n >= len(profiles) {
		for i := range counts {
			counts[i] = 1
		}
		remaining = n - len(profiles)
	}

	if remaining > 0 {
		totalW := 0
		for _, p := range profiles {
			totalW += p.fleetWeight()
		}
		type remainder struct {
			idx  int
			frac float64
		}
		rems := make([]remainder, 0, len(profiles))
		assigned := 0
		for i, p := range profiles {
			exact := float64(remaining) * float64(p.fleetWeight()) / float64(totalW)
			whole := int(exact)
			counts[i] += whole
			assigned += whole
			rems = append(rems, remainder{i, exact - float64(whole)})
		}
		// Largest-remainder: hand the rounding leftovers to the profiles with the
		// biggest fractional shares, ties broken by profile order for determinism.
		sort.SliceStable(rems, func(a, b int) bool { return rems[a].frac > rems[b].frac })
		for k := 0; k < remaining-assigned; k++ {
			counts[rems[k%len(rems)].idx]++
		}
	}

	out := make([]*Profile, 0, n)
	for i, c := range counts {
		for j := 0; j < c; j++ {
			out = append(out, profiles[i])
		}
	}
	for len(out) < n {
		out = append(out, profiles[len(out)%len(profiles)])
	}
	return out[:n]
}

func checkWeight(section string, i, weight int) error {
	if weight <= 0 {
		return fmt.Errorf("%s[%d].weight は 1 以上である必要があります (実際: %d)", section, i, weight)
	}
	return nil
}

func checkRange(field string, r []int64) error {
	if len(r) == 0 {
		return nil
	}
	if len(r) != 2 {
		return fmt.Errorf("%s は [min,max] の2要素である必要があります", field)
	}
	if r[0] > r[1] {
		return fmt.Errorf("%s の min が max を超えています", field)
	}
	if r[0] < 0 {
		return fmt.Errorf("%s が負値です", field)
	}
	return nil
}
