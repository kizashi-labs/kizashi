package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventKind selects which of the profile's spec tables an event is drawn from.
type EventKind int

const (
	KindProcess EventKind = iota
	KindFile
	KindNetwork
	KindDNS
	KindRegistry
	KindAuth
	KindImageLoad
)

// String returns the flat event-type name the server will store, so the
// simulator's own tallies line up with `SELECT event_type FROM events`.
func (k EventKind) String() string {
	switch k {
	case KindProcess:
		return "process"
	case KindFile:
		return "file"
	case KindNetwork:
		return "network"
	case KindDNS:
		return "dns"
	case KindRegistry:
		return "registry"
	case KindAuth:
		return "auth"
	case KindImageLoad:
		return "image_load"
	}
	return "unknown"
}

// Generator produces benign telemetry for one simulated host.
//
// Each host owns its own Generator and its own PRNG stream, seeded from the run
// seed and the host index, so a run is reproducible end to end: same seed, same
// hosts, same events, same alerts. Without that, an FP-rate regression could
// never be told apart from a different random draw.
type Generator struct {
	prof     *Profile
	rnd      *rand.Rand
	hostname string
	user     string
	srcIP    string
	pids     map[string]uint32
	sent     map[EventKind]int64
}

// NewGenerator binds a profile to one simulated host.
func NewGenerator(prof *Profile, hostname string, index int, seed uint64) (*Generator, error) {
	srcIP, err := hostAddr(prof.Subnet, index)
	if err != nil {
		return nil, err
	}
	// Two independent PCG streams derived from (seed, index) so hosts never
	// share a sequence while the whole run stays a pure function of the seed.
	rnd := rand.New(rand.NewPCG(seed, uint64(index)+0x9E3779B97F4A7C15))
	return &Generator{
		prof:     prof,
		rnd:      rnd,
		hostname: hostname,
		user:     prof.Users[index%len(prof.Users)],
		srcIP:    srcIP,
		pids:     map[string]uint32{},
		sent:     map[EventKind]int64{},
	}, nil
}

// Hostname returns this host's simulated hostname.
func (g *Generator) Hostname() string { return g.hostname }

// SrcIP returns this host's simulated address.
func (g *Generator) SrcIP() string { return g.srcIP }

// Sent returns per-kind counts of events produced so far.
func (g *Generator) Sent() map[string]int64 {
	out := make(map[string]int64, len(g.sent))
	for k, v := range g.sent {
		out[k.String()] = v
	}
	return out
}

// Platform maps the profile OS onto the wire enum.
func (g *Generator) Platform() v1.Platform {
	switch g.prof.OS {
	case "windows":
		return v1.Platform_PLATFORM_WINDOWS
	case "linux":
		return v1.Platform_PLATFORM_LINUX
	case "darwin":
		return v1.Platform_PLATFORM_DARWIN
	}
	return v1.Platform_PLATFORM_UNSPECIFIED
}

// PickKind chooses an event kind in proportion to the profile's hourly rates.
func (g *Generator) PickKind() EventKind {
	r := g.prof.Rates
	weights := []struct {
		kind EventKind
		w    float64
	}{
		{KindProcess, r.Process},
		{KindFile, r.File},
		{KindNetwork, r.Network},
		{KindDNS, r.DNS},
		{KindRegistry, r.Registry},
		{KindAuth, r.Auth},
		{KindImageLoad, r.ImageLoad},
	}
	total := r.Total()
	x := g.rnd.Float64() * total
	for _, w := range weights {
		if w.w <= 0 {
			continue
		}
		x -= w.w
		if x <= 0 {
			return w.kind
		}
	}
	// Float rounding on the final bucket: fall back to the last non-zero kind.
	for i := len(weights) - 1; i >= 0; i-- {
		if weights[i].w > 0 {
			return weights[i].kind
		}
	}
	return KindProcess
}

// Next produces one event of the given kind. It never returns nil for a kind
// whose rate is non-zero, because Profile.Validate guarantees a matching spec.
func (g *Generator) Next(kind EventKind) *v1.Event {
	var evt *v1.Event
	switch kind {
	case KindProcess:
		evt = g.processEvent()
	case KindFile:
		evt = g.fileEvent()
	case KindNetwork:
		evt = g.networkEvent()
	case KindDNS:
		evt = g.dnsEvent()
	case KindRegistry:
		evt = g.registryEvent()
	case KindAuth:
		evt = g.authEvent()
	case KindImageLoad:
		evt = g.imageLoadEvent()
	}
	if evt != nil {
		g.sent[kind]++
	}
	return evt
}

func (g *Generator) envelope(t v1.EventType) *v1.Event {
	return &v1.Event{
		Id:            uuid.New().String(),
		Timestamp:     timestamppb.New(time.Now()),
		Type:          t,
		SchemaVersion: 1,
	}
}

func (g *Generator) processEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.Processes, func(s ProcessSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_PROCESS)
	user := spec.User
	if user == "" {
		user = "{{user}}"
	}
	evt.Payload = &v1.Event_Process{Process: &v1.ProcessEvent{
		Pid:              g.pidFor(spec.Name),
		Ppid:             g.pidFor(spec.Parent),
		ProcessName:      g.expand(spec.Name),
		CommandLine:      g.expand(pickString(g.rnd, spec.CommandLines)),
		ImagePath:        g.expand(spec.Path),
		Username:         g.expand(user),
		Action:           v1.ProcessEvent_PROCESS_ACTION_CREATE,
		OriginalFileName: spec.OriginalFileName,
		FileDescription:  spec.FileDescription,
		ProductName:      spec.Product,
		CompanyName:      spec.Company,
		IntegrityLevel:   spec.IntegrityLevel,
	}}
	return evt
}

func (g *Generator) fileEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.Files, func(s FileSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_FILE)
	var size int64
	if len(spec.SizeRange) == 2 {
		size = g.int64Between(spec.SizeRange[0], spec.SizeRange[1])
	}
	fe := &v1.FileEvent{
		Path:        g.expand(pickString(g.rnd, spec.Paths)),
		Action:      fileAction(pickString(g.rnd, spec.Actions)),
		Pid:         g.pidFor(spec.Process),
		ProcessName: g.expand(spec.Process),
		FileSize:    size,
	}
	if fe.Action == v1.FileEvent_FILE_ACTION_RENAME {
		fe.OldPath = fe.Path + ".old"
	}
	evt.Payload = &v1.Event_File{File: fe}
	return evt
}

func (g *Generator) networkEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.Network, func(s NetworkSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	proto := spec.Proto
	if proto == "" {
		proto = "tcp"
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_NETWORK)
	evt.Payload = &v1.Event_Network{Network: &v1.NetworkEvent{
		SrcIp:       g.srcIP,
		SrcPort:     uint32(32768 + g.rnd.IntN(28000)),
		DstIp:       g.expand(pickString(g.rnd, spec.Hosts)),
		DstPort:     uint32(pickInt(g.rnd, spec.Ports)),
		Protocol:    proto,
		Direction:   v1.NetworkEvent_NETWORK_DIRECTION_OUTBOUND,
		BytesSent:   uint64(g.int64Range(spec.BytesSentRange, 200, 20_000)),
		BytesRecv:   uint64(g.int64Range(spec.BytesRecvRange, 500, 200_000)),
		Pid:         g.pidFor(spec.Process),
		ProcessName: g.expand(spec.Process),
		Hostname:    g.expand(spec.Hostname),
		IsEncrypted: pickInt(g.rnd, spec.Ports) == 443,
	}}
	return evt
}

func (g *Generator) dnsEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.DNS, func(s DNSSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	qtype := spec.Type
	if qtype == "" {
		qtype = "A"
	}
	query := g.expand(pickString(g.rnd, spec.Queries))
	evt := g.envelope(v1.EventType_EVENT_TYPE_DNS)
	evt.Payload = &v1.Event_Dns{Dns: &v1.DnsEvent{
		Query:       query,
		QueryType:   qtype,
		Answers:     []string{publicAnswerFor(query)},
		Pid:         g.pidFor(spec.Process),
		ProcessName: g.expand(spec.Process),
	}}
	return evt
}

func (g *Generator) registryEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.Registry, func(s RegistrySpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_REGISTRY)
	evt.Payload = &v1.Event_Registry{Registry: &v1.RegistryEvent{
		KeyPath:     g.expand(pickString(g.rnd, spec.Keys)),
		ValueName:   g.expand(pickString(g.rnd, spec.Values)),
		ValueData:   g.expand(pickString(g.rnd, spec.Data)),
		Action:      registryAction(pickString(g.rnd, spec.Actions)),
		Pid:         g.pidFor(spec.Process),
		ProcessName: g.expand(spec.Process),
	}}
	return evt
}

func (g *Generator) authEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.Auth, func(s AuthSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	method := pickString(g.rnd, spec.Methods)
	if method == "" {
		method = "password"
	}
	src := pickString(g.rnd, spec.Sources)
	if src == "" {
		src = g.srcIP
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_AUTH)
	evt.Payload = &v1.Event_Auth{Auth: &v1.AuthEvent{
		Username:      g.expand(pickString(g.rnd, spec.Users)),
		Action:        authAction(pickString(g.rnd, spec.Actions)),
		Success:       spec.Success,
		SourceIp:      g.expand(src),
		AuthMethod:    method,
		FailureReason: spec.Reason,
	}}
	return evt
}

func (g *Generator) imageLoadEvent() *v1.Event {
	spec := pickWeighted(g.rnd, g.prof.ImageLoads, func(s ImageLoadSpec) int { return s.Weight })
	if spec == nil {
		return nil
	}
	status := "unsigned"
	if spec.Signed {
		status = "valid"
	}
	evt := g.envelope(v1.EventType_EVENT_TYPE_IMAGE_LOAD)
	evt.Payload = &v1.Event_ImageLoad{ImageLoad: &v1.ImageLoadEvent{
		ImagePath:       g.expand(pickString(g.rnd, spec.Paths)),
		Pid:             g.pidFor(spec.Process),
		ProcessName:     g.expand(spec.Process),
		Signed:          spec.Signed,
		SignatureStatus: status,
		Signer:          spec.Signer,
	}}
	return evt
}

// ─── helpers ──────────────────────────────────────────────────

// pidFor returns a PID that is stable for a given process name on this host, so
// a process's file, network and image-load events all attribute to the same PID
// the way real telemetry does. Process-tree and correlation logic keys on PID;
// a fresh random PID per event would make every host look like a fork bomb.
func (g *Generator) pidFor(name string) uint32 {
	if name == "" {
		return 0
	}
	if pid, ok := g.pids[name]; ok {
		return pid
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(g.hostname + "\x00" + name))
	pid := h.Sum32()%60000 + 1000
	g.pids[name] = pid
	return pid
}

// expand substitutes the per-host placeholders a profile may use.
func (g *Generator) expand(s string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	s = strings.ReplaceAll(s, "{{user}}", g.user)
	s = strings.ReplaceAll(s, "{{host}}", g.hostname)
	s = strings.ReplaceAll(s, "{{srcip}}", g.srcIP)
	for strings.Contains(s, "{{rand}}") {
		s = strings.Replace(s, "{{rand}}", fmt.Sprintf("%08x", g.rnd.Uint32()), 1)
	}
	for strings.Contains(s, "{{randint}}") {
		s = strings.Replace(s, "{{randint}}", fmt.Sprintf("%d", g.rnd.IntN(99999)+1), 1)
	}
	for strings.Contains(s, "{{date}}") {
		s = strings.Replace(s, "{{date}}", time.Now().Format("20060102"), 1)
	}
	return s
}

// publicAnswerFor returns a plausible non-RFC1918 A record for one query name.
//
// The address set is STABLE per name and confined to a single /16, because that
// is what benign DNS looks like: a name resolves to the same handful of addresses
// inside one operator's netblock for the life of a TTL.
//
// This used to return a fully random address on every call, which made every
// simulated domain resolve to a different /16 each time it was queried. Any
// detector that inspects answer IPs then fires on ALL benign traffic by
// construction: the 2026-08-02 soak produced fast-flux alerts for google.com,
// microsoft.com, bing.com and jsdelivr.net, and the run's largest single false
// positive was a fast-flux alert on the fleet's own corp domain. Those alerts
// were artefacts of the generator, not findings about the detector.
//
// That matters more than a tuning detail. The whole measurement rests on
// "every event here is benign, so every alert is a false positive"
// (tests/fpsoak/README.md). Telemetry that is malicious-shaped by accident
// breaks that ground truth and makes the FP number unusable — it charges the
// detector for the simulator's unrealism.
//
// A handful of names still need many addresses to model real anycast/CDN
// behaviour; those belong in the profile, not in a blanket randomiser.
func publicAnswerFor(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSuffix(name, "."))))
	sum := h.Sum32()
	// One stable /16 per name, then up to 3 stable hosts inside it — the shape of
	// a small load-balanced service.
	a := 20 + int(sum%200)
	b := int((sum >> 8) % 256)
	c := int((sum >> 16) % 4)
	d := 1 + int((sum>>20)%3)
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func (g *Generator) int64Between(lo, hi int64) int64 {
	if hi <= lo {
		return lo
	}
	return lo + g.rnd.Int64N(hi-lo+1)
}

func (g *Generator) int64Range(r []int64, defLo, defHi int64) int64 {
	if len(r) == 2 {
		return g.int64Between(r[0], r[1])
	}
	return g.int64Between(defLo, defHi)
}

func pickWeighted[T any](rnd *rand.Rand, items []T, weight func(T) int) *T {
	if len(items) == 0 {
		return nil
	}
	total := 0
	for _, it := range items {
		total += weight(it)
	}
	if total <= 0 {
		return &items[0]
	}
	x := rnd.IntN(total)
	for i := range items {
		x -= weight(items[i])
		if x < 0 {
			return &items[i]
		}
	}
	return &items[len(items)-1]
}

func pickString(rnd *rand.Rand, ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[rnd.IntN(len(ss))]
}

func pickInt(rnd *rand.Rand, is []int) int {
	if len(is) == 0 {
		return 0
	}
	return is[rnd.IntN(len(is))]
}

func fileAction(s string) v1.FileEvent_FileAction {
	switch s {
	case "create":
		return v1.FileEvent_FILE_ACTION_CREATE
	case "modify":
		return v1.FileEvent_FILE_ACTION_MODIFY
	case "delete":
		return v1.FileEvent_FILE_ACTION_DELETE
	case "rename":
		return v1.FileEvent_FILE_ACTION_RENAME
	case "execute":
		return v1.FileEvent_FILE_ACTION_EXECUTE
	}
	return v1.FileEvent_FILE_ACTION_MODIFY
}

func registryAction(s string) v1.RegistryEvent_RegistryAction {
	switch s {
	case "create":
		return v1.RegistryEvent_REGISTRY_ACTION_CREATE
	case "modify":
		return v1.RegistryEvent_REGISTRY_ACTION_MODIFY
	case "delete":
		return v1.RegistryEvent_REGISTRY_ACTION_DELETE
	case "query":
		return v1.RegistryEvent_REGISTRY_ACTION_QUERY
	}
	return v1.RegistryEvent_REGISTRY_ACTION_MODIFY
}

func authAction(s string) v1.AuthEvent_AuthAction {
	switch s {
	case "login":
		return v1.AuthEvent_AUTH_ACTION_LOGIN
	case "logout":
		return v1.AuthEvent_AUTH_ACTION_LOGOUT
	case "privilege":
		return v1.AuthEvent_AUTH_ACTION_PRIVILEGE
	case "failed":
		return v1.AuthEvent_AUTH_ACTION_FAILED
	}
	return v1.AuthEvent_AUTH_ACTION_LOGIN
}

// hostAddr derives a stable address for host `index` inside cidr. Simulated
// hosts must sit in RFC1918 space: the cumulative-exfiltration detector excludes
// internal destinations, so a simulator that handed out public source addresses
// would change which detectors can fire and invalidate the measurement.
func hostAddr(cidr string, index int) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("subnet のパースに失敗しました %q: %w", cidr, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return "", fmt.Errorf("subnet は IPv4 である必要があります: %q", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	span := uint32(1) << uint(bits-ones)
	if span < 4 {
		return "", fmt.Errorf("subnet が小さすぎます: %q", cidr)
	}
	// Skip .0 (network) and stay inside the block; wraps for large fleets.
	offset := uint32(index%int(span-2)) + 1
	addr := binary.BigEndian.Uint32(base) + offset
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, addr)
	return out.String(), nil
}
