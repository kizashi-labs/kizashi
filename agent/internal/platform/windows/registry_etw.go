//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

const (
	// registrySessionName is a dedicated ETW session for the manifest
	// Microsoft-Windows-Kernel-Registry provider.
	registrySessionName = "EDR-Agent-Registry"
	// kernelRegistryGUID is Microsoft-Windows-Kernel-Registry.
	kernelRegistryGUID = "{70eb4f03-c1de-4f73-a051-33d13d5413bd}"

	// kcbMapCap bounds the KeyObject→path map. The Kernel-Registry provider is a
	// firehose; on overflow the map is reset (paths rebuild as keys are reopened),
	// trading a brief window of partial paths for bounded memory.
	kcbMapCap = 1 << 17 // 131072
)

// ETWRegistryCollector captures registry modifications via the
// Microsoft-Windows-Kernel-Registry provider. Unlike the RegNotifyChangeKeyValue
// collector (which only reports "something under one of 5 fixed keys changed"),
// this yields the specific value name, the operation (create/modify/delete) and —
// for persistence-relevant keys — the value data. Emission is filtered to
// auto-start / persistence (ASEP) keys so the provider's firehose does not flood
// the pipeline; CreateKey/OpenKey events are consumed only to resolve full paths.
//
// Limitation: golang-etw does not populate this provider's event System header,
// so the acting process (Execution.ProcessID) is unavailable; events carry the
// key/value/data depth but not the writer PID. Opt-in via EDR_AGENT_ETW (shared
// with the other ETW collectors); a no-op when disabled or if the session can't
// start.
type ETWRegistryCollector struct {
	cancel      context.CancelFunc
	out         chan<- collector.RegistryEvent
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer

	// kcb maps a KeyObject pointer to its reconstructed path. Only the ETW
	// consumer callback (single-threaded) touches it, so no lock is needed.
	kcb map[uint64]string
}

func NewETWRegistryCollector() *ETWRegistryCollector {
	return &ETWRegistryCollector{kcb: make(map[uint64]string, 4096)}
}

func (c *ETWRegistryCollector) Start(ctx context.Context, out chan<- collector.RegistryEvent) error {
	c.out = out
	if !etwEnabled() {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorETWRegistry, err)
		return nil
	}
	slog.Info("ETWレジストリ監視を開始しました (Microsoft-Windows-Kernel-Registry)")
	return nil
}

func (c *ETWRegistryCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, registrySessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWRegistryCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(kernelRegistryGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel-registry provider: %w", err)
	}
	// Every Kernel-Registry event carries an operation keyword (SetValueKey,
	// CreateKey, …). MatchAnyKeyword must be all-ones to receive them; left at 0
	// the provider delivers nothing (the manifest has no keyword-0 events).
	prov.MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF
	prov.EnableLevel = 0xFF

	session := etw.NewRealTimeSession(registrySessionName)
	if err := session.EnableProvider(prov); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("enable provider: %w", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(session)
	consumer.EventCallback = func(e *etw.Event) error {
		c.handleETWEvent(e)
		return nil
	}
	if err := consumer.Start(); err != nil {
		_ = session.Stop()
		return nil, fmt.Errorf("start consumer: %w", err)
	}

	c.etwSession = session
	c.etwConsumer = consumer
	return consumer, nil
}

func (c *ETWRegistryCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent classifies events by their property signature rather than by
// EventID: golang-etw does not populate the System header (EventID/Opcode/
// Execution all come through as 0) for this manifest provider, so the EventData
// fields are the only reliable discriminator.
//
//	CreateKey/OpenKey  → has RelativeName (+ KeyObject)         → path tracking
//	SetValueKey        → has ValueName + Type (+ PreviousDataType)
//	QueryValueKey      → has ValueName + InfoClass, no Type     → ignored
//	DeleteValueKey     → has ValueName, no Type, no InfoClass
func (c *ETWRegistryCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWレジストリ処理でパニックを回復しました", "panic", r)
		}
	}()

	// Key open/create: record KeyObject→path (the firehose; cheap, no emission).
	if rel, ok := e.GetPropertyString("RelativeName"); ok && rel != "" {
		c.trackKey(e, rel)
		if disp, _ := e.GetPropertyString("Disposition"); strings.TrimSpace(disp) == "1" {
			if path := c.pathForKeyObject(e); isSensitiveRegPath(path) {
				c.emit(path, "", "create")
			}
		}
		return
	}

	valueName, hasVN := e.GetPropertyString("ValueName")
	if !hasVN || valueName == "" {
		return // key-only ops we don't act on (close/query-key/delete-key)
	}
	_, hasType := e.GetPropertyString("Type")           // SetValueKey only
	_, hasInfoClass := e.GetPropertyString("InfoClass") // QueryValueKey only
	if !hasType && hasInfoClass {
		return // QueryValueKey — a read, not a change
	}

	path := c.pathForKeyObject(e)
	if !isSensitiveRegPath(path) {
		return
	}
	if hasType {
		c.emit(path, valueName, "modify")
	} else {
		c.emit(path, valueName, "delete")
	}
}

// trackKey records the path of a created/opened key, keyed by its KeyObject, by
// joining the (already-known) parent path with the relative name.
func (c *ETWRegistryCollector) trackKey(e *etw.Event, rel string) {
	keyObj := propUint(e, "KeyObject")
	if keyObj == 0 {
		return
	}
	base := ""
	if baseObj := propUint(e, "BaseObject"); baseObj != 0 {
		base = c.kcb[baseObj]
	}
	if base == "" {
		if bn, _ := e.GetPropertyString("BaseName"); bn != "" {
			base = bn
		}
	}
	full := rel
	if base != "" {
		full = base + `\` + rel
	}
	if len(c.kcb) >= kcbMapCap {
		c.kcb = make(map[uint64]string, 4096) // bounded reset
	}
	c.kcb[keyObj] = full
}

// pathForKeyObject returns the normalized path for an event's KeyObject, falling
// back to any inline KeyName/RelativeName the event carries.
func (c *ETWRegistryCollector) pathForKeyObject(e *etw.Event) string {
	p := c.kcb[propUint(e, "KeyObject")]
	if p == "" {
		if kn, ok := e.GetPropertyString("KeyName"); ok && kn != "" {
			p = kn
		} else if rn, ok := e.GetPropertyString("RelativeName"); ok {
			p = rn
		}
	}
	return normalizeRegPath(p)
}

// emit resolves the hive/value data (best-effort) and sends a RegistryEvent.
func (c *ETWRegistryCollector) emit(keyPath, valueName, action string) {
	data := ""
	if action == "modify" && valueName != "" {
		if full, d, ok := resolveValue(keyPath, valueName); ok {
			keyPath, data = full, d
		}
	}
	evt := collector.RegistryEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		KeyPath:   keyPath,
		ValueName: valueName,
		ValueData: data,
		Action:    action,
		// PID/ProcessName intentionally unset: see the type doc — golang-etw zeroes
		// the System header for this provider and the actor PID is not an EventData
		// field, so the writing process is not recoverable here.
	}
	select {
	case c.out <- evt:
	default:
	}
}

func (c *ETWRegistryCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ─── helpers ──────────────────────────────────────────────

// propUint reads a property the provider renders as a hex pointer string
// ("0xFFFF...") and parses it to a uint64. Returns 0 when absent/unparsable.
func propUint(e *etw.Event, name string) uint64 {
	s, ok := e.GetPropertyString(name)
	if !ok || s == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
	if err != nil {
		return 0
	}
	return n
}

// normalizeRegPath rewrites the NT registry namespace into the familiar hive
// prefixes so analysts and Sigma rules see HKLM\..., HKU\... paths.
func normalizeRegPath(p string) string {
	if p == "" {
		return ""
	}
	low := strings.ToLower(p)
	switch {
	case strings.HasPrefix(low, `\registry\machine`):
		return "HKLM" + p[len(`\registry\machine`):]
	case strings.HasPrefix(low, `registry\machine`):
		return "HKLM" + p[len(`registry\machine`):]
	case strings.HasPrefix(low, `\registry\user`):
		return "HKU" + p[len(`\registry\user`):]
	case strings.HasPrefix(low, `registry\user`):
		return "HKU" + p[len(`registry\user`):]
	}
	return p
}

// sensitiveRegFragments are case-insensitive substrings of auto-start /
// persistence (ASEP) registry locations that malware abuses. Emission is gated
// on these so the provider's firehose is reduced to security-relevant writes.
var sensitiveRegFragments = []string{
	`\currentversion\run`, // Run / RunOnce / RunServices
	`\currentversion\policies\explorer\run`,
	`\currentcontrolset\services`, // service install / ImagePath hijack
	`\controlset001\services`,
	`\winlogon`,                    // Shell, Userinit, Notify
	`image file execution options`, // debugger / SilentProcessExit hijack
	`\appinit_dlls`,
	`\currentversion\windows\load`,
	`\currentversion\explorer\shell folders`,
	`\active setup\installed components`,
	`\currentversion\app paths`,
	`\currentversion\runonce`,
	`\bootexecute`,
	`\control\lsa`,   // LSA Notification/Security/Authentication Packages (password filter / SSP / auth pkg)
	`inprocserver32`, // COM in-process server hijack (CLSID InprocServer32)
	`localserver32`,  // COM local server hijack (CLSID LocalServer32)
	`\appcertdlls`,   // AppCert DLLs (loaded into processes calling CreateProcess*)
}

func isSensitiveRegPath(path string) bool {
	if path == "" {
		return false
	}
	low := strings.ToLower(path)
	for _, f := range sensitiveRegFragments {
		if strings.Contains(low, f) {
			return true
		}
	}
	return false
}

// resolveValue reads back the current data of a value, recovering both the hive
// (the ETW relative path often omits it) and the data the provider does not
// capture. Best-effort: detection still has key+value+action without it.
//
// When the path is already hive-qualified it is read directly; otherwise the
// common hives are probed. HKLM resolves machine-wide ASEP writes regardless of
// the agent's user; HKCU only resolves writes in the agent's own user hive.
func resolveValue(path, valueName string) (string, string, bool) {
	if root, sub, ok := splitHive(path); ok {
		if d, ok2 := tryReadValue(root, sub, valueName); ok2 {
			return path, d, true
		}
		return path, "", false
	}
	sub := strings.TrimPrefix(path, `\`)
	for _, h := range []struct {
		name string
		root registry.Key
	}{
		{"HKLM", registry.LOCAL_MACHINE},
		{"HKCU", registry.CURRENT_USER},
	} {
		if d, ok := tryReadValue(h.root, sub, valueName); ok {
			return h.name + `\` + sub, d, true
		}
	}
	return path, "", false
}

// tryReadValue opens root\sub and stringifies the named value. Reports false if
// the key/value is absent or of an unsupported type.
func tryReadValue(root registry.Key, sub, valueName string) (string, bool) {
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	if s, _, err := k.GetStringValue(valueName); err == nil {
		return s, true
	}
	if v, _, err := k.GetIntegerValue(valueName); err == nil {
		return strconv.FormatUint(v, 10), true
	}
	if ss, _, err := k.GetStringsValue(valueName); err == nil {
		return strings.Join(ss, ";"), true
	}
	return "", false
}

// splitHive splits a normalized HKLM\... / HKU\<sid>\... / HKCU\... path into a
// registry root handle and the sub-key path.
func splitHive(path string) (registry.Key, string, bool) {
	if i := strings.IndexByte(path, '\\'); i > 0 {
		switch strings.ToUpper(path[:i]) {
		case "HKLM":
			return registry.LOCAL_MACHINE, path[i+1:], true
		case "HKU":
			return registry.USERS, path[i+1:], true
		case "HKCU":
			return registry.CURRENT_USER, path[i+1:], true
		}
	}
	return 0, "", false
}
