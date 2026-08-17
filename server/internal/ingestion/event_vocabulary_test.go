package ingestion

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The event pipeline has three vocabularies that must line up, and nothing
// checked that they did. Each mismatch fails silently, in a way that looks like
// the absence of activity rather than the absence of a working query.
//
//	1. the event types ingestion promotes  ↔  events_event_type_check
//	2. the event types SQL selects on      ↔  events_event_type_check
//	3. the raw_data keys ingestion writes  ↔  the raw_data keys SQL reads
//
// Measured before this change:
//
//	(1)  6 of 21 promoted types rejected at INSERT with 23514 —
//	     tls_handshake, ps_module, pipe_created, eventlog_cleared,
//	     service_installed, device_event. Every such event ever sent was
//	     dropped at the door. Migration 381 widens the constraint.
//	(2)  3 event_type literals that no row can ever hold — container_event,
//	     container_process and module_load. Those queries returned zero rows by
//	     construction. All three are fixed: the module-load type is image_load,
//	     and the container queries match ordinary process events, which is
//	     where a container's processes actually arrive.
//	(3)  103 read sites naming a raw_data key ingestion never writes, across
//	     28 keys and 10 files. 62 were the wrong name for a datum that is
//	     collected and are fixed; the rest are listed in
//	     knownDeadRawDataKeys with what each cannot see.
//
// The producer vocabularies below are derived at runtime — the event types from
// promoteEventType, the raw_data keys by running normalizeEventData over a
// maximally-populated proto for each type — so they cannot drift from the code
// they describe the way a hand-written list would.

// ─── the producer vocabularies, derived ──────────────────────────────────────

// fillMessage populates every scalar, enum, repeated and nested field of a
// message, so normalizeEventData emits every key it is capable of emitting.
func fillMessage(m protoreflect.Message) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.ContainingOneof() != nil && !f.HasOptionalKeyword() {
			continue // oneof members are set explicitly by the caller
		}
		switch {
		case f.IsList():
			l := m.Mutable(f).List()
			switch f.Kind() {
			case protoreflect.StringKind:
				l.Append(protoreflect.ValueOfString("x"))
			case protoreflect.MessageKind:
				e := l.NewElement()
				fillMessage(e.Message())
				l.Append(e)
			}
		case f.IsMap():
			mp := m.Mutable(f).Map()
			if f.MapKey().Kind() == protoreflect.StringKind && f.MapValue().Kind() == protoreflect.StringKind {
				mp.Set(protoreflect.ValueOfString("k").MapKey(), protoreflect.ValueOfString("v"))
			}
		default:
			switch f.Kind() {
			case protoreflect.StringKind:
				m.Set(f, protoreflect.ValueOfString("x"))
			case protoreflect.BoolKind:
				m.Set(f, protoreflect.ValueOfBool(true))
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
				m.Set(f, protoreflect.ValueOfInt32(1))
			case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
				m.Set(f, protoreflect.ValueOfInt64(1))
			case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
				m.Set(f, protoreflect.ValueOfUint32(1))
			case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				m.Set(f, protoreflect.ValueOfUint64(1))
			case protoreflect.FloatKind:
				m.Set(f, protoreflect.ValueOfFloat32(1))
			case protoreflect.DoubleKind:
				m.Set(f, protoreflect.ValueOfFloat64(1))
			case protoreflect.EnumKind:
				if vals := f.Enum().Values(); vals.Len() > 1 {
					m.Set(f, protoreflect.ValueOfEnum(vals.Get(1).Number()))
				}
			case protoreflect.MessageKind:
				fillMessage(m.Mutable(f).Message())
			}
		}
	}
}

// payloadCases enumerates the Event oneof. A new payload added to the proto
// without a line here is caught by TestEveryEventPayloadIsProbed below.
var payloadCases = []struct {
	evType string
	typ    v1.EventType
	new    func() proto.Message
	set    func(*v1.Event, proto.Message)
}{
	{"process", v1.EventType_EVENT_TYPE_PROCESS, func() proto.Message { return &v1.ProcessEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Process{Process: m.(*v1.ProcessEvent)} }},
	{"file", v1.EventType_EVENT_TYPE_FILE, func() proto.Message { return &v1.FileEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_File{File: m.(*v1.FileEvent)} }},
	{"network", v1.EventType_EVENT_TYPE_NETWORK, func() proto.Message { return &v1.NetworkEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Network{Network: m.(*v1.NetworkEvent)} }},
	{"dns", v1.EventType_EVENT_TYPE_DNS, func() proto.Message { return &v1.DnsEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Dns{Dns: m.(*v1.DnsEvent)} }},
	{"registry", v1.EventType_EVENT_TYPE_REGISTRY, func() proto.Message { return &v1.RegistryEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Registry{Registry: m.(*v1.RegistryEvent)} }},
	{"auth", v1.EventType_EVENT_TYPE_AUTH, func() proto.Message { return &v1.AuthEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Auth{Auth: m.(*v1.AuthEvent)} }},
	{"image_load", v1.EventType_EVENT_TYPE_IMAGE_LOAD, func() proto.Message { return &v1.ImageLoadEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_ImageLoad{ImageLoad: m.(*v1.ImageLoadEvent)} }},
	{"script", v1.EventType_EVENT_TYPE_SCRIPT, func() proto.Message { return &v1.ScriptContentEvent{} },
		func(e *v1.Event, m proto.Message) { e.Payload = &v1.Event_Script{Script: m.(*v1.ScriptContentEvent)} }},
}

// producedKeys maps event type -> the raw_data keys normalizeEventData can emit
// for it, obtained by actually running it.
func producedKeys(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, tc := range payloadCases {
		p := tc.new()
		fillMessage(p.ProtoReflect())
		evt := &v1.Event{Type: tc.typ}
		tc.set(evt, p)

		var m map[string]interface{}
		if err := json.Unmarshal(normalizeEventData(evt), &m); err != nil {
			t.Fatalf("%s: normalizeEventData produced invalid JSON: %v", tc.evType, err)
		}
		keys := map[string]bool{}
		for k := range m {
			keys[k] = true
		}
		if len(keys) == 0 {
			t.Fatalf("%s: no keys produced — the probe is not populating the payload", tc.evType)
		}
		out[tc.evType] = keys
	}
	return out
}

// The probe must cover every payload in the oneof, or a new event type would be
// silently exempt from the whole contract.
func TestEveryEventPayloadIsProbed(t *testing.T) {
	fields := (&v1.Event{}).ProtoReflect().Descriptor().Oneofs().ByName("payload")
	if fields == nil {
		t.Fatal("Event has no payload oneof")
	}
	probed := map[string]bool{}
	for _, tc := range payloadCases {
		probed[tc.evType] = true
	}
	// The oneof field name and our event-type label differ only for image_load
	// (proto "image_load") and script (proto "script"); both already match.
	for i := 0; i < fields.Fields().Len(); i++ {
		name := string(fields.Fields().Get(i).Name())
		if name == "dns" {
			name = "dns"
		}
		if !probed[name] {
			t.Errorf("Event.payload に %q が増えていますが、語彙プローブが未対応です。"+
				"payloadCases に追加してください — 追加しないとその型だけ"+
				"契約の対象外になります", name)
		}
	}
}

// ─── (1) promoted event types ↔ the schema ───────────────────────────────────

// promotedEventTypes returns every value promoteEventType can produce, derived
// by exercising it rather than by restating the switch.
func promotedEventTypes() []string {
	seen := map[string]bool{}
	for _, tc := range payloadCases {
		if v := promoteEventType(&v1.Event{Type: tc.typ}); v != "" {
			seen[v] = true
		}
	}
	// The log-style findings are promoted from an "<type>:" id prefix.
	for _, prefix := range []string{
		"fim_change", "process_stats", "process_block", "memory",
		"credential_access", "host_integrity", "create_remote_thread",
		"tls_handshake", "ps_module", "pipe_created", "wmi_activity",
		"eventlog_cleared", "service_installed", "device_event",
	} {
		if v := promoteEventType(&v1.Event{Id: prefix + ":x:{}"}); v != "" {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every event type ingestion promotes must be one the events table accepts.
// Six were not, and each was rejected at INSERT with 23514 and lost — a
// collector running on every endpoint, feeding a table that refused the row.
func TestEveryPromotedEventTypeIsAccepted(t *testing.T) {
	pool := vocabPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname,os_type,status,last_seen)
		 VALUES ('event-vocab-fixture','linux','online',NOW()) RETURNING id`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM events WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	for _, evType := range promotedEventTypes() {
		if _, err := pool.Exec(ctx,
			`INSERT INTO events (time, agent_id, event_type, raw_data)
			 VALUES (NOW(), $1::uuid, $2, '{}'::jsonb)`, agentID, evType); err != nil {
			t.Errorf("ingestion が生成する event_type %q が events に挿入できません: %v\n"+
				"  この型のイベントは INSERT で拒否され、すべて失われます。"+
				"  events_event_type_check を広げる migration が必要です "+
				"(370 / 381 と同じ形)", evType, err)
		}
	}
}

// ─── (2) selected event types ↔ the schema ───────────────────────────────────

// knownImpossibleEventTypes are event_type literals that SQL selects on but no
// row can ever hold. Each entry records what the query is therefore unable to
// find. The list only shrinks: a new impossible type fails the test, and an
// entry that has become possible must be deleted.
var knownImpossibleEventTypes = map[string]string{}

// Every event_type a query selects on must be one a row can actually hold.
func TestEverySelectedEventTypeCanExist(t *testing.T) {
	pool := vocabPool(t)

	allowed := map[string]bool{}
	var def string
	if err := pool.QueryRow(context.Background(), `
		SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
		 WHERE c.conname='events_event_type_check' AND c.conrelid='events'::regclass`).Scan(&def); err != nil {
		t.Fatalf("read constraint: %v", err)
	}
	for _, m := range constraintLiteralRe.FindAllStringSubmatch(def, -1) {
		allowed[m[1]] = true
	}
	if len(allowed) < 10 {
		t.Fatalf("制約から %d 個しか読めませんでした — 抽出が壊れています", len(allowed))
	}

	selected := selectedEventTypes(t)
	if len(selected) < 5 {
		t.Fatalf("event_type リテラルが %d 個しか見つかりませんでした — 抽出が壊れています", len(selected))
	}

	for evType, files := range selected {
		if allowed[evType] {
			if _, stale := knownImpossibleEventTypes[evType]; stale {
				t.Errorf("knownImpossibleEventTypes が %q を挙げていますが、"+
					"この型は存在できるようになりました。行を削除してください", evType)
			}
			continue
		}
		if _, known := knownImpossibleEventTypes[evType]; known {
			continue
		}
		sort.Strings(files)
		t.Errorf("event_type %q を選択しているクエリがありますが、"+
			"events_event_type_check がこの値を許可していないため、"+
			"一致する行は永久に存在しません: %s", evType, strings.Join(files, ", "))
	}
	// Stale entries for types nothing selects on any more.
	for evType := range knownImpossibleEventTypes {
		if _, ok := selected[evType]; !ok {
			t.Errorf("knownImpossibleEventTypes の %q はどのクエリからも"+
				"参照されなくなりました。行を削除してください", evType)
		}
	}
}

func vocabPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
