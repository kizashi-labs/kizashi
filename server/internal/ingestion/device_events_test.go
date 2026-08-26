package ingestion

import (
	"testing"
	"time"
)

// TestParseDeviceEvent covers the field mapping between the agent's wire payload
// and the device_events columns. The names differ ("name"→device_name,
// "type"→device_type), so a silent mismatch here would write rows with NULL
// device_type and make the XDR endpoint dimension useless without failing
// anything.
func TestParseDeviceEvent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"action":"connected","device_id":"1-1.2","name":"SanDisk Cruzer",` +
		`"vendor_id":"0781","product_id":"5567","type":"storage"}`)

	row, ok := parseDeviceEvent(raw, now)
	if !ok {
		t.Fatal("well-formed USB storage payload was rejected")
	}
	for _, c := range []struct{ field, got, want string }{
		{"action", row.action, "connected"},
		{"device_id", row.deviceID, "1-1.2"},
		{"device_name", row.deviceName, "SanDisk Cruzer"},
		{"device_type", row.deviceType, "storage"},
		{"vendor_id", row.vendorID, "0781"},
		{"product_id", row.productID, "5567"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
	if !row.evtTime.Equal(now) {
		t.Errorf("evtTime = %v, want the event's own timestamp %v", row.evtTime, now)
	}
	if string(row.raw) != string(raw) {
		t.Error("raw payload must be preserved for the raw_data column")
	}
}

// TestParseDeviceEventRejectsUninsertable drops payloads that cannot satisfy the
// table's constraints. These must be filtered in Go rather than left to the DB:
// the action CHECK would reject the row at insert time, and letting that reach
// the database turns one malformed agent payload into a logged error on every
// device event that host reports.
func TestParseDeviceEventRejectsUninsertable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		raw  string
	}{
		{"unknown action violates the CHECK constraint",
			`{"action":"mounted","device_id":"1-1.2","type":"storage"}`},
		{"empty action",
			`{"action":"","device_id":"1-1.2"}`},
		{"missing device_id violates NOT NULL",
			`{"action":"connected","type":"storage"}`},
		{"malformed JSON", `{"action":`},
	}
	for _, c := range cases {
		if _, ok := parseDeviceEvent([]byte(c.raw), now); ok {
			t.Errorf("%s: payload was accepted, want rejected", c.name)
		}
	}
}

// TestParseDeviceEventOptionalFields verifies a sparse payload still inserts:
// only action and device_id are required, and the optional attributes become
// NULL rather than blocking the row.
func TestParseDeviceEventOptionalFields(t *testing.T) {
	row, ok := parseDeviceEvent([]byte(`{"action":"disconnected","device_id":"1-1.3"}`),
		time.Unix(1_700_000_000, 0))
	if !ok {
		t.Fatal("payload with only the required fields was rejected")
	}
	if row.deviceName != "" || row.deviceType != "" || row.vendorID != "" || row.productID != "" {
		t.Errorf("absent optional fields should stay empty, got %+v", row)
	}
	if nullIfEmpty(row.deviceName) != nil {
		t.Error("nullIfEmpty must map an absent attribute to NULL, not \"\"")
	}
}

// TestNullIfEmpty locks the NULL mapping used for every optional device column.
func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Error(`nullIfEmpty("") must be nil so pgx writes NULL`)
	}
	got := nullIfEmpty("storage")
	if got == nil || *got != "storage" {
		t.Errorf("nullIfEmpty(%q) = %v, want a pointer to the value", "storage", got)
	}
}
