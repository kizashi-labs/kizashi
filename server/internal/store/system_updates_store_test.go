package store

import (
	"strings"
	"testing"
)

// ─── nullableTime ─────────────────────────────────────────────────────────

func TestNullableTime(t *testing.T) {
	tests := []struct {
		name string
		in   *string
		want interface{}
	}{
		{"nil pointer", nil, nil},
		{"empty string", strPtr(""), nil},
		{"valid HH:MM", strPtr("02:00"), "02:00"},
		{"valid late hour", strPtr("23:45"), "23:45"},
		{"with seconds (passed through, validation is caller's job)", strPtr("02:00:00"), "02:00:00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nullableTime(tc.in)
			if got != tc.want {
				t.Errorf("nullableTime(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ─── validation helpers (pure logic the handler will reuse) ──────────────
//
// These mirror the validation the handler must do before calling the store.
// Keeping them here lets us unit-test the rules without spinning up Gin.

// validUpdateChannels matches the CHECK constraint on system_updates.channel
// and system_update_settings.channel.
var validUpdateChannels = map[string]bool{
	"stable": true,
	"beta":   true,
}

func isValidUpdateChannel(c string) bool {
	return validUpdateChannels[c]
}

func TestIsValidUpdateChannel(t *testing.T) {
	tests := []struct {
		channel string
		want    bool
	}{
		{"stable", true},
		{"beta", true},
		{"alpha", false},
		{"", false},
		{"STABLE", false}, // case sensitive
		{"  stable", false},
	}
	for _, tc := range tests {
		t.Run(tc.channel, func(t *testing.T) {
			if got := isValidUpdateChannel(tc.channel); got != tc.want {
				t.Errorf("isValidUpdateChannel(%q) = %v, want %v", tc.channel, got, tc.want)
			}
		})
	}
}

// validUpdateStatuses matches the CHECK constraint on system_updates.status.
var validUpdateStatuses = map[string]bool{
	"available":   true,
	"approved":    true,
	"applying":    true,
	"success":     true,
	"failed":      true,
	"rolled_back": true,
	"cancelled":   true,
}

func isValidUpdateStatus(s string) bool {
	return validUpdateStatuses[s]
}

func TestIsValidUpdateStatus(t *testing.T) {
	for _, s := range []string{"available", "approved", "applying", "success", "failed", "rolled_back", "cancelled"} {
		if !isValidUpdateStatus(s) {
			t.Errorf("isValidUpdateStatus(%q) should be true", s)
		}
	}
	for _, s := range []string{"", "pending", "Available", "successful"} {
		if isValidUpdateStatus(s) {
			t.Errorf("isValidUpdateStatus(%q) should be false", s)
		}
	}
}

// validateMaintenanceWindow enforces that start/end are either both present
// or both absent; if present, both must be HH:MM.
func validateMaintenanceWindow(start, end *string) error {
	startEmpty := start == nil || *start == ""
	endEmpty := end == nil || *end == ""
	if startEmpty != endEmpty {
		return errMaintenanceWindowPaired
	}
	if startEmpty {
		return nil // both empty: clear the window
	}
	if !isHHMM(*start) {
		return errMaintenanceWindowFormat
	}
	if !isHHMM(*end) {
		return errMaintenanceWindowFormat
	}
	return nil
}

// isHHMM checks "HH:MM" 24-hour format. No leading zeros tolerated for HH.
func isHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	hh, mm := s[0:2], s[3:5]
	for _, c := range hh + mm {
		if c < '0' || c > '9' {
			return false
		}
	}
	h := (int(hh[0])-'0')*10 + (int(hh[1]) - '0')
	m := (int(mm[0])-'0')*10 + (int(mm[1]) - '0')
	return h >= 0 && h < 24 && m >= 0 && m < 60
}

// Sentinel errors for test readability.
var (
	errMaintenanceWindowPaired = stringErr("maintenance window: start and end must both be set or both empty")
	errMaintenanceWindowFormat = stringErr("maintenance window: must be HH:MM (24h)")
)

type stringErr string

func (e stringErr) Error() string { return string(e) }

func TestIsHHMM(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"00:00", true},
		{"23:59", true},
		{"02:00", true},
		{"09:30", true},
		{"24:00", false},
		{"23:60", false},
		{"2:00", false}, // missing leading zero
		{"02:0", false}, // missing trailing zero
		{"02:000", false},
		{"", false},
		{"abc", false},
		{"02-00", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isHHMM(tc.in); got != tc.want {
				t.Errorf("isHHMM(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateMaintenanceWindow(t *testing.T) {
	cases := []struct {
		name        string
		start, end  *string
		wantErr     bool
		errContains string
	}{
		{"both nil", nil, nil, false, ""},
		{"both empty", strPtr(""), strPtr(""), false, ""},
		{"only start set", strPtr("02:00"), nil, true, "both"},
		{"only end set", nil, strPtr("04:00"), true, "both"},
		{"both valid", strPtr("02:00"), strPtr("04:00"), false, ""},
		{"start invalid", strPtr("25:00"), strPtr("04:00"), true, "HH:MM"},
		{"end invalid", strPtr("02:00"), strPtr("xx:yy"), true, "HH:MM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMaintenanceWindow(tc.start, tc.end)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateMaintenanceWindow err = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error %q should contain %q", err.Error(), tc.errContains)
			}
		})
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────

func strPtr(s string) *string { return &s }
