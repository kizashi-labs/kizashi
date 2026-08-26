package scheduler

import (
	"testing"
	"time"
)

func TestNewIOCExpirySweeper_IntervalDefault(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero defaults to 1h", 0, time.Hour},
		{"negative defaults to 1h", -5 * time.Minute, time.Hour},
		{"positive kept", 30 * time.Minute, 30 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewIOCExpirySweeper(nil, tc.in)
			if s.interval != tc.want {
				t.Errorf("interval = %v, want %v", s.interval, tc.want)
			}
		})
	}
}
