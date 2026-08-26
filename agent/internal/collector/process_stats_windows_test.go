//go:build windows

package collector

import (
	"testing"

	"golang.org/x/sys/windows"
)

// ft builds a FILETIME from a count of 100-ns units (its native resolution).
func ft(units uint64) windows.Filetime {
	return windows.Filetime{
		LowDateTime:  uint32(units & 0xffffffff),
		HighDateTime: uint32(units >> 32),
	}
}

func TestFiletimeSumCentis(t *testing.T) {
	const oneSecond = uint64(1e7) // 1s = 10,000,000 units of 100 ns

	cases := []struct {
		name         string
		kernel, user uint64
		want         uint64 // centiseconds
	}{
		{"zero", 0, 0, 0},
		{"1s kernel", oneSecond, 0, 100},
		{"1s kernel + 0.5s user", oneSecond, oneSecond / 2, 150},
		{"crosses 32-bit boundary", oneSecond * 500, 0, 50000}, // 500s > 2^32 units
	}
	for _, c := range cases {
		if got := filetimeSumCentis(ft(c.kernel), ft(c.user)); got != c.want {
			t.Errorf("%s: filetimeSumCentis = %d, want %d", c.name, got, c.want)
		}
	}
}
