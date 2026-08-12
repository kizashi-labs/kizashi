//go:build darwin

package collector

import (
	"bufio"
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// processStatRaw holds raw counters for one tick.
type processStatRaw struct {
	pid      int
	name     string
	cpuTotal uint64 // cumulative CPU time in centiseconds
	memKB    uint64 // resident set size in kB
}

// readProcessStatsRaw returns raw CPU and memory stats for all running
// processes on macOS, plus a system-wide CPU counter used for delta
// calculation. It shells out to `ps` (no CGo required), mirroring the
// polling approach used by the other Darwin collectors.
//
// cpuTotal is the per-process cumulative CPU time reported by `ps` (the
// TIME column) expressed in centiseconds. The returned total is
// NumCPU * wall-clock-centiseconds, i.e. the total CPU time available
// across all cores. Both values are in the same unit, so the ratio
// deltaCPU/deltaTotal yields the fraction of total capacity a process
// consumed between ticks — matching the /proc-based Linux semantics.
func readProcessStatsRaw() ([]processStatRaw, uint64, error) {
	// ps -axo pid,rss,time,comm
	//   pid  : process id
	//   rss  : resident set size in kB
	//   time : cumulative CPU time [[dd-]hh:]mm:ss[.ff]
	//   comm : accounting command name (single token, kept last)
	cmd := exec.Command("ps", "-axo", "pid=,rss=,time=,comm=")
	out, err := cmd.Output()
	if err != nil {
		return nil, 0, err
	}

	var stats []processStatRaw
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		memKB, _ := strconv.ParseUint(fields[1], 10, 64)
		cpuTotal := parsePSTime(fields[2])
		// `ps -o comm` prints the full executable path on macOS; reduce it
		// to a short process name to match the Linux collector's output.
		name := filepath.Base(strings.Join(fields[3:], " "))

		stats = append(stats, processStatRaw{
			pid:      pid,
			name:     name,
			cpuTotal: cpuTotal,
			memKB:    memKB,
		})
	}

	// System-wide CPU capacity: NumCPU cores each accruing 100 centiseconds
	// of CPU time per elapsed second. Derived from a monotonic clock so the
	// counter never decreases across ticks — a wall-clock step backwards
	// (e.g. NTP correction after boot) would otherwise underflow the
	// collector's uint64 deltaTotal subtraction and zero out every CPU%.
	totalCentis := uint64(runtime.NumCPU()) * uint64(monotonicCentis())
	return stats, totalCentis, nil
}

// parsePSTime converts a macOS `ps` TIME field into centiseconds.
// Accepted formats: "mm:ss", "mm:ss.ff", "hh:mm:ss", and "dd-hh:mm:ss".
func parsePSTime(s string) uint64 {
	var days uint64
	if dash := strings.IndexByte(s, '-'); dash >= 0 {
		days, _ = strconv.ParseUint(s[:dash], 10, 64)
		s = s[dash+1:]
	}

	parts := strings.Split(s, ":")
	// Seconds (last part) may carry a fractional component.
	secStr := parts[len(parts)-1]
	var whole, centis uint64
	if dot := strings.IndexByte(secStr, '.'); dot >= 0 {
		whole, _ = strconv.ParseUint(secStr[:dot], 10, 64)
		frac := secStr[dot+1:]
		// Normalise the fraction to hundredths of a second.
		for len(frac) < 2 {
			frac += "0"
		}
		centis, _ = strconv.ParseUint(frac[:2], 10, 64)
	} else {
		whole, _ = strconv.ParseUint(secStr, 10, 64)
	}

	var minutes, hours uint64
	if len(parts) >= 2 {
		minutes, _ = strconv.ParseUint(parts[len(parts)-2], 10, 64)
	}
	if len(parts) >= 3 {
		hours, _ = strconv.ParseUint(parts[len(parts)-3], 10, 64)
	}

	totalSecs := ((days*24+hours)*60+minutes)*60 + whole
	return totalSecs*100 + centis
}

// procStatsEpoch anchors the monotonic elapsed counter. Go's time.Time
// carries a monotonic reading, so time.Since is immune to wall-clock
// adjustments and only ever increases.
var procStatsEpoch = time.Now()

// monotonicCentis returns centiseconds elapsed since procStatsEpoch using the
// monotonic clock. Only differences between successive readings are used, so
// the absolute anchor is irrelevant; the guarantee that matters is that the
// value never decreases.
func monotonicCentis() int64 {
	return int64(time.Since(procStatsEpoch) / (10 * time.Millisecond))
}
