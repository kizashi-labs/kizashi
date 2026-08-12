//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// processStatRaw holds raw counters read from /proc for one tick.
type processStatRaw struct {
	pid      int
	name     string
	cpuTotal uint64 // utime + stime in jiffies
	memKB    uint64 // VmRSS in kB
}

// readProcessStatsRaw returns raw CPU and memory stats for all running processes
// plus the current total CPU jiffies (for delta calculation).
func readProcessStatsRaw() ([]processStatRaw, uint64, error) {
	totalCPU, err := readTotalCPUJiffies()
	if err != nil {
		return nil, 0, err
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, fmt.Errorf("read /proc: %w", err)
	}

	var stats []processStatRaw
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue // process may have exited
		}
		utime, stime, name, err := parseProcStat(statData)
		if err != nil {
			continue
		}

		memKB := readVmRSS(pid)
		stats = append(stats, processStatRaw{
			pid:      pid,
			name:     name,
			cpuTotal: utime + stime,
			memKB:    memKB,
		})
	}
	return stats, totalCPU, nil
}

// parseProcStat extracts utime, stime, and comm from /proc/{pid}/stat content.
func parseProcStat(data []byte) (utime, stime uint64, name string, err error) {
	s := string(data)
	start := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if start < 0 || end < 0 || end <= start {
		return 0, 0, "", fmt.Errorf("invalid stat format")
	}
	name = s[start+1 : end]
	rest := s[end+2:] // skip ') '
	fields := strings.Fields(rest)
	// Fields after state: (field 3 onward in spec)
	// Index 11 in rest = utime (spec field 14), index 12 = stime (spec field 15)
	if len(fields) < 13 {
		return 0, 0, name, fmt.Errorf("too few fields")
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	return utime, stime, name, nil
}

// readVmRSS reads resident memory size (kB) from /proc/{pid}/status.
func readVmRSS(pid int) uint64 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb
			}
		}
	}
	return 0
}

// readTotalCPUJiffies reads aggregate CPU jiffies from /proc/stat.
func readTotalCPUJiffies() (uint64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		var total uint64
		for i := 1; i < len(fields); i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			total += v
		}
		return total, nil
	}
	return 0, fmt.Errorf("/proc/stat: cpu line not found")
}
