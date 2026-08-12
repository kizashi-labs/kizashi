//go:build !linux && !windows

package collector

// ScanSuspiciousMemory has no implementation on platforms without a memory
// region enumerator yet (e.g. macOS — mach_vm_region is a later phase). Returns
// nil so the shared scanner plumbing still compiles everywhere.
func ScanSuspiciousMemory() []MemoryFinding { return nil }

// ScanSuspiciousMemoryWithYARA has no implementation on unsupported platforms.
func ScanSuspiciousMemoryWithYARA(_ func([]byte) []string) []MemoryFinding { return nil }

// ScanSuspiciousMemoryWithYARAStats has nothing to measure on unsupported
// platforms; it returns zeroed stats so the shared instrumentation compiles
// everywhere (#511).
func ScanSuspiciousMemoryWithYARAStats(_ func([]byte) []string) ([]MemoryFinding, MemoryScanStats) {
	return nil, MemoryScanStats{}
}
