//go:build windows

package windows

import (
	"strings"
	"sync"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	"golang.org/x/sys/windows"
)

// PE VERSIONINFO extraction. A large class of SigmaHQ process_creation rules
// identify a binary by its embedded version metadata (OriginalFilename,
// FileDescription, ProductName, CompanyName) rather than its on-disk path —
// because the path is trivially renamed but the PE version resource is not
// (e.g. "Renamed CreateDump Utility Execution", "Renamed Office Binary
// Execution"). Measured 2026-07-02, OriginalFileName alone was the single
// largest cause of enabled-but-inert Sigma rules (74 rules). This reader lifts
// those four strings onto ProcessEvent so those rules can fire.
//
// All reads are best-effort: a file with no version resource, or a short-lived
// process whose image is already gone, simply yields empty strings and the
// event ships without them.

var (
	modVersion                  = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

// versionInfo holds the four PE version strings extracted from an image.
type versionInfo struct {
	originalFileName string
	fileDescription  string
	productName      string
	companyName      string
}

// Version info is stable per image path, and the same executables spawn
// repeatedly (services, LOLBins, shells). Cache verdicts and drop the map
// wholesale past a bound to cap memory — mirrors the signature cache.
var (
	verInfoMu    sync.RWMutex
	verInfoCache = make(map[string]versionInfo, 1024)
)

// enrichVersionInfo fills the PE VERSIONINFO fields on evt from its ImagePath.
// Best-effort and idempotent: does nothing when ImagePath is empty or the image
// carries no readable version resource.
func enrichVersionInfo(evt *collector.ProcessEvent) {
	if evt.ImagePath == "" {
		return
	}
	vi := cachedVersionInfo(evt.ImagePath)
	evt.OriginalFileName = vi.originalFileName
	evt.FileDescription = vi.fileDescription
	evt.ProductName = vi.productName
	evt.CompanyName = vi.companyName
}

// cachedVersionInfo returns the PE version strings for path, reading the version
// resource on first sight and caching the (possibly empty) result.
func cachedVersionInfo(path string) versionInfo {
	key := strings.ToLower(path)
	verInfoMu.RLock()
	v, ok := verInfoCache[key]
	verInfoMu.RUnlock()
	if ok {
		return v
	}
	v = readVersionInfo(path)
	verInfoMu.Lock()
	if len(verInfoCache) >= 8192 {
		verInfoCache = make(map[string]versionInfo, 1024)
	}
	verInfoCache[key] = v
	verInfoMu.Unlock()
	return v
}

// readVersionInfo reads the VS_VERSIONINFO resource of the PE at path and
// returns its OriginalFilename/FileDescription/ProductName/CompanyName strings.
// Any failure (no resource, unreadable file) returns a zero versionInfo.
func readVersionInfo(path string) versionInfo {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return versionInfo{}
	}

	var handle uint32
	size, _, _ := procGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(p16)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 {
		return versionInfo{}
	}

	buf := make([]byte, size)
	ok, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(p16)),
		0,
		size,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if ok == 0 {
		return versionInfo{}
	}

	// The version strings live under \StringFileInfo\<lang><codepage>\<key>.
	// The <lang><codepage> is an 8-hex-digit table given by \VarFileInfo\Translation
	// (an array of {LangID uint16, CodePage uint16}). Prefer the file's own
	// translations, then fall back to the ubiquitous US-English code pages so we
	// still read binaries that ship a StringFileInfo block without a Translation.
	langs := translations(buf)
	langs = append(langs,
		"040904B0", // US English, Unicode
		"040904E4", // US English, Windows Multilingual
		"000004B0", // language-neutral, Unicode
		"04090000", // US English, 7-bit ASCII
	)

	var vi versionInfo
	for _, lang := range langs {
		if vi.originalFileName == "" {
			vi.originalFileName = queryString(buf, lang, "OriginalFilename")
		}
		if vi.fileDescription == "" {
			vi.fileDescription = queryString(buf, lang, "FileDescription")
		}
		if vi.productName == "" {
			vi.productName = queryString(buf, lang, "ProductName")
		}
		if vi.companyName == "" {
			vi.companyName = queryString(buf, lang, "CompanyName")
		}
		if vi.originalFileName != "" && vi.fileDescription != "" &&
			vi.productName != "" && vi.companyName != "" {
			break
		}
	}
	return vi
}

// translations returns the \VarFileInfo\Translation table as "<lang><cp>" hex
// strings (e.g. "040904B0"), in the order the file lists them.
func translations(buf []byte) []string {
	sub, err := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if err != nil {
		return nil
	}
	var ptr unsafe.Pointer
	var length uint32
	ok, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(sub)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ok == 0 || length < 4 || ptr == nil {
		return nil
	}
	// length is in bytes; each entry is two uint16 (lang, codepage). Clamp the
	// count before slicing: a real PE lists one or a few translations, but the
	// agent reads version resources from attacker-controlled binaries (renamed
	// malware), and a crafted/corrupt resource could report a huge length. Without
	// a bound the slice below would read far past the resource — and a fixed-size
	// array conversion would panic, which the recover in handleKernelProcessEvent
	// turns into a DROPPED process event (an evasion vector). unsafe.Slice plus the
	// clamp keeps this bounded and panic-free.
	count := int(length) / 4
	if count > 64 {
		count = 64
	}
	out := make([]string, 0, count)
	entry := unsafe.Slice((*uint16)(ptr), count*2)
	const hex = "0123456789ABCDEF"
	for i := 0; i < count; i++ {
		lang := entry[i*2]
		cp := entry[i*2+1]
		b := []byte{
			hex[(lang>>12)&0xF], hex[(lang>>8)&0xF], hex[(lang>>4)&0xF], hex[lang&0xF],
			hex[(cp>>12)&0xF], hex[(cp>>8)&0xF], hex[(cp>>4)&0xF], hex[cp&0xF],
		}
		out = append(out, string(b))
	}
	return out
}

// queryString reads a single \StringFileInfo\<lang>\<key> value from the version
// block, returning "" when absent.
func queryString(buf []byte, lang, key string) string {
	sub, err := windows.UTF16PtrFromString(`\StringFileInfo\` + lang + `\` + key)
	if err != nil {
		return ""
	}
	var ptr unsafe.Pointer
	var length uint32
	ok, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(sub)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ok == 0 || length == 0 || ptr == nil {
		return ""
	}
	// length is the character count including the trailing NUL; the buffer is
	// NUL-terminated, so UTF16PtrToString reads exactly the value.
	return strings.TrimRight(windows.UTF16PtrToString((*uint16)(ptr)), "\x00 ")
}
