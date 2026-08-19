//go:build windows

package windows

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const (
	// imageLoadSessionName is a separate ETW session for module-load events on
	// the Kernel-Process provider with the IMAGE keyword enabled.
	imageLoadSessionName = "EDR-Agent-ImageLoad"
	// etwImageLoadID is the Kernel-Process ImageLoad event (id 5) emitted when
	// the IMAGE keyword (0x40) is enabled on the provider.
	etwImageLoadID        = 5
	keywordImage   uint64 = 0x40 // WINEVENT_KEYWORD_IMAGE
)

// ETWImageLoadCollector captures module/DLL loads via ETW for DLL side-loading
// detection. Every module's Authenticode signature is verified (cached by path),
// so SigmaHQ unsigned-DLL rules can exclude signed system DLLs. Verification runs
// on a worker goroutine (verifyCh → out), never on the ETW callback thread, since
// WinVerifyTrust does file I/O and blocking the high-frequency callback drops events.
type ETWImageLoadCollector struct {
	cancel      context.CancelFunc
	out         chan<- collector.ImageLoadEvent
	verifyCh    chan collector.ImageLoadEvent
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWImageLoadCollector() *ETWImageLoadCollector {
	return &ETWImageLoadCollector{}
}

// Start begins ETW image-load monitoring. Additive sensor: default ON, opt-out
// via EDR_AGENT_ETW_SENSORS=0 (or force-on via EDR_AGENT_ETW=1). When opted out
// — or if the session cannot be started — it is a no-op (image-load telemetry is
// additive, with no polling fallback equivalent).
func (c *ETWImageLoadCollector) Start(ctx context.Context, out chan<- collector.ImageLoadEvent) error {
	c.out = out
	if !etwSensorsEnabled() {
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	// Verify signatures off the ETW callback thread: the callback enqueues here and
	// the worker verifies + forwards. Buffered to absorb load bursts.
	c.verifyCh = make(chan collector.ImageLoadEvent, 4096)
	go c.verifyWorker(ctx)
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorETWImageLoad, err)
		return nil
	}
	slog.Info("ETWイメージロード監視を開始しました (Microsoft-Windows-Kernel-Process, IMAGE)")
	return nil
}

func (c *ETWImageLoadCollector) startETW(ctx context.Context) error {
	cons, err := c.establishETW(ctx)
	if err != nil {
		return err
	}
	goSuperviseETWSession(ctx, imageLoadSessionName, cons, c.establishETW, c.teardownETW)
	return nil
}

func (c *ETWImageLoadCollector) establishETW(ctx context.Context) (*etw.Consumer, error) {
	prov, err := etw.ParseProvider(kernelProcessGUID)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel-process provider: %w", err)
	}
	// Restrict to the IMAGE keyword so we receive module-load events (id 5)
	// without the full process/thread firehose.
	prov.MatchAnyKeyword = keywordImage
	prov.EnableLevel = 0xFF

	session := etw.NewRealTimeSession(imageLoadSessionName)
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

func (c *ETWImageLoadCollector) teardownETW() {
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// handleETWEvent converts a Kernel-Process ImageLoad ETW event into an
// ImageLoadEvent. Lightweight: signature verification is only done for
// user-writable paths to keep the trace callback from blocking on every DLL.
func (c *ETWImageLoadCollector) handleETWEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWイメージロード処理でパニックを回復しました", "panic", r)
		}
	}()

	if e.System.EventID != etwImageLoadID {
		return
	}
	img, ok := e.GetPropertyString("ImageName")
	if !ok || img == "" {
		return
	}
	// ETW reports the NT device path (\Device\HarddiskVolumeN\...). Convert to a
	// drive-letter path so WinVerifyTrust can open the file and so analysts/Sigma
	// rules see a normal C:\... path.
	img = ntPathToDOS(img)

	// ProcessName is resolved in verifyWorker from the PID below, NOT here: it is
	// the process that LOADED the module, and looking it up costs an OpenProcess.
	// It used to be set to filepath_base(img) — the loaded DLL's own base name —
	// which is not a process at all. Downstream that value is counted as a process
	// execution and aliased onto Sigma's Image field, so `kernel32.dll` and
	// `crypt32.dll` were reported as anomalous *process* runs, one alert each
	// (validation host, 2026-08-05).
	evt := collector.ImageLoadEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		ImagePath: img,
	}
	if pidStr, ok := e.GetPropertyString("ProcessID"); ok {
		if pid, err := strconv.ParseUint(pidStr, 0, 32); err == nil {
			evt.PID = uint32(pid)
		}
	}

	// Hand off to the verify worker (off the callback thread). Signature
	// verification (WinVerifyTrust = file I/O + crypto) must not run here: blocking
	// the high-frequency ETW callback drops image-load events.
	select {
	case c.verifyCh <- evt:
	default:
		// Worker saturated under a load burst — forward without a verdict rather
		// than block the callback (better to lose a signature than lose the event).
		evt.SignatureStatus = "unknown"
		select {
		case c.out <- evt:
		default:
		}
	}
}

// verifyWorker drains queued image-load events, verifies each module's
// Authenticode signature (cached by path), and forwards to the output channel.
// Running off the ETW callback thread keeps the callback fast. Every module is
// verified — system DLLs were previously reported "unknown" (verification skipped
// to bound callback cost), which broke SigmaHQ unsigned-DLL rules that exclude
// signed system DLLs via a `not Signed:'true'` filter: a system DLL seen as
// "unknown" was NOT excluded, so legit System32 modules (dbghelp/dbgcore) were
// flagged (false positive, confirmed 2026-06-26). The path→verdict cache makes
// verifying every load affordable (unique DLL paths are few; near-100% hits).
func (c *ETWImageLoadCollector) verifyWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-c.verifyCh:
			status := cachedAuthenticode(evt.ImagePath)
			evt.SignatureStatus = status
			evt.Signed = status == "valid"
			// Resolve the LOADING process here, off the ETW callback thread —
			// OpenProcess/QueryFullProcessImageName is the same class of cost as the
			// signature check above, and blocking the callback drops events. Left
			// empty when the process has already exited: an absent actor is honest,
			// a wrong one silently corrupts every consumer of process_name.
			if evt.ProcessName == "" && evt.PID != 0 {
				evt.ProcessName = filepath_base(pidToName(evt.PID))
			}
			select {
			case c.out <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *ETWImageLoadCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ntPathToDOS converts an NT device path (\Device\HarddiskVolumeN\...) to a
// drive-letter path (C:\...) by matching against each drive's device target.
// Returns the input unchanged if it is not an NT device path or no drive matches.
func ntPathToDOS(p string) string {
	if !strings.HasPrefix(strings.ToLower(p), `\device\`) {
		return p
	}
	buf := make([]uint16, 1024)
	for d := byte('A'); d <= 'Z'; d++ {
		drive := string(d) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		dev := windows.UTF16ToString(buf)
		if dev != "" && strings.HasPrefix(strings.ToLower(p), strings.ToLower(dev)+`\`) {
			return drive + p[len(dev):]
		}
	}
	return p
}

// signature verdicts cached by lower-cased image path. Image loads are very high
// frequency but unique DLL paths are few (the same system DLLs load over and
// over), so caching makes verifying every load affordable.
var (
	sigCacheMu sync.RWMutex
	sigCache   = make(map[string]string, 1024)
)

// cachedAuthenticode returns the Authenticode verdict for path, verifying with
// WinVerifyTrust on first sight and caching the result. The cache is dropped
// wholesale past a bound to cap memory (paths are stable, so churn is rare).
func cachedAuthenticode(path string) string {
	key := strings.ToLower(path)
	sigCacheMu.RLock()
	v, ok := sigCache[key]
	sigCacheMu.RUnlock()
	if ok {
		return v
	}
	status := verifyAuthenticode(path)
	sigCacheMu.Lock()
	if len(sigCache) >= 8192 {
		sigCache = make(map[string]string, 1024)
	}
	sigCache[key] = status
	sigCacheMu.Unlock()
	return status
}

// ─── Authenticode signature verification (WinVerifyTrust) ─────────

var (
	modWintrust        = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")

	// Catalog-signature APIs (also exported from wintrust.dll). System DLLs such as
	// dbghelp/dbgcore carry NO embedded Authenticode signature — they are signed via
	// the OS security catalogs (.cat), so the WINTRUST_FILE_INFO check below returns
	// TRUST_E_NOSIGNATURE for them. We then look the file's hash up in the catalog DB
	// and verify it via WINTRUST_CATALOG_INFO.
	procCryptCATAdminAcquireContext2         = modWintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHandle2 = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext          = modWintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATCatalogInfoFromContext       = modWintrust.NewProc("CryptCATCatalogInfoFromContext")

	// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
	wintrustActionGenericVerifyV2 = windows.GUID{
		Data1: 0x00AAC56B,
		Data2: 0xCD44,
		Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}

	sha256Algorithm = mustUTF16Ptr("SHA256")
)

func mustUTF16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	// Union slot: *wintrustFileInfo (dwUnionChoice=wtdChoiceFile) or
	// *wintrustCatalogInfo (wtdChoiceCatalog). Stored as a raw pointer so both
	// callers can reuse the struct.
	pUnion             uintptr
	dwStateAction      uint32
	hWVTStateData      windows.Handle
	pwszURLReference   *uint16
	dwProvFlags        uint32
	dwUIContext        uint32
	pSignatureSettings uintptr
}

// WINTRUST_CATALOG_INFO — identifies the catalog and the member (our file) to verify.
type wintrustCatalogInfo struct {
	cbStruct             uint32
	dwCatalogVersion     uint32
	pcwszCatalogFilePath *uint16
	pcwszMemberTag       *uint16
	pcwszMemberFilePath  *uint16
	hMemberFile          windows.Handle
	pbCalculatedFileHash *byte
	cbCalculatedFileHash uint32
	pcCatalogContext     uintptr
	hCatAdmin            windows.Handle
}

// CATALOG_INFO — receives the catalog file path from CryptCATCatalogInfoFromContext.
type catalogInfo struct {
	cbStruct       uint32
	wszCatalogFile [windows.MAX_PATH]uint16
}

const (
	wtdUINone            = 2
	wtdRevokeNone        = 0
	wtdChoiceFile        = 1
	wtdChoiceCatalog     = 2
	wtdStateActionIgnore = 0

	trustENoSignature = 0x800B0100 // TRUST_E_NOSIGNATURE
	certEExpired      = 0x800B0101 // CERT_E_EXPIRED
)

// verifyAuthenticode returns "valid"|"unsigned"|"expired"|"invalid"|"unknown".
// Wrapped in a recover() guard by the caller; any unexpected failure degrades
// to "unknown" rather than affecting collection.
func verifyAuthenticode(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "unknown"
	}
	fileInfo := wintrustFileInfo{
		pcwszFilePath: p,
	}
	fileInfo.cbStruct = uint32(unsafe.Sizeof(fileInfo))

	data := wintrustData{
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pUnion:              uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       wtdStateActionIgnore,
	}
	data.cbStruct = uint32(unsafe.Sizeof(data))

	ret, _, _ := procWinVerifyTrust.Call(
		0, // hwnd = INVALID_HANDLE_VALUE (no UI)
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	switch uint32(ret) {
	case 0:
		return "valid"
	case trustENoSignature:
		// No embedded signature — most System DLLs are catalog-signed. Fall back to
		// catalog verification before declaring the module unsigned (the dbghelp/
		// dbgcore FP: legit Microsoft DLLs were reported unsigned and tripped the
		// "Suspicious Unsigned DLL" rule).
		return verifyViaCatalog(path)
	case certEExpired:
		return "expired"
	default:
		return "invalid"
	}
}

// verifyViaCatalog checks whether path's hash is present in an OS security catalog
// and, if so, verifies it via WinVerifyTrust with WINTRUST_CATALOG_INFO. Returns
// "valid" for a catalog-signed file, "unsigned" only when the file is in no catalog
// (genuinely unsigned), and "unknown" on any unexpected API failure (degrade safely
// rather than emit a false "unsigned"). Caller wraps this in a recover() guard.
func verifyViaCatalog(path string) string {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "unknown"
	}
	hFile, err := windows.CreateFile(p16, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(hFile)

	var hCatAdmin windows.Handle
	// SHA-256 catalogs (all modern Windows). NULL subsystem GUID = DRIVER_ACTION_VERIFY default.
	r, _, _ := procCryptCATAdminAcquireContext2.Call(
		uintptr(unsafe.Pointer(&hCatAdmin)),
		0,
		uintptr(unsafe.Pointer(sha256Algorithm)),
		0,
		0,
	)
	if r == 0 || hCatAdmin == 0 {
		return "unknown"
	}
	defer procCryptCATAdminReleaseContext.Call(uintptr(hCatAdmin), 0)

	// Two-call idiom: first learn the hash size, then fill it.
	var cbHash uint32
	procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(hCatAdmin), uintptr(hFile), uintptr(unsafe.Pointer(&cbHash)), 0, 0)
	if cbHash == 0 {
		return "unknown"
	}
	hash := make([]byte, cbHash)
	r, _, _ = procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(hCatAdmin), uintptr(hFile),
		uintptr(unsafe.Pointer(&cbHash)), uintptr(unsafe.Pointer(&hash[0])), 0)
	if r == 0 {
		return "unknown"
	}

	hCatInfo, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(uintptr(hCatAdmin),
		uintptr(unsafe.Pointer(&hash[0])), uintptr(cbHash), 0, 0)
	if hCatInfo == 0 {
		return "unsigned" // hash in no catalog and no embedded signature = truly unsigned
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(uintptr(hCatAdmin), hCatInfo, 0)

	var ci catalogInfo
	ci.cbStruct = uint32(unsafe.Sizeof(ci))
	r, _, _ = procCryptCATCatalogInfoFromContext.Call(hCatInfo, uintptr(unsafe.Pointer(&ci)), 0)
	if r == 0 {
		return "unknown"
	}

	// Member tag = uppercase hex of the file hash (WinVerifyTrust matches it in the catalog).
	memberTag, err := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	if err != nil {
		return "unknown"
	}
	wci := wintrustCatalogInfo{
		pcwszCatalogFilePath: &ci.wszCatalogFile[0],
		pcwszMemberTag:       memberTag,
		pcwszMemberFilePath:  p16,
		hMemberFile:          hFile,
		pbCalculatedFileHash: &hash[0],
		cbCalculatedFileHash: cbHash,
		hCatAdmin:            hCatAdmin,
	}
	wci.cbStruct = uint32(unsafe.Sizeof(wci))

	data := wintrustData{
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceCatalog,
		pUnion:              uintptr(unsafe.Pointer(&wci)),
		dwStateAction:       wtdStateActionIgnore,
	}
	data.cbStruct = uint32(unsafe.Sizeof(data))

	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	switch uint32(ret) {
	case 0:
		return "valid"
	case certEExpired:
		return "expired"
	default:
		return "invalid"
	}
}
