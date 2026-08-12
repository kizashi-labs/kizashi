//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Integrity-level RIDs (the last sub-authority of a mandatory-label SID,
// winnt.h SECURITY_MANDATORY_*_RID). Sysmon reports the label string, which is
// what SigmaHQ UAC-bypass / privilege-escalation rules match on IntegrityLevel.
const (
	integrityUntrusted  = 0x0000
	integrityLow        = 0x1000
	integrityMedium     = 0x2000
	integrityMediumPlus = 0x2100
	integrityHigh       = 0x3000
	integritySystem     = 0x4000
	integrityProtected  = 0x5000
)

// tokenIntegrityLevel returns the Sysmon-style integrity label for a process
// token (Untrusted|Low|Medium|High|System|…), or "" if it cannot be read.
// Best-effort: any API failure yields "".
func tokenIntegrityLevel(token windows.Token) string {
	// Query the required buffer size for the TokenIntegrityLevel information class.
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return ""
	}
	// buf holds a TOKEN_MANDATORY_LABEL whose Label.Sid is of the form
	// S-1-16-<RID>, where the last component is the integrity RID.
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := tml.Label.Sid
	if sid == nil {
		return ""
	}
	s := sid.String()
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return ""
	}
	rid, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return ""
	}
	switch {
	case rid == integrityUntrusted:
		return "Untrusted"
	case rid == integrityLow:
		return "Low"
	case rid == integrityMedium:
		return "Medium"
	case rid == integrityMediumPlus:
		return "Medium Plus"
	case rid == integrityHigh:
		return "High"
	case rid == integritySystem:
		return "System"
	case rid >= integrityProtected:
		return "Protected"
	case rid > integrityHigh:
		return "System"
	case rid > integrityMedium:
		return "High"
	default:
		return "Medium"
	}
}

// tokenLogonID returns the process token's logon session ID as the Sysmon hex
// LUID string (e.g. "0x3e7" for the SYSTEM session), or "" if it cannot be read.
// The AuthenticationId LUID sits at offset 8 of TOKEN_STATISTICS (after the
// 8-byte TokenId LUID).
func tokenLogonID(token windows.Token) string {
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenStatistics, nil, 0, &size)
	if size < 16 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenStatistics, &buf[0], size, &size); err != nil {
		return ""
	}
	low := binary.LittleEndian.Uint32(buf[8:12])
	high := binary.LittleEndian.Uint32(buf[12:16])
	luid := uint64(high)<<32 | uint64(low)
	return fmt.Sprintf("0x%x", luid)
}
