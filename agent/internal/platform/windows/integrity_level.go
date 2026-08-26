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
// token (Untrusted|Low|Medium|High|System|…), or "unknown" if the token could
// be opened but the label could not be read.
//
// **"" ではなく "unknown" を返します。**
//
// 空文字は、この経路では既に別の意味を持っています ——
// `process_etw.go` の `if evt.IntegrityLevel == ""` は「まだ埋めていない、
// 埋めよう」の合図です。同じ空文字で「調べたが分からなかった」も
// 表すと、**2つの状態が1つの値に潰れます。**
//
// 分けた結果、欄の意味はこうなります:
//
//	""         トークンを開けなかった（調べるところまで行けていない）
//	"unknown"  開けたが、ラベルを読めなかった
//	"High" 等  読めた
//
// 検知への影響はありません。`IntegrityLevel: High` を見る規則は
// "" にも "unknown" にも一致しません。**変わるのは、運用者が
// 「調べていない」と「分からなかった」を見分けられることです。**
// imageload_etw.go の署名検証が既にこの形をしていて、そちらに揃えました。
func tokenIntegrityLevel(token windows.Token) string {
	// Query the required buffer size for the TokenIntegrityLevel information class.
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return integrityUnknown
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return integrityUnknown
	}
	// buf holds a TOKEN_MANDATORY_LABEL whose Label.Sid is of the form
	// S-1-16-<RID>, where the last component is the integrity RID.
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := tml.Label.Sid
	if sid == nil {
		return integrityUnknown
	}
	s := sid.String()
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return integrityUnknown
	}
	rid, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return integrityUnknown
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
		return integrityUnknown
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenStatistics, &buf[0], size, &size); err != nil {
		return integrityUnknown
	}
	low := binary.LittleEndian.Uint32(buf[8:12])
	high := binary.LittleEndian.Uint32(buf[12:16])
	luid := uint64(high)<<32 | uint64(low)
	return fmt.Sprintf("0x%x", luid)
}

// integrityUnknown は「調べたが分からなかった」です。
//
// 空文字と分けてあります —— 空文字は「まだ調べていない」で、
// process_etw.go の埋め込み処理がその合図として使っています。
const integrityUnknown = "unknown"
