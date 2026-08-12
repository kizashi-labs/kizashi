//go:build linux && ebpf && prevention

package linux

// ノイズフィルタのカウンタのうち、prevention ビルドでしか存在しないもの。
//
// 以前は process_noise.go (//go:build linux) に置かれていたが、加算する側は
// credaccess_runner.go / hostintegrity_runner.go で、いずれも
// linux && ebpf && prevention。既定ビルドでは書く側も読む側も存在しないため
// staticcheck が U1000 (未使用) として報告していた。宣言を利用側と同じ
// ビルドタグに揃える。

import "sync/atomic"

// credNoiseFiltered counts credential-access (ptrace) events dropped at the
// source because the tracer is a known-benign /proc reader (see isBenignCredTracer).
var credNoiseFiltered atomic.Uint64

// hostIntegrityNoiseFiltered counts host-integrity (capset) events dropped at the
// source because the caller is a known-benign capability manipulator (see
// isBenignCapsetProc).
var hostIntegrityNoiseFiltered atomic.Uint64

// preventionNoiseFiltered は prevention 系フィルタの累計を返す。
func preventionNoiseFiltered() (cred, hostIntegrity uint64) {
	return credNoiseFiltered.Load(), hostIntegrityNoiseFiltered.Load()
}
