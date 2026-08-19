//go:build darwin

package hostmetrics

import (
	"context"
	"os/exec"
	"time"
)

// macOS のメモリ。**CPU はまだです** —— 下に理由を書きます。
//
// 累積 CPU カウンタは `host_statistics(HOST_CPU_LOAD_INFO)` にありますが、
// これは mach で、cgo 無しには呼べません。`top -l 1` は「起動からの平均」を
// 出すので使えず、`top -l 2 -s 1` なら実測になりますが、ハートビートの
// たびに1秒以上ブロックする外部プロセスになります。
//
// **間違った CPU 使用率を出すより、出さない方がましです。** `ok=false` の
// あいだ、サーバは `cpu_usage` を NULL のままにします —— 「測っていない」が
// 「0%」に化けないことが、このパッケージの存在理由です。
// （macOS の CPU は判断待ちの一覧に残してあります。）

// readCPUStat is not implemented on macOS. See the package comment above.
func readCPUStat() (idle, total uint64, ok bool) {
	return 0, 0, false
}

// vmStatFn / memSizeFn は差し替え可能です。**この端末では macOS の
// コマンドを走らせられません。** 解析は platform_math.go にあって Linux で
// 通しますが、「解析を呼んでいること」もここで確かめられるようにします。
var (
	vmStatFn  = runVMStat
	memSizeFn = runMemSize
)

func readMemory() (usedMB, totalMB float64, ok bool) {
	out, err := vmStatFn()
	if err != nil {
		return 0, 0, false
	}
	sz, err := memSizeFn()
	if err != nil {
		return 0, 0, false
	}
	// **組み立ては platform_math.go です。** この端末で通せます。
	return darwinMemoryFrom(out, sz)
}

// commandTimeout bounds the helper processes. **ハートビートの経路なので、
// 返ってこないコマンドで止まらないようにします。**
const commandTimeout = 5 * time.Second

func runVMStat() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "vm_stat").Output()
}

func runMemSize() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "sysctl", "-n", "hw.memsize").Output()
}
