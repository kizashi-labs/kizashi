package hostmetrics

import (
	"math"
	"strings"
	"testing"
)

// Windows と macOS の読み取りは、この端末では走らせられません。
// syscall そのものは確かめようがありませんが、**間違えるのは算術と解析の
// 側です。** それを OS 非依存の関数に出してあるので、ここで通します。
//
// このリポジトリには前例があります。`filetimeSumCentis` は FILETIME を
// 絶対時刻として扱う `Filetime.Nanoseconds()` を使っていたため、
// **全プロセスの CPU 時間が 0 になっていました。** 呼び出しは成功し、
// 型は合い、値だけが嘘でした。

// ── Windows: CPU ─────────────────────────────────────────────────────────

// FILETIME の2つの半分が、正しく1つの数になること。
//
// **`Filetime.Nanoseconds()` は使えません。** 絶対時刻として扱い、
// Unix エポック分 (116444736000000000) を引きます。GetSystemTimes が
// 返すのは経過時間なので、引くと桁が飛びます。
func TestFiletimeHalvesCombine(t *testing.T) {
	cases := []struct {
		high, low uint32
		want      uint64
	}{
		{0, 0, 0},
		{0, 1, 1},
		{0, 0xFFFFFFFF, 0xFFFFFFFF},
		{1, 0, 1 << 32},
		{1, 1, 1<<32 + 1},
		{0x12345678, 0x9ABCDEF0, 0x123456789ABCDEF0},
	}
	for _, tc := range cases {
		if got := ftTicks(tc.high, tc.low); got != tc.want {
			t.Errorf("ftTicks(%#x, %#x) = %#x, want %#x", tc.high, tc.low, got, tc.want)
		}
	}
}

// kernel に idle が含まれること。**足し忘れると分母が小さくなり、
// CPU 使用率が実際より高く出ます。**
func TestWindowsCPUTotalsCountsIdleInsideKernel(t *testing.T) {
	// MSDN: lpKernelTime includes lpIdleTime.
	// idle 800, kernel 900 (idle 込み), user 100 → total 1000, busy 20%
	idle, total, ok := windowsCPUTotals(800, 900, 100)
	if !ok {
		t.Fatal("測れたはずが false です")
	}
	if total != 1000 {
		t.Errorf("total = %d, want 1000 (kernel+user)。**kernel には idle が"+
			"含まれるので、別に足すと二重計上になります**", total)
	}
	busy := float64(total-idle) / float64(total) * 100
	if math.Abs(busy-20) > 0.001 {
		t.Errorf("busy = %.3f%%, want 20%%", busy)
	}
}

func TestWindowsCPUTotalsRefusesNonsense(t *testing.T) {
	cases := []struct {
		name               string
		idle, kernel, user uint64
	}{
		// 起動直後。**0% ではなく「まだ分からない」です。**
		{"全部ゼロ", 0, 0, 0},
		// idle が total を超えるのは読み違いです。
		{"idle が大きすぎる", 2000, 900, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := windowsCPUTotals(tc.idle, tc.kernel, tc.user); ok {
				t.Error("測れたことにしています")
			}
		})
	}
}

// ── Windows: メモリ ──────────────────────────────────────────────────────

func TestWindowsMemoryMB(t *testing.T) {
	const gb = 1024 * 1024 * 1024
	used, total, ok := windowsMemoryMB(16*gb, 4*gb)
	if !ok {
		t.Fatal("測れたはずが false です")
	}
	if total != 16*1024 {
		t.Errorf("total = %.1f MB, want 16384", total)
	}
	if used != 12*1024 {
		t.Errorf("used = %.1f MB, want 12288 (合計 − 利用可能)", used)
	}
}

func TestWindowsMemoryMBRefusesNonsense(t *testing.T) {
	if _, _, ok := windowsMemoryMB(0, 0); ok {
		t.Error("合計 0 を測れたことにしています")
	}
	if _, _, ok := windowsMemoryMB(1000, 2000); ok {
		t.Error("利用可能 > 合計 を測れたことにしています")
	}
}

// ── macOS: vm_stat ───────────────────────────────────────────────────────

const vmStatAppleSilicon = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                              123456.
Pages active:                            200000.
Pages inactive:                          150000.
Pages speculative:                        50000.
Pages throttled:                              0.
Pages wired down:                        100000.
Pages purgeable:                          10000.
"Translation faults":                 987654321.
Pages copy-on-write:                   12345678.
Pages zero filled:                    234567890.
Pages reactivated:                       345678.
Pages purged:                             45678.
File-backed pages:                       180000.
Anonymous pages:                         220000.
Pages stored in compressor:              300000.
Pages occupied by compressor:             80000.
`

// ページサイズを見出し行から取ること。
//
// **4096 を決め打ちすると、Apple Silicon の使用量が実際の 1/4 に
// なります** —— 呼び出しは成功し、型も合い、値だけが 4 倍ずれます。
func TestVMStatUsesTheReportedPageSize(t *testing.T) {
	used, ok := parseVMStat(strings.NewReader(vmStatAppleSilicon))
	if !ok {
		t.Fatal("解析できませんでした")
	}
	// (active 200000 + wired 100000 + compressor 80000) * 16384
	const want = uint64(380000) * 16384
	if used != want {
		t.Errorf("used = %d, want %d", used, want)
	}
	// 4096 で読んでいたら 1/4 になります。
	if used == want/4 {
		t.Error("ページサイズを 4096 と決め打ちしています")
	}
}

func TestVMStatOnIntelPageSize(t *testing.T) {
	in := strings.ReplaceAll(vmStatAppleSilicon, "16384 bytes", "4096 bytes")
	used, ok := parseVMStat(strings.NewReader(in))
	if !ok {
		t.Fatal("解析できませんでした")
	}
	if want := uint64(380000) * 4096; used != want {
		t.Errorf("used = %d, want %d", used, want)
	}
}

// inactive を「使用中」に数えないこと。
//
// **必要になれば回収される分です。** Linux 側で MemFree ではなく
// MemAvailable を使っているのと同じ理由で、数えると健全な Mac が
// ほぼ全部メモリ逼迫に見えます。
func TestVMStatDoesNotCountReclaimablePages(t *testing.T) {
	used, ok := parseVMStat(strings.NewReader(vmStatAppleSilicon))
	if !ok {
		t.Fatal("解析できませんでした")
	}
	withInactive := uint64(380000+150000) * 16384
	if used == withInactive {
		t.Error("inactive を使用中に数えています")
	}
	withSpeculative := uint64(380000+50000) * 16384
	if used == withSpeculative {
		t.Error("speculative を使用中に数えています")
	}
}

// 圧縮されたメモリを数えること。**物理 RAM を占めています。**
func TestVMStatCountsTheCompressor(t *testing.T) {
	in := strings.ReplaceAll(vmStatAppleSilicon,
		"Pages occupied by compressor:             80000.",
		"Pages occupied by compressor:                 0.")
	used, ok := parseVMStat(strings.NewReader(in))
	if !ok {
		t.Fatal("解析できませんでした")
	}
	if want := uint64(300000) * 16384; used != want {
		t.Errorf("compressor を 0 にしたら used = %d, want %d", used, want)
	}
}

// 「stored in compressor」と取り違えないこと。
//
// **stored は圧縮前の論理ページ数で、occupied が実際に占めている
// 物理ページ数です。** 取り違えると使用量が大きく出ます
// （この見本では 300000 対 80000）。
func TestVMStatDoesNotConfuseStoredWithOccupied(t *testing.T) {
	used, _ := parseVMStat(strings.NewReader(vmStatAppleSilicon))
	stored := uint64(200000+100000+300000) * 16384
	if used == stored {
		t.Error("「Pages stored in compressor」を使っています。" +
			"占有量は「Pages occupied by compressor」です")
	}
}

func TestVMStatRefusesIncompleteOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"空", ""},
		{"見出しが無い（ページサイズ不明）",
			"Pages active:  100.\nPages wired down:  100.\n"},
		{"active が無い",
			"Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages wired down: 100.\n"},
		{"wired が無い",
			"Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages active: 100.\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// **足りない項を 0 として足しません。** 部分的な合計が
			// 測定値の顔をします。
			if _, ok := parseVMStat(strings.NewReader(tc.in)); ok {
				t.Error("測れたことにしています")
			}
		})
	}
}

// ── macOS: sysctl ────────────────────────────────────────────────────────

func TestParseSysctlUint(t *testing.T) {
	if v, ok := parseSysctlUint([]byte("17179869184\n")); !ok || v != 17179869184 {
		t.Errorf("= (%d, %v), want (17179869184, true)", v, ok)
	}
	for _, in := range []string{"", "\n", "abc", "0"} {
		if _, ok := parseSysctlUint([]byte(in)); ok {
			t.Errorf("%q を測れたことにしています", in)
		}
	}
}

func TestDarwinMemoryMB(t *testing.T) {
	const gb = 1024 * 1024 * 1024
	used, total, ok := darwinMemoryMB(6*gb, 16*gb)
	if !ok {
		t.Fatal("測れたはずが false です")
	}
	if used != 6*1024 || total != 16*1024 {
		t.Errorf("= (%.1f, %.1f) MB, want (6144, 16384)", used, total)
	}
}

// 片方だけでは出さないこと。
//
// **合計が測れていないのに使用量だけ出すと、サーバ側の使用率
// (used/total) が壊れます。**
func TestDarwinMemoryRefusesAHalfReading(t *testing.T) {
	if _, _, ok := darwinMemoryMB(1000, 0); ok {
		t.Error("合計 0 で測れたことにしています")
	}
	if _, _, ok := darwinMemoryMB(2000, 1000); ok {
		t.Error("使用量 > 合計 で測れたことにしています")
	}
}

// 2つの読み取りを組み立てる所。
//
// **部品は全部試してあったのに、組み立てだけ試していませんでした。**
// build tag を付けなかったのは、まさにここを Linux で通すためです。
// 試していない間、`staticcheck` からは呼ばれていない関数に見えていて、
// CI が U1000 で止まって初めて分かりました（macOS でしか呼ばれないので、
// Linux の走査からは使われていないように見えます）。
//
// 引数を取り違えても、型は合います —— vm_stat の出力と sysctl の出力は
// どちらも []byte です。取り違えたら解析が失敗して false になるので、
// ここで捕まります。
func TestDarwinMemoryFromComposesBothReadings(t *testing.T) {
	used, total, ok := darwinMemoryFrom([]byte(vmStatAppleSilicon), []byte("17179869184\n"))
	if !ok {
		t.Fatal("測れたはずが false です")
	}
	// (active 200000 + wired 100000 + compressor 80000) * 16384 バイト
	const wantUsed = float64(380000*16384) / (1024 * 1024)
	if used != wantUsed || total != 16*1024 {
		t.Errorf("= (%.1f, %.1f) MB, want (%.1f, 16384)", used, total, wantUsed)
	}
	// 引数を逆に渡したら、測れたことにしないこと。
	if _, _, ok := darwinMemoryFrom([]byte("17179869184\n"), []byte(vmStatAppleSilicon)); ok {
		t.Error("vm_stat と sysctl を取り違えても測れたことにしています")
	}
}

// 片方が読めなければ、両方出さないこと。
func TestDarwinMemoryFromRefusesAHalfReading(t *testing.T) {
	if _, _, ok := darwinMemoryFrom([]byte(vmStatAppleSilicon), []byte("")); ok {
		t.Error("sysctl が空でも測れたことにしています")
	}
	if _, _, ok := darwinMemoryFrom([]byte("Pages active: 1.\n"), []byte("17179869184\n")); ok {
		t.Error("vm_stat が不完全でも測れたことにしています")
	}
}
