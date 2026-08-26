// このファイルに build tag を付けていないのは意図です。
//
// `//go:build linux` を付けると、Linux の CI では Windows / macOS の
// ファイルが1件も見えず、**上限は永久に緑**になります。中身は
// ソースを文字として読むだけなので、どの OS でも走ります。
// sensor_start_test.go と同じ理由です。

package agentcontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 失敗した分岐が、値を作って先へ進む形 —— の agent 側です。
//
// サーバ側には同じ規則の検査があり（`server/internal/api/handlers/
// answered_with_a_value_test.go`）、4系統すべてを上限0まで落としました。
// **agent には1本もありませんでした。** 前回まで、この形は
// 「センサーが起動失敗しても成功を返す」10件（sensor_start_test.go）
// だけを固定していました。
//
// ここは残り全部を数えます。**今回は減らしません。上限で止めます。**
// サーバ側も同じ順序でした —— 数えて、増えないようにして、それから
// 1件ずつ理由を書くか直すか決めます。理由の無い上限は「あと何件残って
// いるか」しか言いませんが、**何件あるのかを誰も知らない状態よりは
// ずっと先に進みます。**
//
// ── 判定について ──────────────────────────────────────────────
//
// サーバ側の実装をそのまま持ってくることはできません。別モジュールで、
// テストのヘルパは跨げないためです。**写しであることは事実なので、
// 隠さずに書きます。** 判定の意味が同じであることは、両方が読む
// 共通の見本（testdata/fixtures）で留めます —— 片方だけ緩めたら、
// 見本の分類が変わって落ちます。

// agentRoot — agent モジュールの根。**internal/ だけにすると cmd/ が
// 落ちます。** 落ちたことは件数が下がる形で現れるので、下がったことを
// 「直った」と読み違えます。
const agentRoot = "../.."

type site struct {
	file string
	fn   string
	line int
	kind string // return / continue / break / assign
	src  string
	// nilErr: 関数が error を返すのに、その位置に nil を置いている。
	// **いちばん鋭い形です** —— 呼び出し側は「成功した」と受け取ります。
	nilErr bool
}

// ── 上限 ──────────────────────────────────────────────────────────────
//
// 実測です。**増えたら落ちます。減ったら下げてください** ——
// 下げないと、次に増えた分がその差に隠れます。
const (
	// 155 → 152。`internal/response/executor.go` の
	// reportQuarantineToServer が、4つの失敗（JSON生成・リクエスト生成・
	// 送信・HTTP 4xx/5xx）を記録1行だけで片付けて戻っていたのを
	// error で返すようにした分です。**隔離したファイルが `/quarantine`
	// の一覧に出ず、画面から復元できなくなる状態でした。**
	//
	// 152 → 151 / 43 → 42。落ちた2件はどちらも
	// `internal/collector/fim_collector.go` の expandRules です。監視対象を
	// stat できなかったときに黙って飛ばしていたのを、「無い」と
	// 「見に行けない」に分けて報告するようにしました。**FIM の沈黙が
	// 「変更なし」と「見ていない」の両方を意味していました。**
	//
	// 151 → 149。常駐メモリの読み取り3本を理由リストに移した分です。
	// `(値, memState)` の組で、**memState を返すこと自体が報告**です。
	//
	// 149 → 147。メモリスキャナが1プロセスを飛ばす理由を `bool` から
	// `skipReason` に変えた分（linux / windows の2本）。**「断られた」と
	// 「もう居なかった」を1つの数に入れていた**ので、健全な端末でも
	// 毎周期ゼロにならず、判定に使えませんでした。
	//
	// 147 → 145。Windows と macOS の資源測定を実装した分、いったん 154 に
	// 増えて、`(値, 測れたか)` の読み取り7本を理由リストに移して 145 に
	// なりました（ディスク空き容量の3本はもともと数に入っていました）。
	// **0% / 0 MB / 0 GB は、それぞれ「暇な端末」「空のメモリ」「満杯の
	// ディスク」という測定値です。**
	//
	// 145 → 157 / 42 → 43 / 2 → 4 (main 取り込み)。増えた分は #683
	// （アンインストール拒否・OS パッケージ配布）と #721（コマンド実行結果の
	// 返送）が持ち込んだ経路で、**どれも「その値で正しい」前提では書かれて
	// いない**ことを確かめたうえで上げています —— 保護設定を今回の便に
	// 載せない、壊れた payload のコマンドを送らない、ack の送り先が未設定の
	// 間は警告して捨てない、といった分岐です。
	//
	// 157 → 158 / 43 → 44 (#543/#764 の取り込み)。増えたのは main が
	// 入れた eBPF ファイル監視 (`platform/linux/file_ebpf_collector.go`)
	// の ring buffer 読み出しで、**同じ形が既に4本ある**ものです
	// (`ebpf_loader` / `fileless_runner` / `credaccess_runner` /
	// `hostintegrity_runner`)。ring buffer の一時的な読み出し失敗と
	// 長さの足りないレコードを飛ばして次を読む分岐で、値を作って
	// 「読めた」ことにしてはいません。
	//
	// 158 → 160 (#766)。隔離中に SSH 許可を後から入れる
	// `isolate_iptables.go:reconcileSSHAccess` の 2 分岐です。nft / iptables の
	// どちらでも、追加に失敗したら記録して戻ります。**戻った先で隔離自体は
	// 効いたまま**で、開けられなかったのは調査用の SSH だけなので、
	// 「値を作って成功に見せる」形ではありません。
	//
	// 160 → 163 / 44 → 45 (#767)。隔離解除で Windows ファイアウォールの
	// 既定ポリシーを元に戻す `isolate_firewall_policy.go` が持ち込んだ分:
	//
	//   readFirewallPolicy ×2  プロファイルの registry キーが無いのは
	//       ドメイン参加したことがない機体では正常なので、Windows の既定値で
	//       埋める。**「読めなかった」ではなく「既定のままだった」**
	//   loadFirewallPolicy ×2  隔離前スナップショットが無い／壊れている。
	//       nil は「戻すものが無い」の意味で、呼び出し側はそれを見て
	//       netsh の既定に戻す道を選ぶ
	//
	// **163 → 157。初めて下がりました。** 資格情報アクセスの監視で、
	// 「失敗」と「対象なし」が同じ値になっていた分です:
	//
	//   cmd/agent/cred_windows.go:findLsassPID ×3
	//       スナップショットが取れない・先頭が読めない・走査が途中で
	//       終わった —— 3つとも `return 0` で、呼び出し側からは
	//       **「lsass.exe が見つからなかった」と区別が付きません。**
	//       lsass.exe は Windows に必ずいるので、0 が返るのは実際には
	//       ほぼ必ず探せなかったときです。`(uint32, error)` にして、
	//       呼び出し側が telemetry に `ModeFailed` を出すようにしました。
	//   cmd/agent/cred_windows.go / cred_linux.go の未起動分岐 ×3
	//       ドライバ未ロード・lsass PID 登録失敗・eBPF LSM 未起動。
	//       どれも `slog` 1行で抜けていたので、**その端末で資格情報
	//       アクセスを見ていないことが SOC から数えられません**でした。
	//       これも telemetry に寄せてあります。
	agentReturnCeiling   = 157
	agentContinueCeiling = 45
	agentBreakCeiling    = 10
	agentAssignCeiling   = 4

	// QA・採点用の道具。端末には配られないので、製品の数と混ぜません。
	// **混ぜると、道具を1件直したのが端末を1件直したのと同じ数字に
	// なります。**
	// このエディションは攻撃実証用の PoC コマンド (wininject / wincred /
	// wintamper / prevention / winprev / etw-verify) を同梱しないため、
	// 数えられる QA 道具が少ない。上限もその実数に合わせてある。
	// ずれたときは、このテストが出力する実数に合わせて更新する。
	harnessCeiling = 5

	// **0 になりました。** 開始時は10件で、内訳は Windows の ETW 7本と
	// macOS の3本でした。ETW は報告を足して分岐が「値を作るだけ」では
	// なくなり、macOS の3本はエラーを返すようにしました。
	//
	// **この系統がいちばん鋭い形です** —— 関数は error を返せるのに、
	// その位置に nil を置く。呼び出し側は「成功した」と受け取ります。
	//
	// nilErr は sensor_start_test.go も10件で固定していますが、**同じ数に
	// はなりません。訊いていることが違うからです。**
	//
	//   あちら: センサーの Start が、失敗しても nil を返しているか
	//           （分岐が他に何をしていても数えます）
	//   ここ:   分岐が「値を作って終わる」だけか
	//           （報告していれば数えません）
	//
	// 前回 ETW の7本に `etwSensorFailed` を足したので、こちらでは7件減って
	// 3件になりました。あちらは10件のままです —— **戻り値は変えていない
	// ので、正しく10件です。** 数が違うことが、2つが別の問いを見ている
	// 証拠になります。
	agentNilErrCeiling = 0
)

// shippedCmds — 端末に配られるバイナリ。
//
// **`cmd/` の下は全部が製品ではありません。** CLAUDE.md のとおり、
// `agent` と `watchdog` 以外（attack-scorer / etw-verify / prevention-poc /
// wincred-poc / wininject-poc / winprev-poc / wintamper-poc / fleet-sim /
// scorecard-trend）は QA・採点用の道具で、build tag で隔離されていて
// 端末には配られません。
//
// 一緒に数えると、**採点道具の1件を直したのが端末の1件を直したのと
// 同じ数字になります。** 分けて数え、分けて上限を持ちます。
var shippedCmds = map[string]bool{
	"cmd/agent":    true,
	"cmd/watchdog": true,
}

// isHarness reports whether a file belongs to a QA tool rather than the
// shipped agent.
func isHarness(file string) bool {
	if !strings.HasPrefix(file, "cmd/") {
		return false
	}
	rest := strings.TrimPrefix(file, "cmd/")
	dir := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		dir = rest[:i]
	}
	return !shippedCmds["cmd/"+dir]
}

// returnReasons — 「値で答えるのが正しい」箇所。キーは file:fn。
//
// **上限だけでは「あと何件残っているか」しか言えません。** 0 にするには、
// 残った1件ずつに「なぜ値で答えるのが正しいのか」を書くしかありません。
// 書けないものは例外ではなく、直す対象です。
// marshalUnreachable — 自前の構造体を json.Marshal する分岐の共通理由。
//
// **到達しません。** encoding/json が失敗するのは chan・func・NaN・
// 循環参照を含むときだけで、ここで渡しているのはこのパッケージが組み立てた
// 平坦な構造体です。外から来た JSON 由来の値も NaN にはなりません
// （JSON に NaN リテラルがありません）。
//
// 消さずに残すのは、到達したときに黙って捨てるのが正しくないからでは
// なく、**型が変われば先にコンパイルが落ちる**ためです。分岐があること
// 自体は害になりません。
//
// サーバ側の同じ判定も、この形を (b) として理由付きで残しています。
const marshalUnreachable = "(b) 自前の構造体を json.Marshal する分岐。" +
	"chan・func・NaN・循環参照を含まないので encoding/json は失敗しません。" +
	"到達したときは型が変わっているはずで、コンパイルが先に落ちます"

var returnReasons = map[string]string{
	// ── (b) json.Marshal — 到達しない分岐 ──────────────────────────
	"internal/collector/credential_access.go:BuildCredentialAccessEvent":   marshalUnreachable,
	"internal/collector/event_log_clear.go:BuildEventLogClearEvent":        marshalUnreachable,
	"internal/collector/event_service_install.go:BuildServiceInstallEvent": marshalUnreachable,
	"internal/collector/hostintegrity.go:BuildHostIntegrityEvent":          marshalUnreachable,
	"internal/collector/memory_scan.go:BuildMemoryEvent":                   marshalUnreachable,
	"internal/collector/named_pipe.go:BuildNamedPipeEvent":                 marshalUnreachable,
	"internal/collector/ps_module.go:BuildPSModuleEvent":                   marshalUnreachable,
	"internal/collector/remote_thread.go:BuildRemoteThreadEvent":           marshalUnreachable,
	"internal/collector/tls_handshake.go:BuildTLSHandshakeEvent":           marshalUnreachable,
	"internal/collector/wmi_activity.go:BuildWMIActivityEvent":             marshalUnreachable,
	"internal/collector/device_collector.go:emitEvent":                     marshalUnreachable,
	"internal/collector/fim_collector.go:emitEvent":                        marshalUnreachable,
	"internal/collector/process_monitor.go:BuildProcessBlockEvent":         marshalUnreachable,

	// ── (値, 測れたか) の組 ────────────────────────────────────────
	//
	// **この判定は、`false` が「答え」なのか「報告」なのかを見分けられ
	// ません。** `conditionMatches` の false は「一致しなかった」という
	// 答えで、`readMemInfo` の false は「測れなかった」という報告です。
	// 構文は同じなので、意味はここに書きます。
	"internal/hostmetrics/cpu.go:parseProcStat": "(値, 測れたか) の組。" +
		"false が報告そのものです。**部分的に足した合計を返さない**ための" +
		"分岐で、返すと 0 と同じ種類の嘘になります",
	"internal/hostmetrics/cpu.go:readProcStat":      "同上。ファイルを開けなかったことを false で返します",
	"internal/hostmetrics/cpu.go:parseMemInfoValue": "同上。読めない数値を 0 として扱いません",
	"internal/hostmetrics/cpu.go:readMemInfo":       "同上",

	// 常駐メモリの読み取り。**答えは3つあります** ——「測れた」
	// 「ユーザ空間が無い（カーネルスレッド）」「読めなかった」。
	// memState を返り値に置くこと自体が報告で、0 kB は測定値です。
	// 2つに畳んでいたあいだ、このコンテナでは 75 件中 67 件が
	// プロセス一覧から丸ごと消えていました（T1496 の入力です）。
	"internal/collector/process_stats_linux.go:readVmRSS": "(値, memState) の組。" +
		"memState が報告そのものです",
	"internal/collector/process_stats_linux.go:parseVmRSS":  "同上。読み取りの側",
	"internal/collector/process_stats_darwin.go:parsePSRSS": "同上。ps の RSS 列",

	// 端末の資源を測る読み取り。**`ok=false` を返すこと自体が報告です。**
	// 0% / 0 MB / 0 GB は、それぞれ「暇な端末」「空のメモリ」「満杯の
	// ディスク」という測定値です —— 測っていないことを、いちばん強い
	// 主張に化けさせないためにこの形にしてあります。
	//
	// Windows と macOS はこの端末で走らせられないので、算術と解析は
	// build tag の無い `platform_math.go` に出して Linux で通しています。
	"internal/hostmetrics/platform_math.go:parsePageSize":   "(値, 測れたか) の組",
	"internal/hostmetrics/platform_math.go:parseVMStatLine": "同上。vm_stat の1行",
	"internal/hostmetrics/platform_math.go:parseSysctlUint": "同上。sysctl の出力",
	"internal/hostmetrics/cpu_darwin.go:readMemory":         "同上。vm_stat と sysctl の両方が要ります",
	"internal/collector/resource_collector_windows.go:readDiskFreeGB": "同上。" +
		"**0 GB は「満杯の端末」という測定値です**",
	"internal/collector/resource_collector_darwin.go:readDiskFreeGB": "同上",
	"internal/collector/resource_collector_linux.go:readDiskFreeGB":  "同上",

	// ── (c)「分からない」と明示している ───────────────────────────
	//
	// **これが正しい形です。** 空文字は「値が無い」とも「調べていない」
	// とも読めますが、"unknown" はどちらでもなく「調べたが分からなかった」
	// と言っています。Sigma 規則は Signed/Unsigned を見るので、
	// **unknown が署名済みとして通ることはありません。**
	"internal/platform/windows/imageload_etw.go:verifyAuthenticode": "(c) " +
		"署名検証。**\"unknown\" と明示して返します** —— 空文字なら" +
		"「署名欄の無いイベント」に見えますが、これは「調べたが" +
		"分からなかった」と言っています",
	"internal/platform/windows/imageload_etw.go:verifyViaCatalog": "(c) 同上。" +
		"カタログ署名の確認経路",
	"internal/platform/windows/integrity_level.go:tokenIntegrityLevel": "(c) " +
		"\"unknown\" を返します。**空文字は同じ経路で「まだ埋めていない」の" +
		"合図として使われている**ので、潰すと2つの状態が1つの値になります。" +
		"いまは「開けなかった」が \"\"、「開けたが読めなかった」が \"unknown\" です",
	"internal/platform/windows/integrity_level.go:tokenLogonID": "(c) 同上。" +
		"ログオンセッションID",

	// ── (c) パスは「空 ＝ 無い」で正しい ───────────────────────────
	//
	// **IntegrityLevel と同じ直し方は、ここでは間違いです。**
	// `evt.ImagePath == ""` を見ている箇所が8つあり（ハッシュ計算、
	// VERSIONINFO の読み取り、ML スキャナ）、**どれも「パスが無いなら
	// 触らない」で正しく動いています。** "unknown" を返すと、
	// `unknown` という名前のファイルを開こうとし始めます。
	//
	// 値の表し方は、下流が何をするかで決まります。ラベル（IntegrityLevel）
	// は「分からない」と書けますが、パスは開く対象なので、
	// **無いことは無いままにしておく必要があります。**
	"internal/platform/windows/prevention_driver.go:ProcessImageName": "(c) " +
		"パスを取れなければ空。呼び出し側は「パスの無いイベント」として" +
		"扱い、ハッシュも VERSIONINFO も試みません。**\"unknown\" に" +
		"すると、その名前のファイルを開こうとします**",
	"internal/platform/windows/pathalias_windows.go:resolvePath": "(c) 同上。" +
		"デバイスパスをドライブレターに直せなければ空で、呼び出し側が" +
		"元のパスを使い続けます",
	"internal/platform/windows/pathalias_windows.go:volumeDevicePath": "(c) 同上",
	"internal/platform/windows/version_info.go:readVersionInfo": "(c) " +
		"PE の VERSIONINFO は**多くの実行ファイルに最初からありません。**" +
		"空の versionInfo は「資源が無い」で、読めなかったことと同じ姿ですが、" +
		"どちらも「改名バイナリの証拠が無い」で正しく倒れます",
	"internal/platform/windows/version_info.go:queryString": "(c) 同上。" +
		"個々の文字列欄",
	"internal/platform/windows/version_info.go:translations": "(c) 同上。" +
		"言語テーブル",
	"internal/platform/windows/network_collector.go:pidToName": "(c) " +
		"PID からプロセス名を引けなければ空。**ここも \"unknown\" は" +
		"間違いです。** サーバの alert_pipeline は " +
		"`pn != \"\"` を確かめてから Sigma の `Image` 欄に入れるので、" +
		"\"unknown\" はその関門を通り、**存在しないプロセス名として" +
		"アラートとハンティングに出ます。** 名前になる値は、" +
		"分からないなら空のままにします",

	// ── 呼び出し側が「測れなかった」を弾く ─────────────────────────
	"internal/collector/resource_collector_linux.go:readCPUStat": "(0, 0) を" +
		"返しますが、**呼び出し側の collect が `total > prevTotal` で弾きます** ——" +
		"total が 0 なら差が取れないので、CPU の欄は落ちます。0% として" +
		"送られることはありません（unmeasured_test.go が留めています）",
}

// ── 走査 ──────────────────────────────────────────────────────────────

func errIdents(cond ast.Expr) map[string]bool {
	out := map[string]bool{}
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.BinaryExpr:
			if v.Op == token.NEQ {
				if id, ok := v.X.(*ast.Ident); ok {
					if nl, ok2 := v.Y.(*ast.Ident); ok2 && nl.Name == "nil" {
						l := strings.ToLower(id.Name)
						if l == "err" || l == "e" || strings.HasSuffix(l, "err") {
							out[id.Name] = true
						}
					}
				}
			}
			if v.Op == token.LAND || v.Op == token.LOR {
				walk(v.X)
				walk(v.Y)
			}
		case *ast.ParenExpr:
			walk(v.X)
		}
	}
	walk(cond)
	return out
}

func touches(n ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// returnsAnError — 新しいエラーに翻訳して返すのは報告です。
func returnsAnError(ret *ast.ReturnStmt) bool {
	for _, r := range ret.Results {
		switch v := r.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				pkg, _ := sel.X.(*ast.Ident)
				if pkg != nil && ((pkg.Name == "errors" && sel.Sel.Name == "New") ||
					(pkg.Name == "fmt" && sel.Sel.Name == "Errorf")) {
					return true
				}
			}
		case *ast.Ident:
			n := v.Name
			if n != "nil" && len(n) > 3 &&
				(strings.HasPrefix(n, "err") || strings.HasPrefix(n, "Err")) {
				return true
			}
		}
	}
	return false
}

// isLoggingCall — 記録だけの呼び出し。受け手はいません。
//
// **記録して値を返すのは、まだ値で答えています。** ここを「対処している」
// に数えると、slog を1行足すだけで件数が下がります。サーバ側で実際に
// そうなり、下がった数が直ったように見えました。
func isLoggingCall(x ast.Expr) bool {
	call, ok := x.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Debug", "Info", "Warn", "Error", "Print", "Printf", "Println",
		"DebugContext", "InfoContext", "WarnContext", "ErrorContext":
	default:
		return false
	}
	recv := ""
	switch r := sel.X.(type) {
	case *ast.Ident:
		recv = r.Name
	case *ast.SelectorExpr:
		recv = r.Sel.Name
	}
	recv = strings.ToLower(recv)
	return recv == "slog" || recv == "log" || strings.Contains(recv, "log")
}

// answersOnly — 分岐が「値を作って終わる」だけかどうか。
func answersOnly(b *ast.BlockStmt, errs map[string]bool) (string, bool) {
	if len(b.List) == 0 {
		return "empty", true
	}
	kind := ""
	for _, st := range b.List {
		switch s := st.(type) {
		case *ast.ReturnStmt:
			if touches(s, errs) || returnsAnError(s) {
				return "", false
			}
			kind = "return"
		case *ast.BranchStmt:
			if s.Tok != token.CONTINUE && s.Tok != token.BREAK {
				return "", false
			}
			kind = strings.ToLower(s.Tok.String())
		case *ast.AssignStmt:
			if touches(s, errs) {
				return "", false
			}
			hasCall := false
			ast.Inspect(s, func(x ast.Node) bool {
				if _, ok := x.(*ast.CallExpr); ok {
					hasCall = true
				}
				return !hasCall
			})
			if hasCall {
				return "", false
			}
			kind = "assign"
		case *ast.ExprStmt:
			if !isLoggingCall(s.X) {
				return "", false
			}
		default:
			return "", false
		}
	}
	if kind == "" {
		return "", false // 記録だけして続きに落ちる分岐。値では答えていません
	}
	return kind, true
}

// nilInErrorSlot — 関数の error 位置に nil を置いているか。
func nilInErrorSlot(fn *ast.FuncDecl, ret *ast.ReturnStmt) bool {
	if fn.Type.Results == nil || len(ret.Results) == 0 {
		return false
	}
	pos, i := -1, 0
	for _, r := range fn.Type.Results.List {
		n := len(r.Names)
		if n == 0 {
			n = 1
		}
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			pos = i
		}
		i += n
	}
	if pos < 0 || pos >= len(ret.Results) {
		return false
	}
	id, ok := ret.Results[pos].(*ast.Ident)
	return ok && id.Name == "nil"
}

func srcOf(fset *token.FileSet, n ast.Node, body []byte) string {
	p, e := fset.Position(n.Pos()), fset.Position(n.End())
	if p.Offset < 0 || e.Offset > len(body) {
		return ""
	}
	s := strings.Join(strings.Fields(string(body[p.Offset:e.Offset])), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// findSites walks root for non-test Go and returns every branch that answers.
//
// **build tag は無視します。** 尊重すると Linux では windows/darwin の
// ファイルが1件も見えず、上限が永久に緑になります。
func findSites(t *testing.T, root string) []site {
	t.Helper()
	var out []site

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				switch info.Name() {
				case "vendor", "testdata", ".git", "gen":
					return filepath.SkipDir
				}
			}
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(path) // #nosec G304 -- repo-local source
		if rerr != nil {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, body, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || ifs.Body == nil {
					return true
				}
				errs := errIdents(ifs.Cond)
				if len(errs) == 0 {
					return true
				}
				kind, only := answersOnly(ifs.Body, errs)
				if !only || kind == "empty" {
					return true
				}
				s := site{
					file: rel, fn: fn.Name.Name,
					line: fset.Position(ifs.Pos()).Line,
					kind: kind, src: srcOf(fset, ifs, body),
				}
				for _, st := range ifs.Body.List {
					if ret, ok := st.(*ast.ReturnStmt); ok && nilInErrorSlot(fn, ret) {
						s.nilErr = true
					}
				}
				out = append(out, s)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return out
}

// ── 検査 ──────────────────────────────────────────────────────────────

// ceilingComplaint は判定そのものです。**切り出してあるのは、
// 直接動かせるようにするためです。**
//
// 上限ちょうどでなければ文字列を返します。両方向で返すのが要点で、
// 減ったときに黙ると、下げ忘れた差の中に次の増加が隠れます。
func ceilingComplaint(kind string, actual, ceiling int) string {
	if actual > ceiling {
		return fmt.Sprintf(
			"失敗を %s で片付けている箇所が %d から %d に増えています。"+
				"分岐そのものが応答を返さないので、空で返す実装を探す検査には"+
				"映りません", kind, ceiling, actual)
	}
	if actual < ceiling {
		return fmt.Sprintf(
			"失敗を %s で片付けている箇所が %d まで減りました。"+
				"上限を %d に下げてください。**下げないと、次に増えた分が"+
				"この差に隠れます。**", kind, actual, actual)
	}
	return ""
}

func complain(t *testing.T, kind string, got []site, ceiling int) {
	t.Helper()
	msg := ceilingComplaint(kind, len(got), ceiling)
	if msg == "" {
		return
	}
	detail := ""
	if len(got) > ceiling && len(got) <= ceiling+12 {
		sort.Slice(got, func(i, j int) bool {
			return got[i].file+got[i].fn < got[j].file+got[j].fn
		})
		for _, s := range got {
			detail += fmt.Sprintf("\n  %s:%d %s — %s", s.file, s.line, s.fn, s.src)
		}
	}
	t.Errorf("%s%s", msg, detail)
}

// 上限の判定が、両方向に効くこと。
//
// **判定を無効にする変異は、違反する入力を食わせる検査でしか殺せません。**
// 実際に生き残りました —— 実測が上限ちょうどなので、`==` を `<=` に
// 緩めても何も変わりませんでした。
func TestTheCeilingComplainsBothWays(t *testing.T) {
	if msg := ceilingComplaint("x", 5, 5); msg != "" {
		t.Errorf("上限ちょうどで文句を言っています: %s", msg)
	}
	if msg := ceilingComplaint("x", 6, 5); msg == "" {
		t.Error("増えたのに黙っています")
	}
	if msg := ceilingComplaint("x", 4, 5); msg == "" {
		t.Error("**減ったのに黙っています。** 下げ忘れた差に、" +
			"次の増加が隠れます")
	}
}

// 走査が届いていること。**0箇所を検査して緑を返すのがいちばん高くつきます。**
//
// 本体の中の下限チェックとは別に置きます。あちらを潰す変異は
// 「そのテストを消す」のと同じで殺せませんが、こちらは実測を直接見ます。
func TestTheScanReachesTheWholeModule(t *testing.T) {
	sites := findSites(t, agentRoot)
	if len(sites) < 100 {
		t.Fatalf("走査が届いていません: %d 箇所しか見つかりません", len(sites))
	}
	// build tag を尊重していないことの確認。Linux で windows/darwin の
	// ファイルが見えていなければ、この検査は何も見ていません。
	var win, mac, cmd bool
	for _, s := range sites {
		switch {
		case strings.Contains(s.file, "platform/windows/"):
			win = true
		case strings.Contains(s.file, "platform/darwin/"):
			mac = true
		case strings.HasPrefix(s.file, "cmd/"):
			cmd = true
		}
	}
	if !win || !mac || !cmd {
		t.Errorf("走査の穴: windows=%v darwin=%v cmd=%v。"+
			"見えていない範囲は、上限では永久に緑です", win, mac, cmd)
	}
}

func TestAgentFailuresAreNotAnsweredWithAValue(t *testing.T) {
	sites := findSites(t, agentRoot)

	// 走査が届いていること。**0箇所を検査して緑を返すのが
	// いちばん高くつきます。**
	if len(sites) < 100 {
		t.Fatalf("走査が届いていません: %d 箇所しか見つかりません", len(sites))
	}

	byKind := map[string][]site{}
	var nilErr, harness []site
	for _, s := range sites {
		if s.kind == "return" {
			if _, ok := returnReasons[s.file+":"+s.fn]; ok {
				continue // 理由を書いた箇所は上限から外します
			}
		}
		if isHarness(s.file) {
			harness = append(harness, s)
			continue
		}
		byKind[s.kind] = append(byKind[s.kind], s)
		if s.nilErr {
			nilErr = append(nilErr, s)
		}
	}

	complain(t, "return", byKind["return"], agentReturnCeiling)
	complain(t, "continue", byKind["continue"], agentContinueCeiling)
	complain(t, "break", byKind["break"], agentBreakCeiling)
	complain(t, "assign", byKind["assign"], agentAssignCeiling)
	complain(t, "nil を error の位置に置く return", nilErr, agentNilErrCeiling)
	complain(t, "QA 道具の中で値", harness, harnessCeiling)

	t.Logf("端末に配られる分: return %d / continue %d / break %d / assign %d / nilErr %d",
		len(byKind["return"]), len(byKind["continue"]),
		len(byKind["break"]), len(byKind["assign"]), len(nilErr))
	t.Logf("QA 道具: %d", len(harness))
}

// 理由が古くならないこと。直した箇所の理由が残っていると、
// **読んだ人はまだ壊れていると思います。**
func TestNoAgentReasonHasGoneStale(t *testing.T) {
	found := map[string]bool{}
	for _, s := range findSites(t, agentRoot) {
		if s.kind == "return" {
			found[s.file+":"+s.fn] = true
		}
	}
	for key := range returnReasons {
		if !found[key] {
			t.Errorf("%s: 理由として残していますが、実測に見当たりません。"+
				"直したのなら理由も消してください", key)
		}
	}
}
