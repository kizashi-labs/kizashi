# Windows プロセスチェーン検知 — 設計ドキュメント

> **対象コンポーネント**: `server/internal/ml/process_chain.go`、`agent/internal/platform/windows/process_collector.go`
> **最終更新**: 2026-04-29（v1.3.12 時点の実装を反映）

---

## 概要

ProcessChainEngine は、エンドポイントから収集したプロセス生成イベントを使い、MITRE ATT&CK のマルチホップ攻撃シーケンス（例: `winword.exe → cmd.exe → powershell.exe`）をリアルタイムで検知するサーバーサイドエンジンである。

エンジンは各エージェント（エンドポイント）ごとに短命なプロセスキャッシュを保持し、新しいプロセスイベントが届くたびに PPID チェーンをさかのぼって祖先経路を再構成し、定義済みルールとマッチングする。

---

## アーキテクチャ

### データフロー

```
Windows エンドポイント
  └─ WindowsProcessCollector (agent)
       ├─ takeSnapshot()       … 500ms ごとに Toolhelp32 でプロセス一覧を取得
       ├─ buildEvent()         … OpenProcess → CommandLine / PPID / Username を取得
       └─ poll()               … 差分検出 + existing/create/terminate イベントを emit
             │
             │ gRPC stream (ProcessEvent)
             ▼
       ingestion service  ──NATS──▶  detection service
                                         └─ ProcessChainEngine.Analyze()
                                              ├─ procs キャッシュに挿入
                                              ├─ buildChain() … PPID を辿って祖先一覧を構築
                                              └─ matchesChain() … ルールとマッチング
                                                    │
                                                    ▼
                                              alerts テーブルに INSERT
```

### ProcessChainEngine の設計

```go
type ProcessChainEngine struct {
    mu     sync.Mutex
    procs  map[string]map[uint32]*cachedProc  // agentID → pid → proc
    rules  []chainRule
    maxAge time.Duration  // 30 分; 古いエントリを自動削除
}
```

- **キャッシュ粒度**: エージェント ID ごとに独立した map。複数エンドポイントの PID 空間が衝突しない。
- **祖先経路の向き**: `buildChain()` は newest→oldest (leaf→root) 順で返す。ルールパターンは root→leaf 順で定義。`matchesChain()` は chain を反転してからサブシーケンス判定する。
- **マッチング方式**: サブシーケンス包含（intermediate processes allowed）。攻撃チェーンの間に無関係なプロセスが挟まっても検知できる。
- **ステップのマッチング**: `chainStep.name` はプロセスイメージ名のサフィックス一致（大文字小文字無視）。`chainStep.cmdline` は非空の場合コマンドライン文字列の部分一致。

---

## Windows エージェント側の PPID 解決

### 問題: Toolhelp32 の PPID 不信頼性

`CreateToolhelp32Snapshot` + `Process32NextW` が返す `Th32ParentProcessID` は、プロセスがスナップショット取得時点ですでに終了しかけていると `0` になる場合がある。

攻撃チェーンで問題になる典型プロセスの寿命:

| プロセス | 典型実行時間 |
|---|---|
| `reg.exe` | 100〜300 ms |
| `certutil.exe` (download) | 500ms〜数秒 |
| `vssadmin.exe` | 200〜500 ms |
| `net.exe` | 100〜300 ms |

ポーリング間隔 500ms と競合すると、1 回目のスナップショットで `ppid=0` のまま記録され、ProcessChainEngine 上で祖先リンクが切れる。

### 解決策: NtQueryInformationProcess による PPID 再取得

`ntdll.dll!NtQueryInformationProcess` を `ProcessBasicInformation` クラス (0) で呼び出すと、`PROCESS_BASIC_INFORMATION` 構造体の **オフセット 40** に `InheritedFromUniqueProcessId` が格納されており、Toolhelp32 より信頼性が高い PPID を取得できる。

```go
func readParentPID(handle windows.Handle) uint32 {
    var pbi [48]byte
    var returnLen uint32
    ret, _, _ := winProcNtQueryInformationProcess.Call(
        uintptr(handle), 0,
        uintptr(unsafe.Pointer(&pbi[0])),
        uintptr(len(pbi)),
        uintptr(unsafe.Pointer(&returnLen)),
    )
    if ret != 0 {
        return 0  // STATUS_SUCCESS = 0; 非ゼロはエラー
    }
    return uint32(binary.LittleEndian.Uint64(pbi[40:48]))
}
```

PPID 解決を 2 段階で実施する:

1. **`takeSnapshot()` 内**: スナップショットループ中に `Th32ParentProcessID==0` を検出したら即座に `OpenProcess` + `readParentPID` を試みる。プロセスが生きていれば解決できる。
2. **`buildEvent()` 内**: `evt.PPID == 0` のとき同様のフォールバックを実行。OpenProcess が成功した場合のみ上書きする。

### 解決策: PPID 更新時の再 emit（v1.3.12）

Poll 1 で `ppid=0` で記録されたプロセスが Poll 2 でまだ生存しており `ppid=N` に解決できた場合、`create` イベントを再 emit する。これにより `buildEvent()` が 2 回目のチャンスを得て、cmdline をプロセス生存中に取得できる。

```go
// poll ループ内
for pid, info := range currentMap {
    known, existed := c.known[pid]
    if !existed || (known.ppid == 0 && info.ppid != 0) {
        evt := c.buildEvent(info, "create")
        select {
        case out <- evt:
        case <-ctx.Done():
            c.mu.Unlock()
            return
        default:
        }
    }
}
```

**タイムライン例（reg.exe, 寿命 ~400ms）**

```
t=0ms    reg.exe 起動 (ppid=2496, parent=powershell.exe)
t=200ms  Poll 1: takeSnapshot → ppid=0 (reg.exe 終了しかけ)
           buildEvent → OpenProcess 失敗 → ppid=0 のまま emit
t=400ms  reg.exe 終了
t=500ms  Poll 2: takeSnapshot → reg.exe がまだ currentMap にある (終了直後)
           ppid=2496 に解決成功 → 0→2496 変化を検出 → create 再 emit
           buildEvent → OpenProcess 成功 → cmdline 取得
t=1000ms Poll 3: reg.exe は消える → terminate emit
```

---

## プロセスキャッシュのシーディング

ProcessChainEngine は既存プロセスの祖先情報を持っていないと、起動後しばらくチェーンを組み立てられない。

`WindowsProcessCollector.Start()` は最初のスナップショットを「既存プロセスの初期化」として全件 emit する（action = `"existing"`）。これにより、サーバー側 ProcessChainEngine は起動直後から既存の `explorer.exe → cmd.exe` といった祖先リンクをキャッシュに持てる。

**シーディングが切れるケース**:
- detection サービスがエージェント起動後に再起動する → NATS に流れた seeding イベントを detection が受け取れない
- **対処**: 対象エンドポイントの EDRAgent サービスを再起動して seeding を再実行する

---

## チェーンルールの定義

`builtinChainRules()` に 17 件の ATT&CK ベースルールが定義されている（`server/internal/ml/process_chain.go`）。

| ルール ID | MITRE | パターン | 重要度 |
|---|---|---|---|
| chain-T1566.001-a | T1566.001 | winword → cmd → powershell | critical |
| chain-T1566.001-b | T1566.001 | excel → cmd → powershell | critical |
| chain-T1566.001-c | T1566.001 | outlook → winword → powershell | critical |
| chain-T1203-a | T1203 | chrome → powershell → certutil | critical |
| chain-T1203-b | T1203 | iexplore → cmd → powershell | critical |
| chain-T1021.001 | T1021.001 | mstsc → cmd → net | high |
| chain-T1059.001 | T1059.001 | powershell → certutil → cmd | high |
| chain-T1053.005 | T1053.005 | svchost → cmd → powershell | high |
| chain-T1569.002 | T1569.002 | services → cmd → net | high |
| chain-T1055 | T1055 | explorer → cmd → powershell | high |
| chain-T1547.001 | T1547.001 | powershell → reg.exe | high |
| chain-T1003.001 | T1003.001 | cmd → rundll32(+comsvcs) | critical |
| chain-T1218.011 | T1218.011 | cmd → rundll32 → cmd | high |
| chain-T1218 | T1218 | powershell → mshta → cmd | high |
| chain-T1505.003 | T1505.003 | w3wp → cmd → powershell | critical |
| chain-T1490 | T1490 | cmd → vssadmin(+delete shadows) | critical |
| chain-T1562.001 | T1562.001 | powershell → sc.exe(+windefend) | critical |

`stepCmd(name, cmdline)` を使うルールは、プロセス名に加えてコマンドライン文字列の部分一致も必要とする。短命プロセスで cmdline が取れない場合はマッチしないため、`step(name)` のみに緩和することで検知率を優先できる（T1547.001 はこの理由で v1.3.12 で緩和済み）。

---

## ETW を使わない理由

ETW（Event Tracing for Windows）のプロセス作成プロバイダ (`Microsoft-Windows-Kernel-Process`) は理想的には PPID を含む豊富なイベントを提供するが、以下の理由で現実装では Toolhelp32 + NtQueryInformationProcess ポーリングを採用している:

1. **管理者権限の安定性**: ETW セッション管理は権限昇格やセッション競合が発生しやすく、エンドポイントによって挙動が不安定になるケースがある。
2. **実装の複雑性**: ETW バインディングは Windows 専用 CGO または syscall の複雑なラッパーを要する。Toolhelp32 は既存の `golang.org/x/sys/windows` で完結する。
3. **ポーリング方式で十分**: 500ms ポーリング + PPID 再取得フォールバック + 再 emit により、LOLBin の短命性に対応できることが実証された。

将来的に高頻度プロセス生成（C2 ビーコンのプロセス爆発等）への対応が必要になった場合は ETW への移行を検討する。

---

## 既知の制限

| 制限 | 詳細 |
|---|---|
| 32 ビットプロセスの cmdline | `readCommandLine()` は 64 ビット PEB 構造を仮定しており、32 ビットプロセスでは不正な値を読む可能性がある。現在はエラー時に空文字列を返す |
| WOW64 プロセス | NtQueryInformationProcess の PPID 読み取りは WOW64 でも動作するが、PEB アドレス計算が差異を持つ可能性がある |
| PID 再利用 | cachedProc は PID をキーとしており、PID が再利用された場合に誤った祖先チェーンを構築する可能性がある。`addedAt` でキャッシュを 30 分で破棄することで影響を軽減している |
| エージェント再起動前のチェーン | エージェント起動前から動いているプロセス（例: explorer.exe）はシーディングで補われるが、シーディングが欠損すると検知率が下がる |
