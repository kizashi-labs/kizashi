# ETW / EvtSubscribe テレメトリ検証ランブック

opt-in（`EDR_AGENT_ETW=1`）の Windows リアルタイムコレクタ
（プロセス / ネットワーク / DNS / 認証）が、**実機で実際にイベントを出すか**を
確認するための手順。

> このリポジトリの CI ではコンパイル/vet までしか検証できない（ETW セッションと
> Security ログ購読は管理者権限の実 Windows が要る）。本ランブックは
> 「コンパイル可能」を「実機で動作確認済み」に引き上げるための最終ステップ。

> ### ★ 2026-08-04 訂正 — 「CI では検証できない」は誤りだった
>
> 上の前提は**成り立っていなかった**。`.github/workflows/agent-os-tests.yml` の
> `Windows platform tests` ジョブは GitHub ホストの `windows-latest` で
> `agent/internal/platform/windows` のテストを走らせており、**そのランナーは
> 管理者である**。ETW リアルタイムセッションを開くのも `root\subscription` に
> 書くのも、そこで満たされている。要件は最初から満たされていた。
>
> 実証として WMI-Activity センサーの実機検証を CI に入れた
> （`wmi_etw_live_windows_test.go`）。実際に WMI イベントサブスクリプション
> （filter + `CommandLineEventConsumer` + binding = T1546.003 そのもの）を登録し、
> センサーが `wmi_activity` イベントを出すことを確認して、作ったものを defer で消す。
> **2026-08-04 に windows-latest 上で PASS**（139.92s、5861 を捕捉）。
>
> 実測で**仮定 2 つが訂正された**。`query` は WQL 本文ではなく**フィルタ名**を運び、
> `user` は**空**である。ルール作者がペイロードを読んで推測すれば、どちらも外していた。
>
> 意味するところ: 本ランブックの 4 コレクタも、**VM を手配する代わりに同じ形で
> CI に載せられる可能性が高い**。手順書として残す価値はあるが、「手動でしか
> できない」から始めないこと。手動検証は走らない検証になりやすい。
>
> ⚠️ CI 上で live テストが**黙って skip する**形にしてはならない。skip と PASS は
> ジョブ要約で見分けが付かず、「未検証だが動いていると仮定」の状態にそのまま戻る。
> `wmi_etw_live_windows_test.go` は CI 上では skip せず、セッションを開けないこと
> 自体を失敗として扱う。ジョブは `-v` で走らせ、走った証拠を残すこと。

対象コレクタ:

| テレメトリ | プロバイダ / 仕組み | コレクタ |
|-----------|--------------------|---------|
| プロセス   | Kernel-Process ETW (`{22fb2cd6-…}`) | `NewETWProcessCollector` |
| ネットワーク | Kernel-Network ETW (`{7dd42a49-…}`) | `NewWindowsNetworkCollector` |
| DNS       | DNS-Client ETW (`{1c95126e-…}`) | `NewWindowsDNSCollector` |
| 認証       | Security ログ EvtSubscribe (4624/4625/…) | `NewWindowsAuthCollector` |

> **2026-08-01 追記 — 本ランブックの対象4コレクタは引き続き `EDR_AGENT_ETW=1` の opt-in。**
> ただし #509 で**別の5センサが既定ONになった**ので混同しないこと:
>
> | | 対象 | 既定 | 制御 |
> |---|---|---|---|
> | **加算的センサ5種** | リモートスレッド注入 / イメージロード / PowerShell ScriptBlock / PS Module 4103 / 名前付きパイプ | **ON** | `EDR_AGENT_ETW_SENSORS=0` で opt-out |
> | 本ランブックの4コレクタ＋レジストリ収集器 | プロセス / ネットワーク / DNS / 認証 / レジストリ | OFF | `EDR_AGENT_ETW=1` で opt-in |
>
> 前者を既定ONにできたのは**純粋に加算的**（各々が対応技術の唯一のセンサで、ETWセッションを開けなければ no-op に劣化する）だから。後者は**成熟した既存パスを置換/差し替える**（レジストリは `RegNotifyChangeKeyValue`、auth/dns/network は稼働中の非ETW収集器）ため opt-in を維持している。
> `EDR_AGENT_ETW=1` は従来どおり**全部**を force-on するので、本ランブックの手順は不変。

---

## 前提

- 実 Windows ホスト（VM 可）。**管理者権限が必須**。
  - ETW リアルタイムセッション = `SeSystemProfilePrivilege` 相当
  - Security ログ購読 = 管理者（または `Event Log Readers` グループ）
- Go 1.2x（ビルドのみ。配布バイナリ運用なら不要）。

---

## 手順

### 1. 検証ハーネスをビルド

開発機（どの OS でも可）で Windows 向けにクロスビルド:

```bash
cd agent
GOOS=windows GOARCH=amd64 go build -o etw-verify.exe ./cmd/etw-verify
```

`etw-verify.exe` を対象 Windows ホストへ転送する。

### 2. 管理者 PowerShell で実行

```powershell
# 「管理者として実行」した PowerShell / cmd で
.\etw-verify.exe
```

ハーネスは自動で `EDR_AGENT_ETW=1` を設定し、各コレクタを起動したうえで
既知の活動を自分で発生させる:

- **プロセス**: `cmd.exe /c ping -n 2 127.0.0.1` を起動し、その PID の create イベントを待つ
- **ネットワーク**: `1.1.1.1:443` へ TCP 接続し、その宛先への connect イベントを待つ
- **DNS**: 一意な `etwverify-<nanos>.example.com` を名前解決し、その query イベントを待つ
- **認証**: 自動生成できないため **情報表示**。監視中に手動でログオンを発生させる
  （別ユーザで `runas`、ロック→アンロック、RDP 再接続など）

### 3. 結果の読み方

```
[PASS] process   captured create for PID 1234 (ping.exe)
[PASS] network   captured outbound connection to 1.1.1.1:443 (pid 5678)
[PASS] dns       captured query "etwverify-...example.com" (type A, pid 5678)
[INFO] auth      no auth event observed (trigger a logon during the watch window to verify)

0 auto-verifiable source(s) failed.
```

- `PASS` … そのテレメトリが実機でイベントを出した（= 検証完了）
- `FAIL` … イベントが届かなかった。下記トラブルシュートへ
- `INFO` … 認証など、合否判定しない情報行（監視中にログオンを起こせば `PASS` になる）

終了コード: 自動検証 3 種（process/network/dns）が全て `PASS` なら 0、
1 つでも `FAIL` なら 1。

### 4. 認証だけ別途確認したい場合

ハーネスの認証監視ウィンドウ（既定 12 秒）の間に、別の管理者 PowerShell から:

```powershell
runas /user:DOMAIN\someuser cmd   # 4624(成功) / 4625(失敗) を誘発
```

または画面ロック（Win+L）→ サインインし直すと 4624 が出る。
`[INFO] auth` 行が `[PASS] auth captured auth event: …` に変われば配線 OK。

---

## トラブルシュート

| 症状 | 原因 / 対処 |
|------|------------|
| `collector Start failed: Access is denied` | 管理者で実行していない。昇格プロンプトで再実行 |
| process だけ FAIL | ETW セッション競合（同名セッション残存）。`logman query -ets` で確認し `logman stop <name> -ets` |
| network/dns が FAIL だが offline | `[INFO] … offline?` の場合は外部到達性なし。到達可能な環境で再実行 |
| 全部 FAIL かつ即座に戻る | `EDR_AGENT_ETW` が無効化されていないか（ハーネスは強制設定するが、ラッパー実行時は環境を確認） |
| auth が常に INFO | 監視窓の間にログオンを起こしていない。手順 4 を実施 |

---

## 本番エージェントでの有効化

ハーネスはあくまで QA ツール（エンドポイントには配布しない）。
実エージェントで同じ ETW 経路を使うには、エージェント側に環境変数を設定する:

```
EDR_AGENT_ETW=1
```

未設定時は従来のポーリング経路にフォールバックする（後方互換）。
opt-in の段階的有効化方針は `docs/技術的負債と改善計画.md`（P4 章）を参照。

---

## CreateRemoteThread 注入検知の実機 E2E 検証（2026-07-13/14）

PR#445 の `create_remote_thread` センサー（Kernel-Process `THREAD` keyword `0x2`、ThreadStart id 3、
ヘッダPID≠ペイロードProcessID かつ生成元が `%SystemRoot%` 外 = リモートスレッド）を Windows 実機で
「emit → 取込 → **ルール発火**」まで通す手順。上の QA ハーネスと違い、**本番エージェント + 本番サーバ**で行う。

### 手順
1. **本番エージェントを opt-in 起動**（サービス `EDRAgent` が停止中なら手動で）:
   ```powershell
   $env:EDR_AGENT_ETW = "1"
   & "C:\Program Files\EDR Agent\edr-agent.exe" --config "C:\Program Files\EDR Agent\config.toml"
   ```
   起動ログに `ETWリモートスレッド監視を開始しました (Microsoft-Windows-Kernel-Process, THREAD)` が出れば OK。
   ★初回に `Exception` で落ちる事例は、直前のクラッシュ・インスタンスが残した ETW セッション競合。`logman query -ets | Select-String EDR-Agent` で確認し `logman stop <name> -ets` してから再起動。

2. **Defender セーフな注入 PoC**（実機は Defender 実時間保護 ON でもブロックされない最小フットプリント）。
   Defender/例外設定は変更しない（セキュリティ設定変更は不可）。`VirtualAllocEx`/`WriteProcessMemory` を使わず、
   標的（notepad）内の既存モジュール関数 `ExitThread` を指す remote thread を1本張るだけにする:
   ```c
   // rtinject.c — C:\Users\<u>\rtpoc\ 配下（ルールの SourceImage|startswith 'C:\Users\' に整合）
   CreateProcessA("C:\\Windows\\System32\\notepad.exe", …, &pi);   // 標的（TargetImage endswith \notepad.exe）
   Sleep(1500);
   HANDLE hT = CreateRemoteThread(pi.hProcess, NULL, 0,
       (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread"),
       NULL, 0, NULL);                                              // remote thread（notepad は無害に終了）
   ```
   `cl.exe`（VS2022 の vcvars64 経由）でコンパイルして実行。`remote thread created target_pid=… tid=…` が出れば注入成立。

3. **サーバ側の確認は SSH + DB**（RDP 不要）。`create_remote_thread` イベントの取込と `source_image/target_image` を確認:
   ```bash
   docker exec kizashi-postgres psql -U edr -d edrplatform -t -A -c \
     "SELECT time,event_type,rule_matches,alert_id FROM events \
      WHERE agent_id='<id>' AND event_type='create_remote_thread' ORDER BY time DESC LIMIT 3;"
   ```
   `raw_data` に `{source_image, target_image, source_pid, target_pid, start_unbacked, creator_is_target_parent}` が入る。

4. **デプロイ済みサーバに依存せず「発火するはず」を確定**する場合は Linux docker でオフライン再現（§7 検証法, `検知ルールの二重管理とデプロイ.md`）。合成イベントをライブ検証したい場合は `nats-box` で直接投入:
   ```bash
   docker run --rm --network edr-platform_kizashi-internal natsio/nats-box \
     nats pub -s nats://nats-1:4222 events.<agent>.create_remote_thread \
     '{"agent_id":"<id>","platform":"windows","type":"create_remote_thread","data":{"source_image":"C:\\Users\\x\\p.exe","target_image":"C:\\Windows\\System32\\notepad.exe","source_pid":9001,"target_pid":9002}}'
   ```

### 2026-07 検証の結果と重要な注意
- ✅ **エージェント ETW センサーは実機で正常動作**（正しい `create_remote_thread` を emit・取込）。
- ❌ **サーバ側アラートは 0 発火**。原因は本センサー/ルールではなく、**検知パイプラインの結線バグ（2パイプライン×3テーブル分裂）+ detection-engine の慢性ラグ**。
  対象ルール「Process Hollowing」が居る `rules` テーブルを、追いつき済の AlertPipeline が読まないため。
  詳細と修正方針＝[検知ルールの二重管理とデプロイ.md](検知ルールの二重管理とデプロイ.md) §7。
- ★ルール「Process Hollowing via Suspicious Executable」は **severity 9 + `auto_isolate=true`**、サーバ
  `AUTO_ISOLATE_MIN_SEVERITY=9` ゆえ**発火すれば箱が自動隔離される**（RDP 断の可能性）。復旧は管理 API の
  unisolate（[技術的負債と改善計画.md] の隔離節参照）で行う。検証時は隔離の可否を事前に合意しておく。
