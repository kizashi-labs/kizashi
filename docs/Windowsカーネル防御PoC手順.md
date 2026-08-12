# Windows カーネル実行前防御 PoC 手順（プロセス生成コールバックドライバ）

**対象**: [design/Windows・macOS実行前防御と改ざん防止設計.md](design/Windows・macOS実行前防御と改ざん防止設計.md) の Windows W0〜W3。
**目的**: `PsSetCreateProcessNotifyRoutineEx` のコールバックで、ブロックリストに一致する実行ファイルの
プロセス生成を `STATUS_ACCESS_DENIED` で拒否できることを**テストモード Windows VM で実機実証**する。
Linux eBPF LSM（exec 拒否）の Windows 版。

成果物:
- ドライバ: `agent/driver/windows/prevention/prevention.c` / `prevention.h`
- ユーザーランド PoC ハーネス: `agent/cmd/winprev-poc`（IOCTL でルール投入＋判定取得）

> ✅ **実機実証済み（2026-06-20, Windows Server 2022 EC2, テストモード）**: WDK でビルド成立 →
> テスト署名 → ロード（`sc start` = RUNNING）→ `winprev-poc` で **audit（許可＋記録, enforced=0）/
> enforce（プロセス生成を `STATUS_ACCESS_DENIED` で拒否, enforced=1）** をいずれも確認。下記 §1 に
> 実証済みビルドレシピ、§1.5 に当時踏んだ落とし穴と対処を記載。
>
> ⚠️ カーネルバグは BSOD を起こすため、**使い捨て VM / スナップショット取得済みの専用 EC2 限定**で
> ロードすること（本番端末・実機で直接ロードしない）。ドライバは `start= demand`（手動起動）で登録し、
> 万一の不具合でもブートループを避ける。

---

## 0. 必要環境（ユーザー側）

- **使い捨て Windows 10/11 VM**（スナップショット推奨。BSOD 復旧用）。**ビルドは別マシンでも可だがロードは必ず VM**。
- 管理者権限。

---

## 1. WDK / Visual Studio の導入（未導入の場合）

ドライバのビルドには **VS + WDK + WDK の VS 拡張** が要る。**3つのバージョンを一致**させること
（SDK と WDK は同一ビルド番号で揃える。例 10.0.26100）。

1. **Visual Studio 2022（Community 可）** をインストールし、ワークロード
   **「C++ によるデスクトップ開発」** を選択。これで MSVC ツールチェーン + 対応 **Windows SDK** が入る。
2. **Windows Driver Kit (WDK)** を Microsoft 配布ページから入れる
   （`https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk`）。
   インストーラ末尾で **「WDK Visual Studio extension」** を必ず有効化（Driver プロジェクトテンプレートと
   `ConfigurationType=Driver` ビルドサポートが入る）。
3. 確認: VS の「新しいプロジェクト」に **"Empty WDM Driver"** テンプレートが出れば導入成功。
   - SDK と WDK のバージョン不一致だと WDK 拡張が VS に出ないことがある → 同一番号で入れ直す。
   - コマンドラインだけで完結させたい場合は **EWDK（Enterprise WDK、自己完結 zip/ISO）** を展開し
     `LaunchBuildEnv.cmd` で msbuild 環境を起動する手もある（ただし下記レシピで VS から直接ビルドできた
     ので EWDK は不要だった）。

## 1.5 実証済みビルドレシピと落とし穴（2026-06-20, Win Server 2022 EC2）

実機で踏んだ手順と対処（**VS 2026 標準 + WDK 26100** の組み合わせで詰まった）:

1. **VS のバージョンに注意**。新規 EC2 に最初から入っていたのは **Visual Studio 2026（v18）**で、
   WDK 26100 同梱の VSIX は v18 に入らず「`extension has a lower version than required by Visual Studio`」で
   失敗。→ **Visual Studio 2022 Community を別途インストール**（`aka.ms/vs/17/release/vs_community.exe`、
   ワークロード「C++ によるデスクトップ開発」）。WDK 26100 は VS 2022 とペア（最新 WDK 28000 は VS 2026 用）。
2. **WDK の VS 連携は VS Installer の「個別のコンポーネント」で入れる**（VS 17.11 以降、WDK VSIX は
   個別コンポーネント化）。スタンドアロンの `WDK.vsix` を手動実行しても上記理由で失敗する。正しくは
   **VS Installer → VS 2022 を変更 → 個別のコンポーネント → `Windows Driver Kit` をチェック → 変更**。
   これで「Empty WDM Driver」テンプレートと `WindowsKernelModeDriver10.0` ツールセットが入る。
3. **Spectre 緩和ライブラリが必須**（`error MSB8040`）。同じく個別コンポーネントで
   **「MSVC v143 - VS 2022 C++ x64/x86 Spectre 緩和ライブラリ (最新)」** を追加。
4. **ビルド時の自動テスト署名を切る**。WDK の TestSign ターゲットが `signtool ... /sha1`（`/fd` 無し）を
   呼び、26100 の新しい signtool が `/fd` 必須で拒否 → 未署名 `.sys` を削除してビルド失敗。→ `.vcxproj` に
   **`<SignMode>Off</SignMode>`** を入れてビルド時署名を無効化し、署名は §3 で自前証明書で手動実行する。
5. **テンプレート不要の再現ビルド**: リポジトリの
   [`agent/driver/windows/prevention/prevention.vcxproj`](../agent/driver/windows/prevention/prevention.vcxproj)
   をソースと同フォルダに置き、Developer 環境で msbuild するのが最短:
   ```powershell
   Import-Module 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
   Enter-VsDevShell -VsInstallPath 'C:\Program Files\Microsoft Visual Studio\2022\Community' -DevCmdArguments '-arch=x64'
   cd <prevention.vcxproj のフォルダ>
   msbuild prevention.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
   → `x64\Release\prevention.sys`（`Build succeeded`、0 Error）。

---

## 2. ドライバのビルド（`prevention.sys`）

**確実なのは VS テンプレート方式**（正しい `.vcxproj` が自動生成される。手書き .vcxproj は版依存で壊れやすい）:

1. VS → 新しいプロジェクト → **「Empty WDM Driver」** を作成（例 名前 `prevention`）。
2. 生成プロジェクトに `agent/driver/windows/prevention/prevention.c` と `prevention.h` を**追加**
   （既存項目の追加）。テンプレートが作った雛 .c があれば削除。
3. 構成 **x64 / Release**。
4. **プロジェクト プロパティ → Linker → Command Line に `/INTEGRITYCHECK` を追加**
   （`PsSetCreateProcessNotifyRoutineEx` 登録の必須要件。無いと登録が `STATUS_ACCESS_DENIED`）。
5. ビルド → `x64\Release\prevention\prevention.sys` が出力。

> ビルドエラーになったら多くは SDK/WDK バージョン不一致か `/INTEGRITYCHECK` 漏れ。プロジェクトの
> ターゲット SDK バージョンを導入済みの番号に合わせる。

## 3. テスト署名 + テストモード

実証済み手順（管理者 PowerShell。`New-SelfSignedCertificate` + signtool `/fd sha256`）:
```powershell
$sys = '<...>\x64\Release\prevention.sys'
# テスト用コード署名証明書を作成
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=KizashiTest' `
        -CertStoreLocation Cert:\CurrentUser\My -KeySpec Signature
# 署名（/fd sha256 必須。無いと "No file digest algorithm specified" で失敗）
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
& $signtool sign /v /fd sha256 /s My /n 'KizashiTest' $sys
# 署名検証用にテスト証明書を信頼ストアへ（Root + TrustedPublisher）
$cer = '<...>\KizashiTest.cer'
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
& $signtool verify /v /pa $sys     # "Successfully verified" を確認
# テストモード有効化（再起動が必要。★EC2 は再起動前に必ず AMI スナップショット取得）
bcdedit /set testsigning on
Restart-Computer
```
再起動後、デスクトップ右下に「テスト モード」と表示されれば testsigning 有効。

## 4. ドライバのインストール & ロード

```powershell
# start= demand(手動起動) で登録。万一の不具合でも自動起動のブートループを避ける
sc.exe create KizashiPrevention type= kernel start= demand binPath= C:\path\to\prevention.sys
sc.exe start KizashiPrevention
sc.exe query KizashiPrevention   # STATE: 4 RUNNING を確認
```
（アンロード: `sc.exe stop KizashiPrevention` → `sc.exe delete KizashiPrevention`）
- `sc start` が **577** = 署名/テストモード未反映、**1275/ACCESS_DENIED** = `/INTEGRITYCHECK` か署名の問題。

## 5. ハーネスのビルド & 実証

ハーネス（Go）は普通にビルドできる:
```powershell
cd agent
go build -o winprev-poc.exe ./cmd/winprev-poc
```

> agent モジュールを持ち込めない検証ホスト（例: 単発の EC2）では、`main_windows.go` は
> `golang.org/x/sys/windows` だけに依存するので**最小モジュールで単独ビルド**できる:
> `go.mod`（`module winprev-poc` / `go 1.21` のみ）と `main_windows.go` を 1 フォルダに置き、
> `go mod tidy && go build -o winprev-poc.exe .`。★PowerShell 5.1 で `go.mod` を書くときは
> `Set-Content -Encoding ascii`（`-Encoding utf8` は BOM 付与で `unexpected input character '﻿'`）。

ブロック対象は使い捨てバイナリにする（システム必須 exe を enforce で止めない）:
```powershell
copy C:\Windows\System32\whoami.exe %TEMP%\blockme.exe
```

### 4-1. audit（許可しつつ記録）

別シェルでハーネスを起動（ブロックは suffix マッチ。`\blockme.exe` で末尾一致）:
```powershell
.\winprev-poc.exe -block \blockme.exe
```
別シェルで対象を実行:
```powershell
%TEMP%\blockme.exe    # 起動は「成功」する（audit は許可）
```
ハーネス側に `decision: pid=... blocked=1 enforced=0 path=...\blockme.exe`。

### 4-2. enforce（実際に拒否）

```powershell
.\winprev-poc.exe -block \blockme.exe -enforce
```
別シェルで:
```powershell
%TEMP%\blockme.exe    # → アクセス拒否で起動失敗するはず
```
ハーネス側に `decision: ... enforced=1`。プロセス生成が `STATUS_ACCESS_DENIED` で拒否されれば **W0 成功**
＝Windows でカーネルレベルの実行前防御が動作することの実機実証。

---

## 6. トラブルシュート

| 症状 | 原因/対処 |
|---|---|
| `sc start` が 577 / 署名エラー | テストモード未有効 or 証明書未信頼。§3 を再確認、再起動 |
| ドライバロード時にハング/BSOD | カーネルバグ。VM スナップショットから復旧。`prevention.c` を見直し（IRQL・ロック・バッファ長） |
| `PsSetCreateProcessNotifyRoutineEx` が失敗 | `/INTEGRITYCHECK` リンク無し。ビルド設定を確認 |
| `open \\.\KizashiPrevention failed` | ドライバ未ロード（`sc query`）、またはシンボリックリンク未作成 |
| enforce でも止まらない | suffix マッチ不一致（ImageFileName は NT パス）。`-block` の末尾文字列を実パスの末尾に合わせる。NT→DOS 正規化は本実装の改良点（Linux #219 と同型） |

---

## 7. 既知の制約 / 次段（設計書 W1〜W5）

- **PoC の matching は NT パスの suffix 一致**。本実装では `process_block_rules` の絶対パス/ハッシュに対し
  NT→DOS 正規化した厳密照合へ（Linux で踏んだパス正規化の Windows 版）。
- 本番化には **EV 証明書 + WHQL/Attestation 署名**（テスト署名は本番端末で不可）。
- agent への統合: ユーザーランド agent（`process_monitor` 相当）が `process_block_rules` を取得して
  IOCTL でドライバへ配信、判定を `process_block` イベントで申告（Linux の prevention_linux.go と同じ役割）。
- 改ざん防止（W4）: PPL + ELAM。
- fail-open 既定・enforce opt-in・audit→enforce 段階は Linux と同じ思想（`PREV_MODE_*` + global enforce）。

## 関連
- 設計: [design/Windows・macOS実行前防御と改ざん防止設計.md](design/Windows・macOS実行前防御と改ざん防止設計.md)
- Linux 版（実証済み）: [design/Linux改ざん防止と実行前防御設計.md](design/Linux改ざん防止と実行前防御設計.md) / [Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md)
