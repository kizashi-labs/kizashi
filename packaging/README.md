# エージェントのOSパッケージ

`.deb` / `.rpm` / `.msi` / `.pkg` の生成物と、その署名経路。
生成は [`.github/workflows/package.yml`](../.github/workflows/package.yml)。

## なぜ必要か

これまでの導入経路は `curl … | bash` と対話的な `install.ps1` の2つだけだった。

Intune・SCCM/ConfigMgr・グループポリシー・Jamf・Ansible の apt/yum モジュール・
各種パッチ管理製品——**企業が既に持っている配布基盤はどれも署名済みパッケージを配る**
ものであって、「環境変数を設定して root でシェルスクリプトを実行する」は配れない。

フリート展開が止まるのはエージェントの能力ではなくここなので、能力を足す前に塞ぐ。

## 生成物

| 形式 | 対象 | 生成 |
|---|---|---|
| `.deb` / `.rpm` | linux amd64 / arm64 | nfpm（1つの YAML から両方） |
| `.msi` | windows x64 | WiX v5 |
| `.pkg` | macOS x86_64 / arm64 | pkgbuild + productsign |

いずれも **`deploy/install/install.sh` と同じレイアウト**を使う。スクリプト導入済みの
ホストとパッケージ導入のホストが混在しても、設定とダッシュボード上の識別子が食い違わない。

```
/usr/local/bin/{edr-agent,edr-watchdog}     (Windows: C:\ProgramData\EDRAgent\bin\)
/etc/edr/agent.toml                          (Windows: C:\ProgramData\EDRAgent\agent.toml)
/var/log/edr, /var/lib/edr
```

## サーバURLの渡し方

パッケージはビルド時にサーバURLもエージェントIDも知り得ない。事前投入方式にした。

**Linux / macOS** — パッケージ導入の前に置く:

```sh
# /etc/edr/enroll.env
SERVER_URL=https://edr.example.com
ENROLLMENT_TOKEN=<token>     # 任意
```

**Windows** — msiexec のプロパティ:

```
msiexec /i edr-agent-1.2.3-x64.msi /qn SERVERURL="https://edr.example.com"
```

URLが無い場合、**パッケージは入るがサービスは起動しない**。理由をログに出す。
プレースホルダURLで起動させると「active だがどこにも接続していない」エージェントになり、
これは正常な導入と外形が同じで最も気づかれにくい。

## アップグレード時にエージェントIDを再生成しない

設定生成は `edr-agent -write-config` に一本化してあり、**既存ファイルがあれば何もしない**。
3つのパッケージ形式それぞれの言語（MSI のカスタムアクション、shell、pkg スクリプト）で
UUID 生成と TOML 書き出しを書くと必ずずれるので、実装はバイナリ側に1つだけ置いた。

再生成してしまうと、そのホストが**新しい識別子で再登録され**、既存のアラート・
インシデント・タイムラインが孤児になる。`.deb`/`.rpm` では config ファイル指定
（`config|noreplace`）でも二重に守っている。

## アンインストール保護との関係

[アンインストール保護](../docs/アンインストール保護.md) を `uninstall.sh` だけで
強制すると、`apt remove edr-agent` と `msiexec /x` が迂回路として残る。
apt や Intune で管理されたフリートでは、それは例外ではなく**通常の削除経路**。

そのため:

- `.deb`/`.rpm` の `preremove` が `edr-agent -verify-uninstall` を実行し、非ゼロなら削除を中止する
- MSI は `REMOVE="ALL"` 時に `StopServices` の**前**に同じ検証を走らせる（拒否された時点で
  端末は何も変わっていない＝まだ監視されている状態のまま）

`preremove` は `-help` にフラグが載っているかを見てから呼ぶ。この機能より前に作られた
パッケージを削除するときに、未知のフラグで削除不能にしないため。

## 署名

**署名鍵が無くてもビルドは通る。** Windows の EV/OV 証明書も Apple の Developer ID も
調達に数週間かかるので、それを待つ間パッケージが作れないのは困る。ただし
**未署名のものを署名済みとして公開はしない**。

| 対象 | シークレット | 無い場合 |
|---|---|---|
| deb/rpm | `PACKAGE_GPG_PRIVATE_KEY`, `PACKAGE_GPG_PASSPHRASE` | 未署名で生成。apt/yum リポジトリからは配れない（手動導入のみ） |
| msi | `WINDOWS_CODESIGN_PFX`(base64), `WINDOWS_CODESIGN_PASSWORD` | 未署名で生成。SmartScreen が警告し、署名必須ポリシー下では配布不可 |
| pkg | `APPLE_DEVELOPER_ID_P12`, `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_SIGN_IDENTITY`, `APPLE_INSTALLER_IDENTITY`, `APPLE_TEAM_ID`, `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_APP_PASSWORD` | 未署名で生成。既定設定の Mac では Gatekeeper が拒否する |

### 落とし穴

- **Windows は MSI だけでなく中身の .exe も署名する。** MSI だけ署名すると、ディスク上に
  置かれる実行ファイルが未署名のまま残る。WDAC / AppLocker が見るのはそちらで、
  よりによって EDR センサが未署名バイナリであってはならない。
- **macOS の pkg 署名は "Developer ID Installer" 証明書。** バイナリ署名に使う
  "Developer ID Application" とは別物。取り違えるとビルドマシンでは入るのに
  他の全ての Mac で拒否される pkg ができる。
- **`rpm --addsign` は署名に失敗しても exit 0 になることがある。** ワークフローは
  署名後に `rpm -qpi | grep 'Key ID'` で実際に載ったことを確認している。
- **ESF ビルドと eBPF/LSM ビルドはここでは梱包しない。** 前者は Apple の entitlement 承認、
  後者は clang とランナーの BTF が要り、それぞれ専用ワークフローが公開する。
  特に LSM 版を既定の `.deb` にすると、カーネルが対応していないホストに
  「防御版のつもりの無効な sensor」が載る。

## 検証状況（2026-08-10）

CI を使わずローカルで実施済み。手順は再現可能な形で `packaging/test/` に置いてある。

### deb / rpm — 実インストール済み ✅

```bash
packaging/test/install-test.sh both     # Docker 必須
```

`debian:bookworm-slim` と `rockylinux:9` のコンテナで実際に導入・アップグレード・削除まで実行。
**deb 25/25、rpm 24/24 通過**。確認内容は配置・サービスアカウント・初回設定生成・
アップグレードでエージェントIDが変わらないこと・SERVER_URL 未指定時にサービスを起動しないこと、
そして **`apt remove` / `rpm -e` でもアンインストール保護が効くこと**（無し/誤り=拒否、正しい=許可）。

> この検証は実バグを1件見つけている。`/var/log/edr` と `/var/lib/edr` を `type: dir` で
> パッケージ内容として出荷していたため、パッケージマネージャがそれらを所有し、
> postremove が「ログは残す」と表示しながら `apt remove` が削除していた。
> 静的チェックでは見つからない類で、postinstall で作る形に変更済み。

### MSI — ビルドと構造を検証済み ✅

WiX 5.0.2 でビルド成功（20.8 MB）。実インストールはしていないが、管理インストール
（`msiexec /a`）で展開し、MSI テーブルを直接検査した。

| 確認項目 | 結果 |
|---|---|
| 配置 | `CommonAppDataFolder\EDRAgent\bin\{edr-agent,edr-watchdog}.exe` |
| ServiceInstall | `EDRWatchdog` / StartType=2（自動）/ 引数のプロパティ展開OK |
| ServiceControl | Event=163（install時start・both stop・uninstall時削除） |
| `VerifyUninstall` | seq **1899** — `StopServices`(1900) / `DeleteServices`(2000) / `RemoveFiles`(3500) の**前**。拒否時に端末は無変更のまま |
| `ConfigureAgent` | seq **4002** — `InstallFiles`(4000) の後、`StartServices`(5900) の前 |
| カスタムアクション型 | VerifyUninstall=3073（deferred / no-impersonate / 戻り値チェック）、ConfigureAgent=3137（同＋戻り値無視） |

再現するには WiX が要る:

```bash
dotnet tool install --global wix --version 5.0.2
wix extension add -g WixToolset.Util.wixext/5.0.2
```

### macOS pkg — 未検証 ⏳

`pkgbuild` / `productsign` は macOS 専用で、Mac 実機か macOS ランナーが要る。
署名に必要な Apple の entitlement 承認も未取得のため、いずれにせよ現時点では配布できない。
