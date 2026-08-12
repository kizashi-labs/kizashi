# ATT&CK 検知カバレッジ監査

**目的**: 現行の検知ルール全体を MITRE ATT&CK Enterprise の全14戦術にマップし、被覆ゼロ／希薄な領域を可視化して、次にどこを埋めるべきかを**当てずっぽうでなくデータで**決める。

**対象ソース**（2026-08-03 更新）:
- api ビルトイン Sigma: `server/internal/detection/sigma_builtins.go`（**300ルール**／被覆220 technique ID）
- DB ルール / シーケンス: `server/migrations/*.sql`（バースト・ランサム・キルチェーン等、被覆214 technique ID）
- **ランタイム・ステートフル検知（detection エンジン内、2026-07-20 拡充）**: 単発イベントでは見えない
  レート/ファンアウト現象を窓集約で検知する `*Scorer`/`*Detector` 群。`netScan`(T1046) /
  `dnsAgg`(T1071.004) / `beacon`(C2周期) に加え、`discovery`(探索バースト) / `authAttack`(T1110/T1110.003) /
  `fileBurst`(T1486) / `lateralFanout`(T1021) / `exfilVol`(T1048) / `c2fusion`(TI+周期性+希少性の多信号融合,
  Ph1-3) / `RansomwareCorrelator`(復旧妨害+防御改ざん+ACL付与の複合前兆相関) 等。いずれも `matches` 経由で
  `KillChainScorer` 相関へ自動供給。詳細＝
  [検知率向上_20260720_サマリ_ランタイム相関と到達性ハードニング.md](検知率向上_20260720_サマリ_ランタイム相関と到達性ハードニング.md)、
  [検知率向上_20260715_...](検知率向上_20260715_Windows横展開深化とクラウド永続化とランサム複合相関.md)。

**規模**: api/DB合算・重複排除後 **265 technique ID**（2026-08-03 時点、下記再現コマンドで実測・再計測）。
builtin は 79→300 ルールに増加（うちPR #447で44ルール追加）。★従来「115 technique ID」のまま長期間
更新されていなかった（ルールは79→160→300と増え続けていたのに規模の記載だけ据え置かれていた）ため、
本ドキュメント自身の記載鮮度が「監査ドキュメントの記載漏れ」問題（本文中で何度も指摘している既知パターン）
の一例になっていた。再発防止のため、以後は大きな検知バッチ完了時に再現コマンドで再計測すること。

> ⚠️ **2026-08-02 追記 — 本文書の「被覆」は 2026-08-02 まで一部が名目値だった**。
> ビルトインSigmaを本番で評価する唯一の経路（`AlertPipeline`）が **`process`/`network`/`file`/`registry` の
> 4イベント型しか購読していなかった**ため、`script` / `image_load` / `dns` / `auth` /
> `create_remote_thread` / `credential_access` / `device_event` / `pipe_created` を入力とするルールは
> **ルールが存在してもエンジンに到達していなかった**。とくに:
> - **T1574.002（DLLサイドロード）** — `image_load` 依存。§4 Persistence で被覆済みと記載していたが不発だった
> - **T1059.001 / T1027（難読化解除後のスクリプト本文）** — `script` 依存。
>   コマンドライン型ルールが取りこぼす fileless PowerShell を埋める役割のルールが不発だった
>
> 購読リストを `eventTypeCategories` からの導出に変えて根治済み
> （[技術的負債と改善計画.md P5-10](技術的負債と改善計画.md)）。本文書の原則
> 「被覆＝ルールの存在ではなくテレメトリ到達性で判定する」は、**評価経路の到達性まで含めて**
> 適用する必要がある——センサーが emit していても、購読フィルタで落ちていれば同じく不被覆である。

## 再現コマンド

```sh
# api ビルトインの被覆 technique
grep -oiE 'attack\.t[0-9]{4}(\.[0-9]{3})?' server/internal/detection/sigma_builtins.go | sed 's/attack\.//' | tr a-z A-Z | sort -u
# DB ルール（migration）の被覆 technique
grep -rhoiE 'T[0-9]{4}(\.[0-9]{3})?' server/migrations/*.sql | tr a-z A-Z | sort -u
```

`server/internal/detection/sigma_builtins_health_test.go` の `TestBuiltinSigmaPrimaryTechnique` 系がタグの健全性をガードしているため、抽出されるタグは信頼できる（死蔵タグ無し）。

---

## 戦術別カバレッジ・マトリクス

凡例: ✅厚い / 🟡薄い / 🔴ほぼ無し / ⚪EDR対象外（pre-compromise）

### 1. Reconnaissance / 2. Resource Development ⚪
外部偵察・インフラ構築は pre-compromise でエンドポイント観測不可。**EDR対象外**（被覆ゼロは想定どおり、ギャップではない）。

### 3. Initial Access 🟡
- 被覆: T1566.001(マクロ→子プロセス), T1078(有効アカウント), T1505.003(Web Shell)
- ★**リムーバブルデバイス検知の配線（#506, 2026-07-20）**: **T1091**(リムーバブルメディア経由の感染拡大), **T1200**(ハードウェア追加), **T1052.001**(USB経由の持ち出し) を追加。エージェントの `device_event` 収集器は実装済みだったが promote 欠落でサイレント破棄されていた（`typedFindings` で接続を検知、storage=sev5/usb=sev3、input/network は無発火）。詳細は [検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md](検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md)。
- 穴: T1190(公開アプリ攻撃=一部Web Shellで), T1133(外部リモートサービス)
- 評価: EDRで取りにくい領域。リムーバブルメディア(T1091/T1200/T1052)は device_event 配線で被覆。残穴は公開アプリ攻撃・外部リモートサービス。

### 4. Execution ✅
- 被覆: T1059(.001/.004/.005/.007), T1047(WMIC), T1053(.003/.005), T1569(サービス), T1218.*(LOLBin多数), T1204(temp実行)
- 穴: T1106(ネイティブAPI直叩き), T1559.001(COM), T1129(共有モジュール)
- 評価: 厚い。

### 5. Persistence 🟡
- 被覆: T1547.001(Run), T1547.004(Winlogon), T1053.*, T1543(.003/.004 サービス), T1546.003(WMI購読), T1546.012(IFEO), T1505.003(WebShell), T1136(.001/.002 アカウント), T1098(.004 SSH鍵), T1574.002(DLLサイドロード)
- ★**Linux 永続化を FIM file_event で拡充（migration 311 / #426, 2026-07-07）**: **T1546.004**(.bashrc/.profile/.zshrc/profile.d シェル初期化), **T1574.006**(/etc/ld.so.preload 動的リンカ preload ハイジャック), **T1037.004**(/etc/rc.local ブート永続化), **T1053.003**(cron ドロップインへのファイル作成) を追加。センサーは #423 の FIM /home 監視。ld.so.preload(sev7)/rc.local(sev6) は実 endpoint でライブ発火実証済（[results/live-20260707-linux-persistence-fim.md](results/live-20260707-linux-persistence-fim.md)）。
- 🔴**穴（高価値・残）**: **T1037.001–.003(Windows ログオンスクリプト等)**, **T1197(BITS Jobs永続化)**, **T1546.008(スティッキーキー/アクセシビリティ)**, **T1546.015(COMハイジャック)**, **T1546.001(AppInit)**, T1574.001(DLL探索順序), T1554(クライアントバイナリ汚染)
- 評価: Linux のファイル系永続化(shell-rc / ld.so.preload / rc.local / cron / authorized_keys)は FIM 拡張で被覆。残穴は Windows の T1546 サブ群・アクセシビリティ系・BITS。

### 6. Privilege Escalation 🟡
- 被覆: T1068(Pwnkit/exploit), T1055(.001/.012 注入), T1543.003, T1548.002(UACバイパス), T1166(SUID), **T1134**(アクセストークン操作), T1574.*
- ✅**T1134(アクセストークン操作)＝「最大の穴」は既に実装済み・2026-07-09 に回帰テストで固定**: `runas /netonly`/`Invoke-TokenManipulation`/`getsystem`/`incognito`/`make_token`/`DuplicateTokenEx` 等を `sigma_builtins.go` で検知。`attack_coverage_test.go` に発火テストが無かったため単一イベント被覆テストを追加して固定。
- 🔴**残る穴**: T1484(ドメインポリシ改変), T1055(.002/.003/.004 他注入手法), T1547.006(カーネルモジュール/Linux)
- 評価: 最大の穴だった T1134 を被覆済み。残は GPO 改変・他注入手法・Linux カーネルモジュール。

### 7. Defense Evasion ✅（古典穴も被覆済み・回帰テストで固定）
- 被覆: T1027, T1070(.001/.004/**.006**), T1112, **T1140（2026-08-02 に certutil ローカル復号を独立ルール化。従来は T1105 のダウンロード規則が兼務しており、オフライン復号が「for File Download」として鳴っていた）**, T1218.*(10サブ), T1220, T1216.001, T1222(.001/.002), **T1036.003**, T1548.002, T1553.004, T1562(.001/**.002**/.004/.006), T1564(.001/**.003**/**.004**), T1574.*, T1055.*, T1127.001, T1090.003
- ✅**古典穴は既に実装済み（docが陳腐化していた）＝2026-07-09 に回帰テストで固定**: **T1036.003**(システム正規名を非System32パスから実行=`not legit`否定演算子)/**T1564.003**(隠しウィンドウ `-WindowStyle Hidden`/`-w hidden`)/**T1564.004**(NTFS ADS `-Stream`/`::$DATA`)/**T1070.006**(タイムストンプ timestomp/`.LastWriteTime =`/SetFileTime)/**T1562.002**(イベントログ無効化 `auditpol /success:disable`/`wevtutil sl /e:false`/`Stop-Service EventLog`)。いずれも `sigma_builtins.go` に存在したが `attack_coverage_test.go` に発火テストが無く**サイレント破損しうる状態**だった → 5技の単一イベント被覆テストを追加しハーネスに固定。
- 🔴**残る穴**: T1006(直接ボリュームアクセス)
- ✅**T1620(リフレクティブコードロード)は 2026-08-01 に解消**: メモリ/インジェクションスキャナ（RWX・非バック実行領域＋メモリ内YARA）を既定ON化（#511, opt-out=`EDR_MEMORY_SCAN=0`）。従来 `EDR_MEMORY_SCAN=1` の opt-in で既定OFF＝**全端末で死蔵**だった。Windows実機で負荷検証済み（60秒周期の占有率 0.94-0.99%、定常イベント量0件/日/台）。詳細＝[検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md](検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md) §2.1
- 評価: LOLBin系に加えマスカレード・ADS・タイムストンプ・ログ無効化の古典も被覆済み。回帰テスト固定でサイレント破損を防止。T1620 も既定ONで恒常監視化。
### 7. Defense Evasion ✅（ただし古典的穴あり）
- 被覆: T1027, T1070(.001/.004), T1112, T1140, T1218.*(10サブ), T1220, T1216.001, T1222(.001/.002), T1548.002, T1553.004, T1562(.001/.004/.006), T1564.001, T1574.*, T1055.*, T1127.001, T1090.003
- 🔴**穴（高価値・古典的）**: **T1036(.003/.005 マスカレード=システム正規名へのリネーム)**, **T1564.003(隠しウィンドウ powershell -windowstyle hidden)**, **T1564.004(NTFS ADS)**, **T1070.006(タイムストンプ)**, **T1562.002(イベントログ無効化 auditpol/wevtutil)**, T1006(直接ボリュームアクセス)
- **T1620(リフレクティブコードロード)**: メモリ/インジェクションスキャナ（RWX・非バック実行領域＋メモリ内YARA）で検知可能。従来 `EDR_MEMORY_SCAN=1` の opt-in で既定OFF→死蔵だったが、**2026-08-01 に既定ON化(opt-out)を #511 でマージ済み**（Windows実機で負荷検証、finding 抑制機構を併せて追加）。
- ✅**Linux の memfd 経路は別機構。誤ゲートで死角だったが解消（2026-07-26 判明 → 2026-08-01 修正）**: 上記メモリ
  スキャナは Windows 実機で検証された RWX/非バック領域スキャンで、**Linux のディスクレス実行を捕捉する経路とは別**。
  Linux 側は fileless センサ（`ebpf/fileless_monitor.bpf.c`、tracepoint `sys_enter_execveat` の `AT_EMPTY_PATH`
  ＝memfd/fd からの実行 + `sys_enter_memfd_create`）が担う。[PR#390](https://github.com/kizashi-labs/kizashi/pull/390)
  で実装・実機実証済みにもかかわらず consumer `fileless_runner.go` が **`ebpf && prevention` 誤ゲート**のため
  標準 Linux 出荷ビルド（`-tags ebpf`）では**デッドコード＝発火しなかった**。ルール不足ではなく**配布ゲートの誤り**で、
  タグを `ebpf` へ是正して解消。
  詳細＝[検知率向上_20260726_prevention誤ゲートによるeBPF死角.md](検知率向上_20260726_prevention誤ゲートによるeBPF死角.md) §5。
- 評価: LOLBin系は厚いが、マスカレード・ADS・タイムストンプ・ログ無効化の古典が抜け。T1620 は Windows がセンサ既定ON化、Linux が誤ゲート是正でいずれも解消。
- **T1112 深化(2026-07-03, [PR#373](https://github.com/kizashi-labs/kizashi/pull/373))**: 従来の Run キー限定(`reg add ...CurrentVersion\Run`)に加え、level:low builtin「Registry Modification via reg.exe」で **HKCU/HKLM/HKU への汎用 `reg.exe add`** も `attack.t1112` で Technique 被覆。Windows 能動計測([results/live-20260702-windows-discovery.md](results/live-20260702-windows-discovery.md))で T1112=Technique を実機実証し、ディスカバリ/実行/永続化 13技が **Technique 92.3%→100%**。高価値キー(Run/Defender/UAC/Winlogon)は既存の高 severity ルールが役割分担。

### 8. Credential Access 🟡→✅（深掘りバッチで穴埋め進捗）
- 被覆: T1003(.001/.002/.003/.006/.008), T1110(.001), T1552.001(ファイル内資格), T1555(.003/.004 ブラウザ/資格マネージャ), T1558.003(Kerberoast), T1078, T1550.002(PtH)
- ✅**深掘りバッチ（ビルトインSigma追加）**: **T1003.004**(LSAシークレット=`reg save HKLM\SECURITY`), **T1003.005**(キャッシュドメイン資格=cachedump/gsecdump/`lsadump::cache`), **T1552.004**(秘密鍵窃取=id_rsa/id_dsa/id_ecdsa/id_ed25519/.ppk), **T1557.001**(LLMNR/NBT-NSポイズニング=Responder.py/Inveigh) を追加。`attack_coverage_test.go` の credaccess 単一イベント被覆が **5→9技** に。
- 🔴**残る穴**: **T1556(認証プロセス改変)**, T1552.006(GPP cpassword), T1539(セッションCookie窃取), T1110.003(パスワードスプレー)
- 評価: ダンプ系に加え LSA/キャッシュ・秘密鍵・ネットワーク資格窃取(Responder)を被覆。残は認証プロセス改変・GPP・Cookie。
- ★**T1078(有効アカウント)の LogonType 配線（#510, 2026-07-20）**: 4624/4625 の `logon_type` をエージェント→proto→ingest まで配線。休眠していたオフアワーログインUEBA（`login_hour` 異常）と LogonType ベース Sigma（Network=3 / RemoteInteractive=10 等）を有効化。従来は消費側・supported 宣言はあるのに emit 経路が無かった（reachability ガードの唯一の穴）。
- 🔴**穴（高価値）**: **T1003.004(LSAシークレット)**, **T1003.005(キャッシュドメイン資格)**, **T1552.004(秘密鍵 id_rsa/.pem)**, **T1557(LLMNR/NBT-NSポイズニング Responder/Inveigh)**, **T1556(認証プロセス改変)**, T1552.006(GPP cpassword), T1539(セッションCookie窃取)
- ✅**ランタイム認証攻撃検知(2026-07-20, `authAttack` / PR#486)**: **T1110(ブルートフォース=単一アカウント多数失敗、成功でリセット)** と **T1110.003(パスワードスプレー=単一ソース→多数アカウント失敗)** をリアルタイムに検知。既存 builtin「Multiple Failed Login」が EventID を1件で発火するだけで回数を数えていなかった構造欠陥を是正。稼働サーバでライブ発火実証。
- ✅**ブルートフォース「成功」の検知(2026-08-02, `authAttack` 拡張 / PR #542 由来)**: 上記 `authAttack` は成功時にカウンタを**削除して nil を返す**設計だった。試行(T1110)は鳴るが、**その試行が通った瞬間＝アカウント侵害そのもの(T1110→T1078)はどこにも記録されない**。状態が最も価値を持つ地点で捨てていたことになる。削除の直前に窓内失敗数を数え、閾値（`bruteSuccessMinFails=10`、試行アラートの `bruteMinFails=6` より意図的に高く設定＝打ち間違いの常習FPを避ける）以上なら severity 9 で発火する。タグは **T1110 と T1078 の両方**（バーストは credential-access、通った後のセッションは valid-account の initial-access であり、credential-access だけではキルチェーンを過小評価する）。自動隔離はしない（残存FPは「パスワードを思い出した本人」であり、人間のトリアージに回すべき）。
- ✅**LSASS creddump → プロセス注入のキルチェーン有効化（2026-08-02, migration 365）**: **T1003.001 → T1055.012**。コマンドラインに頼らず `credential_access`（LSASSハンドルアクセス）と `create_remote_thread`（クロスプロセススレッド作成）の2専用センサーを `target_image` で相関させる。PR #542 の棚卸しでは「両センサー未着地」として保留していたが、**その判定が誤りで両方 main に着地済み**だった（センサー / 配線 / CHECK制約 / フィールドサポート / パイプライン購読の5層すべてで再確認）。`ordered: true` かつ stage2 を重要システムプロセスに限定。
- 評価: ダンプ系は厚く、ブルートフォース/スプレー**および成功遷移**はランタイム相関で被覆。**ダンプ後の横移動（注入）まで連鎖として捕捉**。残穴は LSA/キャッシュ・秘密鍵・ネットワーク資格窃取(Responder)。

### 9. Discovery ✅
- 被覆: T1033, T1007, T1012, T1016, T1018, T1046, T1049, T1057, T1069(.001), T1082, T1083, T1087(.001/.002), T1135, T1518.001, T1482 ← バースト相関で広範囲
- 穴: T1010(アプリウィンドウ), T1124(システム時刻), T1201(パスワードポリシ), T1217(ブラウザ履歴)
- ✅**探索コマンド分類→kill-chain 供給(2026-07-20, `discovery.go` / PR#483)**: `classifyDiscoveryCommand` が
  探索コマンドを技術IDへ分類し、**単発は単独アラート化せず**kill-chain の discovery 段に供給（誤検知ゼロ）。
  加えて5分窓で4種以上の探索技術バーストのみ相関1件。実測で `netstat`(T1049) が既存DBルール未カバーだったのを
  本分類器が補完し、バーストの4種目を成立させたことをライブ確認。
- 🔴**T1046 の Linux 実効性に注記（2026-07-26 判明）**: `netScan` スコアラは実装として正しいが、**Linux 出荷ビルドでは
  入力テレメトリが永久にゼロ**だった。network eBPF connect-tracer の consumer が `ebpf && prevention` 誤ゲートで
  デッドコード化し `/proc/net` ポーリングへ無言降格していたため。`/proc/net/tcp` は**確立済みソケットしか列挙しない**＝
  **閉ポートへの接続試行（ポートスキャンの本質的シグネチャ）が構造的に不可視**。
  [PR #544](https://github.com/kizashi-labs/kizashi/pull/544) で修正。詳細＝
  [検知率向上_20260726_prevention誤ゲートによるeBPF死角.md](検知率向上_20260726_prevention誤ゲートによるeBPF死角.md)。
  > **監査上の教訓**: 本表の「被覆」は**ルールの存在**を示すもので、**テレメトリ到達性を保証しない**。
  > 以後の監査は「ルール × 対象OSでの入力イベント実在」の両輪で判定すること。
- 評価: バースト検知で厚い。
- ✅**ライブ実証(2026-06-26, Win2022)**: 静的被覆だけでなく、実機で `net localgroup`(T1069.001)を含む
  8コマンドのバーストを発火させ **8/8 Technique** を end-to-end 確認。T1069.001 は第1回(6-22)で唯一の
  ライブ MISS だったが、バースト規則の `mitre_tags` 補完(migration 273/PR#262)で解消。詳細＝
  [ATT&CK検知率測定計画.md](ATT&CK検知率測定計画.md) §12。★静的被覆=規則にタグがある、ライブ検知=
  新規アラートに実際にタグが乗る、は別物（既存アラートはタグ凍結のため規則更新後の新規発火が必要）。
- ✅**低速偵察耐性化(2026-07-06, migration 307)**: 探索バーストの観測窓を `60s → 10m`・閾値 `4 → 5` に拡張。
  Caldera のジッター付き偵察が 60 秒窓に収まらず Discovery 群が Tactic 止まりだった問題を解消。実機で
  **72 秒間隔**の低速偵察でバースト発火を実証。単一バーストアラートが `ai_mitre_tags` 経由で Discovery
  9 technique を一括 Technique 化する（scorer オフライン採点で実証）。★**減衰スコアは「幅」検知に無効
  ＝窓拡張が正解**。詳細＝[Caldera多段エミュレーション採点.md](ops/Caldera多段エミュレーション採点.md)
  「低速偵察耐性化と Discovery / T1005 ギャップ潰し（2026-07-06）」。

### 10. Lateral Movement 🟡→✅（主要穴を被覆・回帰固定）
- 被覆: T1021(.001 RDP/.002 PsExec/**.003 DCOM**/**.004 SSH**/.006 WinRM), T1047(WMI), T1550(.002 PtH/**.003 PtT**), T1570(横展開ツール転送)
- ✅**主要な横展開穴は既に実装済み・2026-07-09 に回帰テストで固定**: **T1021.004**(SSH インライン資格 plink `-pw`/sshpass `-p`), **T1021.003**(DCOM MMC20.Application/ShellWindows/GetTypeFromProgID), **T1550.003**(Pass-the-Ticket kerberos::ptt/.kirbi/Rubeus `ptt /ticket`)。いずれも `sigma_builtins.go` に存在したが発火テストが無かったため `attack_coverage_test.go` に固定。
- 🔴**残る穴**: T1021.005(VNC), T1563(セッションハイジャック), T1072(ソフト配布ツール)
- 評価: SSH/DCOM/PtT が抜け。

### 11. Collection ✅（2026-07-06 更新でほぼ被覆）
- 被覆（当初 2026-06-23）: T1560.001(パスワード付きアーカイブ) **のみ**
- ✅**更新(2026-06-29〜30, migration 283/284/285/290)**: **T1074.001(ステージング)**, **T1113(画面キャプチャ=CopyFromScreen/BitBlt 安定化)**, **T1115(クリップボード)**, **T1560.001**, **T1041** を追加。Caldera 収集チェーンを Windows/Linux 両方で 100% 到達実証。
- ✅**更新(2026-07-06, migration 308)**: **T1005(ローカルデータ収集)** = 再帰ファイル列挙（`Get-ChildItem -Recurse -Include … | %{$_.FullName} | Select -First`）を ScriptBlockText / CommandLine 両経路で検知。Caldera の最後の Tactic 止まり技を埋めた。詳細＝[Caldera多段エミュレーション採点.md](ops/Caldera多段エミュレーション採点.md)。
- 🔴**残る穴**: **T1056.001(キーロギング=`GetAsyncKeyState`署名)**, T1114(メール収集), T1039(共有ドライブ), T1119(自動収集), T1123(音声)
- 評価: 当初「最希薄」から、収集チェーン中核（ステージング/アーカイブ/画面/クリップボード/ローカルデータ）を被覆。残はキーロギング・メール・音声。

### 12. Command and Control ✅
- 被覆: T1071(.001/.004), T1090(.001/.003 プロキシ), T1095, T1105, T1219(RAT), T1568(.002 DGA), T1571(非標準ポート), T1572(トンネリング)
- 穴: T1573(暗号化チャネル), T1102(Webサービス), T1008(フォールバック), T1132(データエンコード)
- 評価: コマンドライン検知可能なC2は厚い。**真の穴=プロセス署名を持たないビーコン検知**（ネットワーク振る舞い解析が必要＝別軸）。周期性ビーコンは `beacon_detector.go`（#441 調和折り畳み）で既に実装・ライブ稼働。残る JA3/DNSエントロピー/多信号フュージョンの拡張設計は [design/ネットワークC2振る舞い検知の多信号フュージョン設計.md](design/ネットワークC2振る舞い検知の多信号フュージョン設計.md)。

### 13. Exfiltration 🔴→🟡（最希薄ゾーンに新規被覆＋固定）
- 被覆: T1048.003(非暗号化C2外経路), **T1048**(代替プロトコル アップロードツール), T1567.002(クラウドストレージ rclone)
- ✅**新規追加（2026-07-09, ビルトインSigma）**: **T1048**(代替プロトコル経由持出=`curl -T`/`--upload-file`/`--data-binary @`, `wget --post-file`, `tftp put`, `Invoke-WebRequest -InFile`)。加えて既存の **T1567.002**(rclone) が単一イベント層で発火するのに `attack_coverage_test.go` で未検知扱い(stale)だったのを**発火固定**。
- 🔴**残る穴**: **T1041(C2チャネル経由持出)**(DBルール別エンジンで一部被覆、builtin harness外), T1048(.001/.002 暗号化経路), T1029(スケジュール転送), T1030(転送サイズ制限), T1011(他媒体), T1052(USB物理媒体)
- ✅**`ftp.exe` の追加（2026-08-02）**: T1048 アップロードツール規則は curl / wget / tftp / Invoke-WebRequest を見ていたが、**全 Windows ホストに最初から在る `ftp.exe` だけが抜けていた**——ダウンロードもインストールも不要な転送クライアントで、持ち出し経路としてはむしろ第一候補。put/get は対話セッション内で打つためコマンドラインから方向が判別できず、素の `ftp.exe` を条件にすると起動しただけで鳴るので、LOLBAS 記載の無人スクリプトモード `-s:` を条件にした（対話利用には決して付かず、攻撃者が実際に使う非対話呼び出しには必ず付く）。
- 評価: 最希薄ゾーンにツール起点のアップロード検知(T1048/T1048.003)を追加。残の暗号化経路・スケジュール/サイズ制限は振る舞い検知向き（別軸）。

### 14. Impact 🟡
- 被覆: T1485(データ破壊), T1486(暗号化/ランサム), T1489(サービス停止=DBサービス拡張 #476), T1490(復旧阻害), T1529(シャットダウン/再起動 #476), T1497(サンドボックス回避 #476)
- ✅**ランサム挙動バースト検知(2026-07-20, `fileBurst` / PR#486)**: 1プロセスが短時間に多数の異なるファイルを**破壊的操作**(modify/rename/delete、create/read は除外)で **T1486** 発火。拡張子・ツール非依存の挙動レートなので、シグネチャの無い新種暗号化にも反応（severity 9）。**⚠️到達性修正 PR#491**: 当初 file イベントの action を `action` キーで読んでいたが実際は `operation` キーで、本番無反応だった不具合を是正（実本番形式 `FILE_ACTION_MODIFY` でライブ発火実証）。
- ★**T1496(リソースハイジャック/クリプトマイニング)の検知（#507, 2026-07-20）**: `process_stats` スナップショット（従来どこも消費せず死蔵）をステートフル `CryptoMinerScorer` で消費。1PIDが `cpu_pct≥80%`（システム全体比）を3スナップショット連続（約90秒）維持で sev5 発火。単発スパイクはリセットで誤検知抑制。
- 🔴**残穴（高価値）**: **T1561(ディスクワイプ)**, **T1531(アカウントアクセス削除)**, T1491(改ざん), T1565(データ操作)
- 評価: ランサム中核＋挙動バースト＋クリプトマイニング(T1496)＋強制シャットダウンを被覆。残はワイプ・アカウント削除。

---

## データ駆動の次バッチ・ロードマップ（優先順）

被覆希薄 × EDRでコマンドライン/プロセス検知可能 × 高シグナル を優先。

| # | バッチ | 戦術 | 主要技（検知の着眼） | 価値 |
|---|---|---|---|---|
| **1** | **Collection 一括** ✅ 大半完了 | Collection | ~~T1115~~✅, ~~T1113~~✅(284), ~~T1005~~✅(308 機微パス再帰列挙), 残: T1056.001(キーロガー署名/`GetAsyncKeyState`), T1114(.eml/PST一括読込) | 最希薄ゾーンを一掃 |
| ~~**2**~~ ✅ | ~~**Credential Access 深掘り**~~ 完了 | Cred Access | ~~T1003.004(reg save HKLM\\SECURITY), T1003.005(cached `lsadump::cache`), T1552.004(id_rsa/.pem/.ppk探索), T1557(Responder/Inveigh署名)~~ ✅ビルトインSigma追加済 | ダンプ以外の窃取経路 |
| ~~**3**~~ ✅ | ~~**Defense Evasion 古典穴**~~ 完了(既存を回帰固定) | Def Evasion | ~~T1036.003, T1564.003, T1564.004, T1070.006, T1562.002~~ ✅実装済を `attack_coverage_test.go` に固定 | 古典回避の取りこぼし |
| ~~**4**~~ ✅ | ~~**Lateral Movement 拡充**~~ 完了(既存を回帰固定) | Lateral | ~~T1021.004(ssh横展開), T1021.003(DCOM mmc/excel), T1550.003(Pass-the-Ticket)~~ ✅実装済を固定 | 主要横展開の残穴 |
| ~~**5**~~ ✅ | ~~**Privilege Escalation**~~ 完了(既存を回帰固定) | Priv Esc | ~~T1134(トークン操作: `runas /netonly` 等)~~ ✅実装済を固定 | 単一だが高価値 |
| **6** | **Impact 拡充** | Impact | T1496(`xmrig`/マイニングプール), T1561(`diskpart clean`/`Clear-Disk`), T1531(`net user /delete`,`Remove-ADUser`) | ランサム周辺 |
| **2** | **Credential Access 深掘り** | Cred Access | T1003.004(reg save HKLM\\SECURITY), T1003.005(cached `lsadump::cache`), T1552.004(id_rsa/.pem/.ppk探索), T1557(Responder/Inveigh署名) | ダンプ以外の窃取経路 |
| **3** | **Defense Evasion 古典穴** | Def Evasion | T1036.003(システム正規名へのリネーム=Image≠正規パス), T1564.003(`-WindowStyle Hidden`), T1564.004(NTFS ADS `:`), T1070.006(timestomp), T1562.002(`auditpol /set`,`wevtutil sl`) | 古典回避の取りこぼし |
| **4** | **Lateral Movement 拡充** | Lateral | T1021.004(ssh横展開), T1021.003(DCOM mmc/excel), T1550.003(Pass-the-Ticket `rubeus ptt`/`.kirbi`) | 主要横展開の残穴 |
| **5** | **Privilege Escalation** | Priv Esc | T1134(トークン操作: `runas /netonly`, `SeDebug`乱用, `Get-System`系) | 単一だが高価値 |
| **6** | **Impact 拡充** | Impact | ~~T1496~~✅(#507 process_stats の持続的高CPU＝採掘検知), T1561(`diskpart clean`/`Clear-Disk`), T1531(`net user /delete`,`Remove-ADUser`) | ランサム周辺 |
| — | ネットワークビーコン検知 | C2 | 通信周期性/JA3/DNSエントロピー（プロセス署名なきC2） | 別軸=新検知クラス（コード規模大） |
| — | センサ深度 | Cred/Disc | LSASS process_access, FIM, registry value-set | 構造的ceiling＝実機要 |

**実装手順は確立済みの低リスク経路**（ビルトインSigma追加 → `TestBuiltinSigmaPrimaryTechnique`/`TestNewCoverageRulesMatch` でガード → server-api `--no-cache` デプロイ）。Collection と Cred Access 深掘りが ROI 最大。

## メンテナンス

ルール追加のたびに本監査の被覆リストは変化する。四半期ごと、または大きな検知スプリント後に上記の再現コマンドで被覆 technique を再抽出し、本ドキュメントの戦術別マトリクスを更新すること。

### 更新ログ
- **2026-07-22 (AD/ドメイン全体タンパリング + Windowsログオンスクリプト)**: 発火＋良性否定テスト
  `builtin_ad_persist_fire_test.go`。
  - **Domain Policy Modification via GPO Tampering**(**T1484.001 新規被覆**): `New-GPO`/
    `Set-GPRegistryValue`/`Set-GPPrefRegistryValue`/`SharpGPOAbuse` = GPO経由でOU全体に悪性設定
    (スケジュールタスク/レジストリ値/スクリプト)を一括配布する手口。読取専用の`Get-GPOReport`は非発火。
  - **Windows Logon Script Persistence via Registry**(**T1037.001 新規被覆**): `UserInitMprLogonScript`
    レジストリ値の設定=単一ホスト永続化。同キー配下の無関係な値(TEMP等)は非発火。
  - **Network Logon Script Deployment via NETLOGON or SYSVOL Share**(**T1037.003 新規被覆**): NETLOGON/
    SYSVOLへのスクリプトコピー=ドメイン全体(全ユーザ/OU)への一括永続化。ローカルコピーのみは非発火。
  - **Domain Controller Authentication Tampering (DCShadow/AdminSDHolder Abuse)**(**T1556.001 新規被覆**,
    critical): `mimikatz lsadump::dcshadow`+`/pushmode`(ロークDC偽装によるAD複製への不正注入)、または
    `dsacls`によるAdminSDHolder ACL改変 = Domain Adminへの永続的かつ検知回避的な裏口。privilege::debug
    単体や無関係オブジェクトへのdsaclsクエリは非発火。
  - ★このエントリ作成時点で監査ドキュメントの記載漏れ(T1134/T1197/T1546.008/T1546.015/T1546.010/
    T1547.006/T1003.004-005/T1552.004,006/T1557.001/T1539が実装済みにもかかわらず「穴」表示のまま
    残っていた)も是正したが、本ブランチとmainで並行して同種の是正が進んでいたため、下記の既存エントリ群と
    一部重複する記述が残っている。詳細＝
    [検知率向上_20260722_AD全体タンパリングとWindowsログオンスクリプト永続化.md](検知率向上_20260722_AD全体タンパリングとWindowsログオンスクリプト永続化.md)。
- **2026-07-15 (Windows横展開の深化 + クラウド永続化 + ランサム複合相関)**:
  - **Windows横展開の深化**(PsExec/WinRM基礎検知は既存、発火＋良性否定テスト
    `builtin_lateral_deep_fire_test.go`): 既存ルールはツールの**存在**(psexec.exe/PSEXESVC.exe/winrs/
    PSSession)止まりで、実際に何が実行されたかを捉えていなかった。**Process Spawned by PsExec Service**
    (T1569.002, ParentImage=PSEXESVC.exe)と**Process Spawned by WinRM Remote Shell Host**(T1021.006,
    ParentImage=wsmprovhost.exe)を追加し、svchostハロウイング検知と同じ「子プロセス=実ペイロード」パターンを
    横展開。加えて**PsExec-Alternative Remote Execution Tool (PAExec/RemCom)**(T1569.002, 署名回避の
    クローンツール)、**PowerShell Remote Command Execution via Invoke-Command**(T1021.006,
    `-ComputerName`/`-Session`)、**WinRM Remote Management Enabled**(T1021.006, low,
    `winrm quickconfig`/`Enable-PSRemoting`=横展開の前段有効化)。否定: 通常サービスホスト経由のcmd/
    explorer経由のpowershell/ローカルscriptblock/読取専用winrm queryは非発火。
  - **クラウド永続化**(IAM特権昇格・サーバレス改ざんは既存、発火＋良性否定テスト
    `builtin_cloud_persist_fire_test.go`): **Cloud Backdoor Account Creation**(T1136.003, AWS
    `iam create-user`/GCP `iam service-accounts create`+`keys create`/Azure `ad sp create-for-rbac`等 =
    資格情報ローテーションを生き延びる恒久バックドア)、**Cloud Persistence via Scheduled Event Trigger**
    (T1053.005のクラウド版, `events put-targets`がLambda/SSM/Step FunctionsのARNを指す場合、またはGCP
    `scheduler jobs create` = イベント駆動での自己再起動)。読取専用一覧やSNS宛てターゲットは非発火。
  - **ランサムウェア複合相関**(`ransomware_correlator.go`, `RansomwareCorrelator`, agentIDキー・15分窓・
    バウンド、`ransomware_correlator_test.go`): 個別の前兆ルール(復旧妨害T1490=シャドウコピー/バックアップ
    削除、防御/バックアップサービス改ざんT1489、広範囲ACL付与T1222)は単独でも高/重大レベルで発火するが、
    **同一ホストで短時間に2系統以上が併発**するのは正規運用では稀という洞察に基づき、C2相関器と同じ多信号
    昇格パターン(windowed・bounded-key・注入可能クロック)を適用。2軸一致でsev10＋自動隔離、3軸目でも再発火
    (成長のみ再発火・同一集合は非再発火)。`engine.go`の`matches`に対し`classifyRansomwareSignal`でMITREタグ
    (T1490/T1489/T1222プレフィックス)から軸分類し、`ProcessThreatCorrelator`と同じ位置(キルチェーン相関の
    直前)に配線。大規模暗号化が始まる前に介入できる、最も価値の高いタイミングでの検知。
    詳細＝[検知率向上_20260715_Windows横展開深化とクラウド永続化とランサム複合相関.md](検知率向上_20260715_Windows横展開深化とクラウド永続化とランサム複合相関.md)。
- **2026-08-01 (mainとのマージ統合メモ)**: `claude/detection-rate-methods-6mza2z` ブランチ(本エントリ群)は
  mainの並行開発（JA3/JA3S基礎ライブラリ、C2FusionScorer Ph1-3、DBエンジンパリティmigration 318-329等）と
  同時期に進行していたため、機能重複（例: JA3実装、T1134/T1003.004-005等の記載漏れ是正）が生じた。マージでは
  mainの完成度の高い実装(JA3はcapture未配線のため本ブランチの完全実装を採用、ルールは両者の被覆を合算し
  重複タイトルのみ統合)を基準とし、本ブランチ固有の**44ルール**を追記する形で統合した。
- **2026-07-13（同日・後半スプリント：両エンジンパリティ＋相関キルチェーン＋コンテナ技法）**: 単一イベント被覆の拡充（下記+20技法バッチ）に続き、**検知の"深さ"（両エンジン被覆・多段相関）とコンテナ攻撃面**を強化。方針は一貫して「実装があるか確認→無ければ追加、有れば回帰テストで固定」。
  - **DBエンジン両エンジンパリティ（migration 318–329、計56 technique を api-server ビルトインから detection-server DB RuleEngine へ移植＝12バッチ）**: 同一攻撃がどちらのイベント経路を通っても捕捉できるよう二重被覆。全ルール `CommandLine|contains` のみ（DB の field mapping で解決＝死蔵回避）、`ARRAY['linux','windows','macos']`、`WHERE NOT EXISTS` で冪等化。`migration_parity_test.go` の**発火回帰71件**＋既存 migration 群（compile/match時err/field-support/coverage/self-check）で固定。
    - **318 クラウド/AD初弾**: T1526 / T1562.008 / T1087.002(+ADSI) / T1558.004(+Impacket GetNPUsers) / T1649(AD CS Certipy)
    - **319 持ち出し/リレー/トンネル**: T1567.002(rclone/MEGAcmd) / T1557.001(Responder/Inveigh/ntlmrelayx/mitm6) / T1558.001(Rubeus/Impacket ticketer) / T1572(ngrok/chisel/frp/plink)
    - **320 クラウド攻撃面**: T1580 / T1619 / T1098.001 / T1098.003 / T1562.007
    - **321 クラウド永続化/収集/認証情報**: T1578(スナップショット持ち出し) / T1136.003 / T1552.005(インスタンスメタデータ169.254.169.254) / T1114.003(メール転送ルール)
    - **322 コンテナ攻撃面**: T1610(特権コンテナ) / T1611(ホストエスケープ nsenter/runc) / T1612(ホスト内イメージビルド) / T1609(コンテナexec) / T1552.007(K8s SAトークン)
    - **323 Windows永続化**: T1546.001(AppInit DLLs) / T1037.001(UserInitMprLogonScript) / T1546.012(IFEO Debugger) / T1197(BITS jobs)
    - **324 認証情報アクセス**: T1003.003(NTDS.dit) / T1003.004(LSA secrets) / T1003.005(DCC2 cached) / T1552.006(GPP cpassword) / T1555.004(Credential Manager)
    - **325 防御回避LOLBin**: T1218.004(InstallUtil) / T1218.007(msiexec遠隔) / T1218.009(Regsvcs/Regasm) / T1220(XSL msxsl/wmic) / T1218.003(CMSTP)
    - **326 横展開/収集**: T1021.003(DCOM) / T1550.003(Pass-the-Ticket) / T1115(クリップボード) / T1114.001(ローカルメールストア) / T1123(音声キャプチャ)
    - **327 C2/持ち出しチャネル**: T1219(RMM AnyDesk/TeamViewer/ScreenConnect) / T1102(正規Webサービスデッドドロップ pastebin/githubusercontent/telegram/discord webhook) / T1071.002(FTP/TFTP) / T1071.003(メールプロトコル)
    - **328 探索/永続化/防御回避**: T1615(グループポリシー探索) / T1136.002(ドメインアカウント作成) / T1053.002(at.exe) / T1564.003(隠しウィンドウ) / T1564.004(NTFS ADS)
    - **329 WMI購読/MOTW/残りLOLBin**: T1546.003(WMIイベント購読永続化) / T1553.005(Mark-of-the-Web回避) / T1218.001(hh.exe遠隔) / T1027.002(UPXパッキング) / T1569.002(PsExecサービス実行)
  - **相関キルチェーン拡充（correlation ビルトイン 5→11）**: AlertPipeline が主技法に応じてマーカー（`_attack_surface`=cloud/ad, `_ransomware_precursor`, `_exfil_activity`, `_container_escalation`, `_credential_theft`）を付与し、単発検知を多段インシデントへ昇格。各ルールに発火/ゲーティング（marker無し・MinEvents境界）回帰テスト、`TestLoadBuiltins_RuleCount` を 5→11 で固定、`engine_helpers_test.go` にマーカー分類テスト。
    - **corr-006 クラウド乗っ取りチェーン**（surface=cloud, MinEvents3）/ **corr-007 AD侵害チェーン**（surface=ad, ESC8コアーション→リレー→ADCS を含む, MinEvents3）/ **corr-008 ランサム準備**（precursor 2件）/ **corr-009 データ持ち出し進行中**（exfil 2件）/ **corr-010 コンテナ→ホスト/クラスタ・ブレイクアウト**（container_escalation 2件, T1610→T1611→T1552.007 を束ねる）/ **corr-011 多元的認証情報窃取**（credential_theft 2件、単一攻撃者がLSASS/SAM/ブラウザ/GPP/Kerberos等の複数ソースから短時間に窃取; corr-002の同一技法クロス3エージェントとは相補的）
  - **ビルトイン新技法（単一イベント被覆 125→128）**: **T1612**(Build Image on Host: docker/podman/nerdctl build・buildah・kaniko でホスト上に悪性イメージビルド＝レジストリスキャン回避) / **T1546.001**(AppInit DLLs 永続化) / **T1037.001**(ログオンスクリプト UserInitMprLogonScript 永続化) を追加。いずれも監査で「🔴穴(高価値・残)」だった Windows 永続化を埋めるもので、attack_coverage_test.go・primary-technique want マップ・scorer戦術まで全ゲート固定。
  - **FN堅牢化（同日）**: ADSI(adsisearcher/DirectorySearcher)・Impacket横展開スイート・evil-winrm・rclone回避/MEGAcmd・Follina(msdt) 等のクロスプラットフォーム回避を既存ルールに追記。加えて **PowerShellダウンロードクレードル T1071.001**(DownloadData/Invoke-RestMethod(irm)/[Net.WebRequest]/OpenRead=fileless in-memory 亜種) と **Rundll32 T1218.011**(url.dll,OpenURL / advpack,LaunchINFSection / pcwutl,LaunchApplication / zipfldr,RouteTheCall 等の古典LOLBinエクスポート悪用＋Temp/AppData/Public/ProgramData のステージングDLLロード) の自明な回避を封鎖。全て `evasion_hardening_test.go` で固定。
- **2026-07-13（ビルトイン技法拡充スプリント：+20 技法、商用EDR比較の穴埋め）**: 単一イベント層の未被覆を
  商用EDR（CrowdStrike/SentinelOne/Cortex）の重視領域中心に5バッチで拡充。**単一イベント期待技術カバレッジ
  94→114/114 命中**（`attack_coverage_test.go` corpus、全て `expectSingleEvent=true` で発火を回帰固定、
  primary technique を `sigma_builtins_primary_technique_test.go` の want マップで固定）。方針は一貫して
  「汎用ルールが取りこぼす別ツール経路（Rubeus/Impacket/CrackMapExec/NetExec/PowerView/Invoke-TheHash/
  各クラウドCLI）を狙い、**真の追加被覆**を確保」。
  - **AD/ドメイン偵察**（横展開・権限昇格の前段）: T1482 Domain Trust / T1087.002 Domain Account（+BloodHound・
    SharpHound）/ T1018 Remote System・DC / T1069.002 Domain Group / T1135 Network Share / T1615 Group Policy。
    LOLBin（nltest/dsquery/net）＋ PowerShell/PowerView 両経路を被覆。
  - **Kerberos 認証情報悪用**: T1558.004 AS-REP Roasting（既存 Rubeus 中心ルールが取りこぼす PowerView/
    ASREPRoast.ps1 経路を補完）/ T1558.001 Golden・Silver Ticket（Rubeus golden/silver・`/krbtgt:`・Impacket
    ticketer）/ T1550.002 Pass-the-Hash（Invoke-TheHash・CrackMapExec/NetExec `-H`・Impacket `-hashes`）。
    既存 T1003 汎用 mimikatz ルール・T1550.003 PtT との重複を corpus で峻別。
  - **C2/持ち出しチャネル**: T1071.004 DNSトンネリング（dnscat2/iodine/dns2tcp/dnsteal）/ T1071.002 FTP-TFTP /
    T1071.003 メール経路（Send-MailMessage -Attachments・swaks・curl smtp）。
  - **資格情報（Linux）**: T1552.003 シェル履歴探索（.bash_history/.mysql_history 等）。
  - **クラウド攻撃面**（クラウドEDRの最大差別化領域、全て未被覆だった）: T1526 Service/IAM Discovery
    （sts get-caller-identity・iam/organizations list・az ad/role・gcloud iam）/ T1580 Infrastructure Discovery
    （ec2 describe・vm list・compute list）/ T1619 Storage Object Discovery（s3 ls・storage list・gsutil）/
    **クラウド永続化・権限昇格** T1136.003 Cloud Account Creation（iam create-user 等）/ T1098.001 Additional
    Cloud Credentials（create-access-key・credential reset・keys create）/ T1098.003 Additional Cloud Roles
    （attach-user-policy・role assignment create・add-iam-policy-binding）。列挙(list)より攻撃者特有な
    作成/付与(create/attach)を狙い高シグナル化。マルチOS（logsource product 非固定）。
  - scorer（`agent/cmd/attack-scorer/tactics.go`）に T1615/T1526/T1580/T1619 を追加。全ゲート
    （compile/primary/field-support/NoMalformedPatterns）・両モジュール vet/build・scorerテスト緑。
    途中で FTP rule の description 内 `": "` による YAML パース誤りを `TestAllBuiltinRulesCompile` が検出→是正
    （「壊れたら回帰ゲートが捕捉」を実証）。
- **2026-07-11（DBエンジンのフィールド被覆監査＝第3の死蔵モードを是正）**: 監査系の深掘り。ビルトイン側の
  `TestBuiltinRuleFieldSupportAudit`（未サポートフィールド＝サイレント死蔵の検出）の **detection-server RuleEngine 版**が
  無かった。過去に潰した死蔵は「パース失敗」「match時err」だったが、第3のモード＝**フィールド名不一致**が残存:
  出荷 DB sigma ルールのうち Sysmon 名（`TargetImage`/`GrantedAccess`/`TargetObject`/`SourceImage`/`Details`）で
  選択する **6ルール**が、RuleEngine の field mapping で解決されず**この検知エンジンで無言で不発**だった（api-server
  AlertPipeline 側は解決できるのに片肺状態）。
  - **是正**: detection-server が実際に emit する native フィールド（`target_image`/`access_mask`/`key_path`/
    `value_data`/`source_image`/`operation`）への Sysmon エイリアスを `rule_engine.go` の config に追加 → **5ルールを復活**
    （LSASSダンプ／レジストリRun鍵×2／WinLogon Helper DLL／プロセスホロウイング）。実イベントで発火することを
    `TestMigrationSigmaRevivedRulesFire` で回帰固定。
  - **恒久ゲート**: `TestMigrationSigmaFieldSupport` を新設（完全不発ルールを検出し件数を回帰ガード）。
    残る1件「Cobalt Strike Beacon via Named Pipe」は detection-server が named-pipe イベントを処理しないため
    knownInert に正当化付きで allowlist（CS はビルトインのプロセス名 IOC でも捕捉）。
  ★これで detection-server の死蔵モードは3種（コンパイル/match時/フィールド不一致）とも監査・是正された。
- **2026-07-11（FN堅牢化 第10弾：macOS Dylib インジェクション）**: 回避監査を macOS 固有手口へ展開
  （`evasion_hardening_test.go` 計52ケース）。実FN 2件を是正:
  - **macOS T1574.006 DYLD インジェクション（新ルール）**: `DYLD_INSERT_LIBRARIES=`（LD_PRELOAD の macOS 版）
    ／`DYLD_LIBRARY_PATH=`／`DYLD_FRAMEWORK_PATH=` で標的プロセスに悪性 dylib を強制ロードする注入/永続化/
    昇格経路が**全く未被覆**だった → 新ルール追加。
  - 参考: osascript リバースシェル（`do shell script`）はクロスプラットフォームで既に捕捉済みを確認。
  - 回避監査52ケース全て発火、3ゲート・全カバレッジ・vet 緑。macOS 固有の in-process 注入の耐性を底上げ。
- **2026-07-11（FN堅牢化 第9弾：SUID列挙/コンテナエスケープ）**: Linux 権限昇格recon とコンテナ突破を強化
  （`evasion_hardening_test.go` 計49ケース）。実FN 6件を是正:
  - **T1548.001 SUID/capability 列挙（新技法・新ルール）**: `find / -perm -4000`／`-perm -u=s`／`getcap -r /` は
    Linux 権限昇格の**第一歩の偵察**なのに**builtin ルールが存在しなかった** → 新ルール追加。
  - **T1611 コンテナエスケープの追加変種**: 既存ルール（nsenter/--privileged/proc/1/root/unshare/cap_sys_admin/
    host-mount）に、**runc `/proc/self/exe` 上書き（CVE-2019-5736）／cgroup `release_agent` エスケープ／
    マウントされた `docker.sock` 悪用**を追加。
  - 回避監査49ケース全て発火、3ゲート・全カバレッジ・vet 緑。クラウド/コンテナ権限昇格の耐性を底上げ。
- **2026-07-11（FN堅牢化 第8弾：Linux ダウンロード実行/GTFOBins）**: Linux 実行系のFN堅牢化を継続
  （`evasion_hardening_test.go` 計43ケース）。実FN 6件を是正:
  - **ダウンロード/復号→シェル直結（T1059.004、新ルール）**: `curl … | bash`／`wget -qO- … | sh`／
    `echo <b64> | base64 -d | bash` は**ディスクにもLOLBin名にも触れず**にペイロード実行するが未被覆だった →
    「Download or Decode Piped to Shell (Linux)」ルールを追加（source=curl/wget/base64 -d × pipe_shell=|bash/|sh…）。
  - **sudo GTFOBins の追加変種（T1548.003）**: 既存ルールが vim/find/awk/python/perl/-p 止まりで、
    `sudo env /bin/sh`／`sudo tar … --checkpoint-action=exec=`／`sudo gdb -ex`／`sudo less|more|man`（ページャ脱出）／
    `sudo ftp|ed` を取りこぼし → 追加。
  - 回避監査43ケース全て発火、3ゲート・全カバレッジ・vet 緑。
- **2026-07-11（FN堅牢化 第7弾：Linux リバースシェルの多変種）**: これまで Windows 中心だった回避監査を
  Linux 実行系に展開。T1059.004 リバースシェルが **bash `/dev/tcp` のみ**で、チートシート常連の非bash
  ワンライナーを**全て取りこぼしていた**（`evasion_hardening_test.go` 計37ケース）。実FN 7件を新ルールで是正:
  - **perl**（`perl -e 'use Socket;...exec("/bin/sh")'`）／**ruby**（`ruby -rsocket`/TCPSocket）／
    **php**（`php -r '...fsockopen...'`）／**socat**（`socat TCP:.. EXEC:/bin/bash`）／
    **mkfifo バックパイプ**（`mkfifo /tmp/f;...|nc ..`）／**nc -e**（`nc -e /bin/sh`）／
    **awk**（gawk `/inet/tcp/` ネットワーク拡張）。
  - 新ルール「Linux Reverse Shell via Interpreter or Tool」で condition を
    `(perl_sock and perl_exec) or ruby_sock or php_sock or socat_exec or (fifo and fifo_net) or nc_exec or awk_inet`。
    回避監査37ケース全て発火、3ゲート・全カバレッジ・vet 緑。コンテナ/クラウドの主戦場である Linux 実行系の
    実効検知率を大きく底上げ（商用EDRがリバースシェル検知で重視する領域）。
- **2026-07-10（FN堅牢化 第6弾：BITS/netsh/mshta LOLBin）**: BITS・netsh portproxy・主要LOLBin の回避耐性を
  点検（`evasion_hardening_test.go` 計30ケース）。
  - **監査で「既に堅牢」を確認**: T1197 BITS の PowerShell 経路（`Start-BitsTransfer`）と T1218.011 rundll32
    `javascript:` 実行は**既存ルールで捕捉済み**だった（回帰固定として追加）。netsh portproxy も十分。
  - **実FN 2件を是正**: T1218.005 mshta が `http/vbscript/javascript` トークン依存で、**ローカル `.hta` 実行**
    （`mshta.exe C:\...\evil.hta`）と **`about:` インラインスクリプト**を取りこぼしていた → `.hta`/`about:`/
    Temp・AppData・Public パスを追加。
  - 回避監査30ケース全て発火、3ゲート・全カバレッジ・vet 緑。
- **2026-07-10（FN堅牢化 第5弾：AMSI/ETW バイパス）**: 現代攻撃で常用される計測回避の穴を是正
  （`evasion_hardening_test.go` 計26ケース）:
  - **T1562.001 AMSI バイパス（インライン）**: 既存 AMSI ルールは `ScriptBlockText`（スクリプトイベント）依存で、
    **プロセス command_line にインライン展開された `-Command` AMSI パッチ**（amsiInitFailed/AmsiScanBuffer の書換）を
    取りこぼしていた → process_creation 版の AMSI ルールを新設。
  - **T1562.006 ETW バイパス（新技法）**: Event Tracing for Windows の無効化（`EtwEventWrite` パッチ、.NET
    `EventProvider` の `m_enabled` 改変、`logman stop` によるトレースセッション停止）が**全く未被覆**だった → 新ルール追加。
    EDR/テレメトリを盲目化する重要技法。
  - 回避監査26ケース全て発火、3ゲート・全カバレッジ・vet 緑。in-memory/計測回避系の耐性を底上げ。
- **2026-07-10（FN堅牢化 第4弾：Run鍵/WMIサブスクの PowerShell 経路）**: レジストリ/WMI 永続化の
  Image・クラス名依存ルールが PowerShell 経由の同等操作を取りこぼしていた（`evasion_hardening_test.go` 計24ケース）:
  - **T1547.001 Run鍵**: `reg.exe add` 依存で、**PowerShell `Set-ItemProperty`/`New-ItemProperty` による Run鍵書込**を
    取りこぼし → `(ps_write_cmd and ps_write_key)` ブランチを追加。
  - **T1546.003 WMIサブスクリプション**: `__EventFilter`/`CommandLineEventConsumer` 等のクラス名依存で、
    **PowerShell `Register-WmiEvent`/`Register-CimIndicationEvent`** を取りこぼし → 追加。
  - 回避監査24ケース全て発火、3ゲート・全カバレッジ・vet 緑。「fileless（reg.exe/wmic を使わない PS 直接操作）」経路の耐性を底上げ。
- **2026-07-10（FN堅牢化 第3弾：Windows Defender 無効化）**: Defender 改ざんの T1562.001 は
  `Set-MpPreference -DisableRealtimeMonitoring` とレジストリ改変しか見ておらず、実際に多用される回避を
  取りこぼしていた（`evasion_hardening_test.go` 計20ケースに拡張）。新ルール1件で以下を捕捉:
  - **除外による盲目化**: `Add-MpPreference -ExclusionPath/-ExclusionProcess`（スキャン対象から除外）
  - **他の Set-MpPreference 無効化**: `-DisableIOAVProtection`/`-DisableBehaviorMonitoring` 等（Realtime 以外）
  - **サービス停止**: `sc/net stop WinDefend`・`Stop-Service`・`sc config`（WinDefend/Sense/WdNisSvc）
  - **定義削除**: `MpCmdRun -RemoveDefinitions`
  condition は `((setmp or addmp) and mp_evasion) or (svc_name and svc_verb) or (mpcmdrun and removedef)`。
  回避監査20ケース全て発火、3ゲート・全カバレッジ・vet 緑。ランサム前段で常用される Defender 無効化の耐性を底上げ。
- **2026-07-10（FN堅牢化 第2弾：LSASS/スケジュールタスク/サービス）**: 回避監査を最重要クレデンシャル技法と
  常用永続化に拡大。追加で実FN 5件を是正（`evasion_hardening_test.go` 計15ケースに拡張）:
  - **T1003.001 LSASS**: comsvcs MiniDump を**エクスポート名でなく序数 `#24`** で呼ぶ回避（`rundll32 comsvcs.dll,#24
    <pid> out.dmp full`）を取りこぼし → comsvcs ルールを `MiniDump or #24` に。加えて**専用ダンプツール/PSコマンドレット**
    （nanodump/dumpert/HandleKatz/Out-Minidump/pypykatz/lsassy/SafetyKatz/Invoke-Mimikatz）を捕捉する新ルールを追加。
  - **T1053.005 スケジュールタスク**: schtasks.exe の Image 依存で **PowerShell `Register-ScheduledTask`** を取りこぼし → 追加。
  - **T1543.003 サービス作成**: sc.exe の Image 依存で **PowerShell `New-Service`** を取りこぼし → 追加。
  - 回避監査15ケース全て発火、3ゲート・全カバレッジ・vet 緑。LOLBin/序数/PS 経由の代替手口に対する耐性を底上げ。
- **2026-07-10（既存ルールのFN堅牢化＝回避手口の取りこぼし是正）**: 技法追加ではなく、**既存の高価値ルールが
  攻撃者の一般的な回避手口を取りこぼしていないか**を点検し、`evasion_hardening_test.go` で回避バリアントを
  発火固定。監査で発見した実FN 3件を是正:
  - **T1059.001 Encoded PowerShell**: ルールが `-enc`/`-ec`/`-e` しか見ておらず、PowerShell の**パラメータ接頭辞
    マッチ**（`-en`/`-enco`/`-encod`/`-encode`/`-encoded`/…はすべて -EncodedCommand）で自明に回避可能だった。
    `-e`〜`-encodedcommand` の全接頭辞を追加。あわせて Image を `pwsh` にも拡張。
  - **T1490 Volume Shadow Copy Deletion**: vssadmin/wmic/diskshadow の Image リストに依存し、**PowerShell の
    WMI/CIM 経由のシャドウ削除**（`Get-WmiObject/Get-CimInstance Win32_ShadowCopy | Remove-*`）と **wbadmin** を
    取りこぼしていた。ps_wmi + wbadmin セレクションを追加。
  - **T1105 CertUtil download**: `-urlcache` のみで、代替ダウンロード経路 `-verifyctl`/`-split` を取りこぼしていた。追加。
  - 回避監査10ケース全て発火、3ゲート・全カバレッジ・vet 緑。★技法「数」ではなく既存検知の「実効性（回避耐性）」を上げる回。
- **2026-07-10（ビルトイン新技法：パッキング/MOTW/macOS永続化）**: genuinely新規かつ commandline 検知可能な
  高シグナル技法を5件追加（最も希薄な macOS を重点）。T1027.002(UPX パッカーによる難読化)／T1553.005(Mark-of-
  the-Web バイパス＝Zone.Identifier ADS 除去・Unblock-File)／T1547.007(macOS Re-opened Applications 永続化＝
  com.apple.loginwindow)／T1546.014(macOS Emond ルール永続化＝/etc/emond.d/rules)／T1037.005(macOS StartupItems
  永続化)。3ゲート通過、`attack_coverage_test.go` に5エントリ追加し単一イベント期待技術 **94/94 命中**、各ルール
  自技法発火を個別検証。macOS の被覆技法が厚くなった（session 通算で macOS 10→約20）。
- **2026-07-10（ビルトイン新技法：ルートキット/ブート/不正DC/コンテナ資格情報）**: どのOSでも未被覆の
  高シグナル技法を5件追加。T1552.007(K8s サービスアカウントトークン/kubelet 資格情報アクセス＝コンテナ→
  クラスタAPI 昇格)／T1207(DCShadow 不正ドメインコントローラ＝`lsadump::dcshadow`)／T1014(ld.so.preload
  ユーザランドルートキット)／T1542.003(ブートローダ改変＝bcdedit safeboot/GRUB rewrite)／T1091(リムーバブル
  メディア複製＝autorun.inf/USBへのexeコピー)。scorer に T1014/T1542/T1207 追加。★T1091 ルールで YAML の
  重複キー(`CommandLine|contains` を同一selection内に2度)によるパース失敗＝コンパイル時死蔵を作りかけたが、
  `TestAllBuiltinRulesCompile`/`NoMalformedPatterns` ゲートが即座に検出→セレクション分割で修正（ゲートの有効性を実証）。
  3ゲート通過、`attack_coverage_test.go` に5エントリ追加し単一イベント期待技術 **89/89 命中**、各ルール自技法発火を個別検証。
- **2026-07-10（ビルトインIOCの適合性を回帰固定）**: `ioc_builtins.go` の出荷28 IOC は既存テストが
  Type/Value 非空しか検証しておらず、**型に対する適合性（IP がパース可能か・hash が MD5/SHA1/SHA256 の
  hex 長か・domain がスキーム/空白を含まないか）が未検証**だった。不正な IOC は enabled でも実テレメトリに
  一度もマッチしない「サイレント死蔵」（Sigma のコンパイル/フィールド被覆ゲートと同型）。`ioc_builtins_test.go`
  を新設し、①各 IOC の型別適合性 ②ID 一意性 ③CompositeIOCLoader がビルトインを実際に合流させること、を固定。
  出荷28件は全て適合（バグは無し・以後の混入を回帰ガード）。
- **2026-07-10（api-server 相関層の点検・固定＋Exfil/C2ビルトイン追加）**: 2件を実施。
  - **①api-server AlertPipeline 相関層の点検・固定**: AlertPipeline が配線する相関エンジンは
    `internal/correlation`(detection-server の SequenceEngine とも、detection.CorrelationEngine とも別物)。
    既存 18テストは**エンジン機構をシンセティックルールで検証するのみ**で、**出荷される5つのビルトイン相関
    ルール(corr-001 横展開/002 資格情報ダンプ/003 ランサム大流行/004 永続化/005 C2ビーコン)を end-to-end で
    一度も発火検証していなかった**（DBルールと同型のドリフト危険）。`builtins_coverage_test.go` を新設し、
    `LoadBuiltins` した実ルールを代表アラート列で駆動し、①各ルールが正しい technique で発火 ②MinEvents 未満は
    沈黙 ③Conditions(severity/contains)ゲートが効く ④5件ロードされる、を回帰固定。加えて
    **`AlertPipeline.isDuplicate`(重複抑制のスライディングウィンドウ、テスト皆無)** と
    **`detection.CorrelationEngine` の設定バリデーション(threshold<1→3, window<=0→1h)** も固定。
  - **②Exfil/C2/資格情報ストア ビルトイン5技法追加**（どのOSでも未被覆）: T1102(正規Webサービス悪用C2＝
    pastebin/raw.githubusercontent/telegram bot/discord・slack webhook)／T1620(リフレクティブ.NETアセンブリ
    メモリロード)／T1555.005(パスワードマネージャ vault 窃取＝.kdbx/1Password/Bitwarden)／T1090.002(proxychains/
    chisel/socat/ssh -D によるトンネリング)／T1114.001(ローカルメール窃取＝.pst/.ost/.mbox)。scorer に T1620 追加。
    3ゲート通過、`attack_coverage_test.go` に5エントリ追加し単一イベント期待技術 **84/84 命中**、各ルール自技法発火を個別検証。
- **2026-07-10（ビルトイン新技法バッチ：クラウド/コンテナ/探索/ブラウザ資格情報）**: ビルトイン全体で
  **どのOSでも未被覆だった技法**を中心に追加（現代的なクラウド/コンテナ攻撃面の穴を埋める）。
  - **新技法6**: T1552.005(クラウドメタデータAPI＝169.254.169.254/metadata.google.internal への curl/wget＝
    インスタンス資格情報窃取)／T1613(kubectl get pods・secrets / docker ps / crictl ps によるコンテナ/
    クラスタ探索)／T1614.001(timedatectl・systemsetup -gettimezone によるロケーション探索)／T1201(chage -l・
    /etc/login.defs・pwpolicy によるパスワードポリシー探索)／T1217(Safari/Chrome/Firefox のブックマーク・
    履歴DB読取)／T1555.003(ブラウザ資格情報ストア Login Data/key4.db/logins.json/cookies.sqlite 読取＝
    既存Windowsルールに macOS/Linux パスの横断被覆を追加)。
  - **macOS パリティ2**: T1087.001(dscl . -list /Users・dscacheutil によるアカウント探索)／
    T1136.001(sysadminctl -addUser・dscl -create /Users によるアカウント作成)。
  - scorer の technique→tactic マップに T1613(discovery)を追加。プロセス系フィールドのみ使用で
    field-support gate 通過、technique タグ先頭で primary-technique gate 通過、値クォートで
    malformed-pattern gate 通過。`attack_coverage_test.go` に7エントリ追加、単一イベント期待技術 **79/79 命中**。
    各ルールが自技法タグで発火することを個別検証。全ゲート・両モジュール build・vet 緑。
- **2026-07-10（DBエンジン相関層の回帰固定＋抽出ハーネスの穴を是正）**: A で固めたのは detection-server の
  **単一イベント**ルールだった。もう一段深く、SequenceEngine の**時間軸相関ルール**（ブルートフォース・
  ポートスキャン・ディスカバリバースト・ランサム一括暗号化・多段キルチェーン）を出荷SQLから固定。
  - **抽出ハーネスの穴を発見・是正**: A の `extractMigrationRules` は `INSERT … VALUES` 形しか解析せず、
    **`INSERT … SELECT … WHERE NOT EXISTS`（冪等）形の14マイグレーション＝32ルールを無言でスキップ**していた。
    キルチェーン相関(274/290/304/306)・discovery burst(266)・ransomware(267)・caldera/linux collection-exfil
    (283/285)・各種永続化(309/311/312)が丸ごとハーネスの射程外だった。SELECT形パーサ(`scanSelectValues`、
    top-levelの WHERE/ON CONFLICT/RETURNING/`;` で終端)を追加。抽出ルール数 **97→129**（sigma 85→105、
    behavioral 10→22、閾値型シーケンス 10→13、多段キルチェーン 0→9）。self-check 閾値を 80→115 に引き上げ、
    SELECT形の脱落を大声で検出するようにした。新たに可視化された32ルールもコンパイル/match時エラーゲート緑
    （追加の死蔵ルールは無し）。
  - **相関カバレッジ固定**: `migration_sequence_coverage_test.go` を新設。出荷 behavioral ルールを実SQLから
    SequenceEngine にロードし、代表バーストで発火固定。閾値型8シナリオ（T1110.001 SSH総当り／T1046 ポート
    スキャン／T1018 内部偵察／T1055 大量プロセス生成／T1071.004 DNS急増／T1568 DGA多ドメイン／T1033
    ディスカバリバースト／T1486 ランサム一括暗号化）＋多段キルチェーン4シナリオ（T1562.001→T1105 防御回避→
    取得／T1059→T1547.001 実行→永続化／Linux T1105→T1222.002 投下／Linux T1003.008→T1041 窃取→持ち出し）。
    従来はインラインコピー（rule_engine_test.go 等）でしか無かった相関層を、実バイト固定でドリフトゼロに。
  ★これで detection-server エンジンは**単一イベント層(A)＋相関層(本項)の両方**が実SQLで回帰保護された。
- **2026-07-10（Linux/macOS ビルトインパリティ拡充）**: api-server ビルトイン `sigma_builtins.go` は
  Windows 偏重（technique 数で **Windows 108 / Linux 33 / macOS 10**）だった。Linux 実行環境・macOS が
  EDR の主戦場であるのに希薄なため、Windows 側は被覆済みで Linux/macOS 側が未被覆の高価値技法を追加。
  - **Linux 5技**: T1046(nmap/masscan/zmap/rustscan・nc -z によるネットワークサービススキャン)／
    T1518.001(falcon-sensor/crowdstrike/sentinelone 等セキュリティ製品の列挙)／T1562.001(setenforce 0・
    firewalld/auditd 停止・ufw disable・iptables -F 等の防御無効化)／T1070.004(shred/srm/wipe による
    アンチフォレンジック消去)／T1136.001(useradd/adduser・usermod による新規アカウント作成)。
  - **macOS 3技**: T1562.001(spctl --master-disable / csrutil disable による Gatekeeper・SIP 無効化)／
    T1105(curl/wget/osascript によるペイロード取得)／T1497(system_profiler/ioreg/sysctl と VM ベンダ文字列
    照合によるサンドボックス回避)。
  - プロセス系フィールド(Image/CommandLine)のみ使用＝`TestBuiltinRuleFieldSupportAudit`(未サポート
    フィールド禁止)を通過。technique タグ先頭で `TestBuiltinSigmaPrimaryTechnique` 通過。値は全て
    クォートし `TestBuiltinSigmaNoMalformedPatterns`(コロン+空白トラップ)を通過。
  - `attack_coverage_test.go` に8エントリを追加し発火固定（単一イベント期待技術 72/72 命中）。
    健全性ゲート・全ルールコンパイル・vet・build 全て緑。scorer の technique→tactic マップも既存で網羅済み。
  ※ これは api-server の SigmaEvaluator（`[Sigma]`アラート）側。反映は server-api の再デプロイが必要。
- **2026-07-10（DBルールエンジン監査・回帰固定）**: これまでの回帰固定はすべて api-server の
  **ビルトイン `SigmaEvaluator`**（`attack_coverage_test.go` / `EvaluateEnvelope`）側だった。もう一方の
  検知エンジン＝detection-server の **`RuleEngine`/`SequenceEngine`**（本番は Postgres の `rules` テーブル＝
  `migrations/*.sql` から `ListEnabled` でロード）はコンテナ内テストの射程外で、唯一のカバレッジは
  ルール YAML を**インラインコピー**した個別テスト（「SQLを直したらコピーも直せ」というドリフト危険）だった。
  - **ハーネス新設**: `migration_rules_test.go` に `INSERT INTO rules` を実際のマイグレーションSQLから
    抽出するトークナイザ（`$$`ダラー引用・`'…'`(`''`エスケープ)・`ARRAY[...]`・5種の列順に対応）を実装。
    **出荷される97ルール（sigma 85 / behavioral 10 / yara 2、73 technique）を実バイトからロード**して
    検証＝ドリフトゼロ。将来パーサが壊れたら self-check が大声で落ちる。
  - **隠れた故障を2種3件発見・是正**:
    - **コンパイル時死蔵**: `Linux Reverse Shell via Bash`(T1059.004, migration 019) の description が
      `NOTE: auto_isolate…` とコロン+空白を含む未クォート YAML で**パース必ず失敗**＝本番で一度も評価されず。
      critical な Linux リバースシェル検知が実質無効だった。→ 019修正＋corrective migration **316**。
    - **match時死蔵**: `not_in` は sigma-go 非対応修飾子で、コンパイルは通るが**評価のたびに err**を返し
      `Evaluate` がそれを握りつぶすため無言で発火せず。`Suspicious Outbound Connection`(T1571) と
      `FTP Data Exfiltration`(T1048.003) の2件が該当。→ 標準Sigmaの `condition: selection and not filter`
      へ書換（019修正＋corrective migration **317**）。
  - **回帰ゲート3種**: `TestAllMigrationSigmaRulesCompile`（コンパイル時死蔵の再発防止）＋
    `TestNoMigrationSigmaRuleErrorsAtMatch`（match時死蔵を汎用に検出＝benignイベント評価で err を出すルールを禁止）＋
    `TestMigrationExtractor_SelfCheck`（ハーネス自身の劣化検出）。
  - **技法カバレッジ固定**: `TestMigrationRuleCoverage` に**31技法**の代表攻撃イベント→出荷ルール発火を固定
    （Windows: PS encoded/vssadmin/LSASS/PtH/wmic/psexec/mstsc/sc create/Defender改変/DL cradle/certutil/regsvr32/
    C2非標準ポート/Tor/FTP exfil、Linux: reverse shell/crontab/sudo -l/chmod tmp/passwd・shadow書換/nmap/
    password policy/timezone/timestomp/tmpスクリプト実行/.bashrc改変/curl POST exfil/セキュリティ製品列挙/
    history無効化/隠しファイル実行/Webサーバのシェル spawn）。ビルトイン側と対をなす DB エンジンの回帰網。
  ★教訓の再確認: 「別エンジンが丸ごと回帰未保護」という構造リスクを潰したら、**本番で無言で死んでいた
    critical ルールが3件**出てきた。検知率の“実効値”はコード上の被覆数ではなく**実際に発火するか**で決まる。
- **2026-07-09（バッチ①②③）**: 検知率の3方向深堀り。
  - **①回帰固定（実装済み9技）**: T1056.001(キーロガー)/T1114(メール)/T1561(ワイプ)/T1531(アカウント削除)/
    T1552.006(GPP)/T1539(Cookie)/T1547.006(カーネルモジュール)/T1546.015(COMハイジャック)/T1547.005(LSA登録)を
    `attack_coverage_test.go` に発火固定（実装済みだが未テスト＝サイレント破損リスクを解消）。
  - **②新規穴5技**: T1021.005(VNC)/T1006(直接ボリュームアクセス)/T1563.002(RDPセッションhijack tscon)/
    T1484.001(GPO改変)/T1123(音声)を新規ビルトインSigmaで追加。単一イベント被覆 TOTAL 68/78。
  - **③Technique精度**: `attack-scorer/tactics.go` に、ビルトインで検知するのに未マップだった8基底
    (T1068/T1202/T1216/T1484/T1539/T1556/T1609/T1610)を追加。検知しても scorer が Tactic 昇格できず None に
    落ちる精度損失を解消。`tactics_test.go`(tactic妥当性＋検知技の網羅)で回帰ガード。
- **2026-07-09**: Exfiltration（最希薄戦術）に **T1048**（代替プロトコル経由持出=curl/wget/tftp/IWR の
  アップロード）を**新規ビルトインSigmaで追加**＝今回は「実装済み」ではなく本物の穴だった。加えて既存
  T1567.002(rclone) が単一イベント層で発火するのに coverage_test で未検知扱い(stale bonus)だったのを
  `expectSingleEvent=true` に固定。exfil 単一イベント被覆 2→3。§13 を 🔴→🟡 に更新。
- **2026-07-09**: Lateral Movement 主要穴（T1021.004 SSH / T1021.003 DCOM / T1550.003 PtT）と
  Privilege Escalation の「最大の穴」T1134（アクセストークン操作）が**既に `sigma_builtins.go` に
  実装済みだった**ことを確認（§6/§10 の🔴穴は解消済み）。`attack_coverage_test.go` に発火テストが
  無かったため4技の単一イベント被覆テストを追加して回帰固定（lateral 6/privesc 4 エントリに拡張）。
  Defense Evasion と同型の「実装済みだが未固定」パターン。
- **2026-07-09**: Defense Evasion 古典穴（T1036.003/T1564.003/T1564.004/T1070.006/T1562.002）が
  **既に `sigma_builtins.go` に実装済みだった**ことを確認（docが陳腐化＝§7の🔴穴は解消済み）。ただし
  `attack_coverage_test.go` に発火テストが無くサイレント破損しうる状態だったため、5技の単一イベント
  被覆テストを追加して回帰ハーネスに固定（evasion 単一イベント被覆が明示的に守られる状態に）。
  ★教訓（`検知率向上と隠れた故障の是正_20260701.md` と同型）: 「新規追加」を検討すると既存が見つかる。
  検知率保護のROIは新規ルールより**既存ルールのテスト固定**が高い場合がある。
- **2026-07-09**: Credential Access 深掘りバッチをビルトインSigma（`sigma_builtins.go`）へ追加＝
  **T1003.004**(LSAシークレット `reg save HKLM\SECURITY`)／**T1003.005**(キャッシュ資格 cachedump/gsecdump/`lsadump::cache`)／
  **T1552.004**(秘密鍵 id_rsa/id_dsa/id_ecdsa/id_ed25519/.ppk)／**T1557.001**(LLMNR/NBT-NS ポイズニング Responder.py/Inveigh)。
  §8 の 🔴 穴リストから4技を被覆へ移動。`attack_coverage_test.go` の credaccess 単一イベント被覆 **5→9技**。
  健全性(TestBuiltinSigmaNoMalformedPatterns/PrimaryTechnique)・全ルールコンパイル・カバレッジ発火テスト緑。
  ※ これは api-server の SigmaEvaluator（`[Sigma]`アラート）側。detection-server の DB ルールとは別系統
  （[検知ルールの二重管理とデプロイ.md](検知ルールの二重管理とデプロイ.md)）、反映は server-api の再デプロイが必要。
- **2026-07-20**: **ランタイム相関検知スプリント＋到達性ハードニング**。単発では見えないレート/ファンアウト
  現象のステートフル検知を5種新設し、各戦略のカバレッジを面的に補強：
  - §8 Credential Access ← `authAttack`（T1110 ブルートフォース / T1110.003 スプレー、PR#486）
  - §9 Discovery ← `discovery.go` 分類器の kill-chain 供給＋偵察バースト（PR#483）
  - §10 Lateral Movement ← `lateralFanout`（T1021 横方向ファンアウト、PR#486）
  - §13 Exfiltration（🔴→🟡）← `exfilVol`（T1048 量ベース持ち出し、PR#488）
  - §14 Impact ← `fileBurst`（T1486 ランサム挙動バースト、PR#486）＋ T1489/T1529/T1497（PR#476）
  - **単一イベント被覆 80%→90%**（②〜⑦、PR#476）: builtin 79→160 ルール。
  - **サイレント故障の是正3件**: クラウドアラート無言脱落（agent_id 空→NULL、PR#480）／ランサム検知本番
    無反応（file action は `operation` キー、PR#491）／field-support 到達性（emit されているのに未サポート
    だった bytes_sent/state/old_path/file_size を追加＋同期ガードテスト、PR#492）。いずれも「作ったのに本番で
    動いていない」系の実バグをライブ検証/コード監査で発見・修正。詳細＝
    [検知率向上_20260720_サマリ_ランタイム相関と到達性ハードニング.md](検知率向上_20260720_サマリ_ランタイム相関と到達性ハードニング.md)。
  ★被覆 technique 数（115）は要再抽出（builtin が倍増したため）。
- **2026-07-07**: Linux ファイル系永続化を FIM file_event で拡充（migration 311 / #426）。§5 Persistence に
  T1546.004 / T1574.006 / T1037.004 / T1053.003 を追加、🔴 穴リストから T1037（→ Windows サブテクに限定）を除外。
  センサーは #423 の FIM /home 監視。被覆 technique 数は上記トップの「115（2026-06-23 時点）」から未再計算＝
  次回の再抽出で更新のこと。
- **2026-07-20**: 「死んでいた検知配線の復活」バッチ（詳細 [検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md](検知率向上_20260720_死んだ配線の復活と既定センサ有効化.md)）。
  §3 Initial Access に **T1091/T1200/T1052.001**（device_event 配線, #506）、§8 Credential Access で **T1078** に
  LogonType 配線（#510, **マージは 2026-08-01**）、§14 Impact の 🔴穴から **T1496**（#507）を除外。
  §7 Defense Evasion の **T1620** はメモリスキャナ既定ON化（#511）で解消（下記 2026-08-01 参照）。
  ロードマップ表 #6 の T1496 を完了マーク。被覆 technique 数は未再計算＝次回の再抽出で更新のこと。
- **2026-08-01**: 既定OFFセンサの有効化2件を Windows 実機の負荷検証を経てマージ。**#509**（加算的ETWセンサ5種＝
  リモートスレッド注入/イメージロード/PowerShell ScriptBlock/PS Module 4103/名前付きパイプ）で T1055・T1574.001/.002・
  T1059.001 のテレメトリが全 Windows 端末で恒常生成に。**#511**（メモリ/インジェクションスキャナ）で §7 Defense Evasion
  の 🔴穴から **T1620** を除外。#511 では負荷検証中に「周期をまたぐ finding 抑制機構の欠如」による重複イベント
  （約14,400件/日/台）を発見し、初回検出時のみ報告する `memFindingSuppressor` を併せて実装（定常0件/日/台に是正）。
  計測手順＝[ops/メモリスキャン負荷計測ランブック.md](ops/メモリスキャン負荷計測ランブック.md)。あわせて **#510**
  （LogonType 配線, T1078）も CI ランナー基盤障害からの再キック後に全 green を確認してマージ。これで 07-20 バッチの
  6件（#506-#511）がすべて main に入った。被覆 technique 数は未再計算＝次回の再抽出で更新のこと。
