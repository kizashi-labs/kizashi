# field-support ロングテールの完全消化と回帰カナリア — 2026-07-03 セッション総括

[検知率向上_20260702_curate衛生とplatformゲート.md](検知率向上_20260702_curate衛生とplatformゲート.md) の続報。

前回までで curate は SigmaHQ ルールを段階有効化できるようになったが、**「有効化したのに参照フィールドを
テレメトリが満たさず永久に発火しない」= false green** が残っていた。本セッションは、検証EC2 の使い捨て
`fieldcheck`（`SupportedSigmaFields`/`RuleFieldSupportWith` を import して enabled な sigmahq ルールの
field 対応を集計する Go ツール）で実測しながら、この false green を **93 → 0** まで段階的に根絶した。

本質は単発の数字ではなく、**「不足していると見えたテレメトリの多くは、実は既存機構の整合・導出・ゲート精度で
解消できた」**という発見である。真に新規のテレメトリ実装が必要だったのは PE バージョン情報と 2 つのトークン
属性のみで、残りはサーバ側の alias/導出、あるいは field-support ゲート自身のバグ修正だった。

関連 PR（すべて main マージ + 検証EC2 反映済）:
[#370](https://github.com/kizashi-labs/kizashi/pull/370)
[#374](https://github.com/kizashi-labs/kizashi/pull/374)
[#377](https://github.com/kizashi-labs/kizashi/pull/377)
[#379](https://github.com/kizashi-labs/kizashi/pull/379)
[#381](https://github.com/kizashi-labs/kizashi/pull/381)
[#383](https://github.com/kizashi-labs/kizashi/pull/383)
[#385](https://github.com/kizashi-labs/kizashi/pull/385)
[#386](https://github.com/kizashi-labs/kizashi/pull/386)
[#387](https://github.com/kizashi-labs/kizashi/pull/387)

---

## 0. false green の削減推移（検証EC2 実測、enabled sigmahq 1233 件）

| 局面 | false green | 手法 | PR |
|---|---|---|---|
| 起点（PE 前） | 93 | — | — |
| PE バージョン情報 | **14** | agent が VS_VERSIONINFO を抽出 | #370 / #374 / #377 |
| IntegrityLevel | **11** | agent がトークン整合性レベルを出力 | #379 |
| ★OR/condition 考慮ゲート根治 | **4** | field-support ゲートの構造バグ修正 | #381 |
| DNS/network 派生 | **2** | src_ip→SourceIsIpv6、query_type/answers→record_type/answer | #383 |
| LogonId | **1** | agent がトークンのログオンセッションID を出力 | #385 |
| registry EventID 合成 | **0** | registry operation→Sysmon EventID | #386 |

---

## 1. PE バージョン情報（renamed-binary / LOLBin 検知）— #370 / #374 / #377

false green の最大要因（93 件中 ~94 のルールが `OriginalFileName` 等を参照）は PE バージョンリソースだった。
`Renamed CreateDump Utility Execution` のように、**パスは偽装できるが PE 版数リソースは残る**型のルール群。

- **#370**: `ProcessEvent` に `original_file_name`/`file_description`/`product_name`/`company_name` を追加。
  Windows agent が `version.dll`（`GetFileVersionInfoSizeW`/`VerQueryValueW`）で VS_VERSIONINFO を抽出。
  サーバは `original_file_name→OriginalFileName` 等の alias。
- **#374 / #377（実機検証で判明した 2 段の欠陥を根治）**: この box は ETW 経路で、NT Kernel Logger が
  ImageFileName を**ベース名**で報告する。ベース名はディスク読取が agent サービスの CWD（System32）基準に
  解決されるため、**System32 外（renamed-binary の典型的な置き場所）は PE も hash も読めなかった**。
  - #374: ライブハンドルがあればベース名を `QueryFullProcessImageName` でフルパスに昇格。
  - #377: しかし `QueryFullProcessImageName` は ProcessStart 直後のインタラクティブセッションプロセスで
    非決定的に失敗した（DB 証跡: username 取得成功＝ハンドルは開けているのに image=ベース名/hash 空）。
    **カーネル捕捉の CommandLine の argv[0] は常にフルパスを含む**ため、これを最終フォールバックにした。
- **実機実証（box EC2AMAZ-EVVIB8T）**: notepad のコピー `ren7.exe`（偽装パス）を起動 →
  DB で `image=C:\Users\Administrator\ren7.exe`, `original_file_name=NOTEPAD.EXE` を確認。

> 教訓: 実機を通したからこそ、机上では見えない ETW ベース名の解決問題を根因特定できた。ETW 再起動直後は
> セッション確立前でプロセスを取りこぼすため、ウォームアップ後に再テストする。

---

## 2. トークン属性（IntegrityLevel / LogonId）— #379 / #385

UAC バイパス・権限昇格ルールがゲートするトークン属性。いずれも agent が username 取得で既に開いている
`OpenProcessToken` を再利用する低コスト実装。

- **IntegrityLevel（#379）**: `GetTokenInformation(TokenIntegrityLevel)` の mandatory-label SID の末尾 RID を
  Sysmon ラベル（Untrusted/Low/Medium/High/System）に変換。サーバは `integrity_level→IntegrityLevel` alias。
- **LogonId（#385）**: `GetTokenInformation(TokenStatistics)` の `AuthenticationId` LUID を `"0x%x"` 形式に
  （SYSTEM=`0x3e7`）。サーバは `logon_id→LogonId` alias。
- **実機実証（2026-07-03, box）**:

  | プロセス | integrity_level | logon_id |
  |---|---|---|
  | iltest2.exe（管理者昇格ユーザー） | `High` | `0x49d6279`（ユーザーセッション LUID） |
  | NETWORK SERVICE（サービス） | `System` | `0x3e4`（NETWORK SERVICE LUID） |

---

## 3. ★field-support ゲートを OR/condition 考慮に根治（最大の質的改善）— #381

`NewName`（registry rename）を参照する 4 ルールを「agent 実装が必要か」調査したところ、**これらは真の
false green ではなかった**。`NewName` は selection の**代替ブランチ（OR）**にのみ現れ、もう一方の
supported ブランチ（`TargetObject`/`EventType`）で**現に発火**していた。

**真因**は field-support ゲート（`RuleFieldSupportWith`）が detection の**全ブランチの全フィールド**が
supported であることを要求していたこと（`RuleSelectedFields` が全フィールドを平坦化）。OR/condition を
考慮しないため、supported ブランチで発火するルールを inert と誤判定していた（false negative）。

修正は「**supported フィールドだけで発火可能か**」を condition 評価で判定するゲート:
- ブロックの satisfiable = 全フィールド supported（map）/ いずれか supported（list = OR of サブ選択）/
  keyword list は field 非依存で satisfiable。
- `condition` を再帰下降パーサで評価（優先順位 not > and > or、`<N|all> of <pattern|them>` 量化子）。
- ★**否定項（`not filter`）は常に true** = 未サポートフィールドの filter はルールを inert にしない
  （field 不在 → filter 非マッチ → `not filter` は常に真）。
- 「フィールド参照ゼロ（keyword-only/unparseable）は enable しない」ガードは据え置きで挙動変更を最小化。

**効果**: false green **11 → 4**。NewName 4 件だけでなく、CurrentDirectory/SourceHostname/blocked 系の
**計 7 件**が正しく supported 化した。

> 教訓: fieldcheck の「false green N 件」は**過大計上**だった。`unsupported fields` リストは否定/代替ブランチの
> フィールドも挙げるため、**condition 上の必須 positive ブロッカー**を見極める必要がある（後述の
> CurrentDirectory の例）。

---

## 4. サーバ側で導出できたフィールド — #383 / #386

残件の真のブロッカーを精査すると、追加テレメトリ不要でサーバ側の alias/導出だけで解消できるものが多かった。

- **SourceIsIpv6（#383）**: WinRM リモート PowerShell ルール（5985/5986）が `SourceIsIpv6:'false'` を必須参照。
  `src_ip` から導出（IPv6 リテラルは `:` を含む）。
- **record_type / answer（#383）**: DNS TXT 実行文字列ルールが `record_type:'TXT'` + `answer|contains` を参照。
  既存の `query_type`/`answers`（配列）と同一データ。`query_type→record_type` alias ＋ answers を join して
  `answer` を導出。
- **registry EventID（#386）**: Azorult persistence ルールが `EventID:[12,13]`（Sysmon の registry
  add/delete/setvalue）を参照。registry イベント（`key_path` でゲート）の `operation` を数値 EventID に
  合成（modify→13、create/delete→12）。**file イベントも `operation` を持つため、`key_path` 有無でゲートし
  registry のみに限定**。

> 教訓（真ブロッカー精査）: `Elevated System Shell Spawned From Uncommon Parent Location` は当初
> `CurrentDirectory` が原因に見えたが、それは filter（否定側）で無害。`condition: all of selection_*` の
> `selection_user` にある `LogonId:'0x3e7'` が真のブロッカーだった。

---

## 5. 回帰防止カナリア — #387

false green を 0 にしても、**直接 enable（カテゴリ一括 `UPDATE`/手動トグル）やテレメトリ退行**で再発しうる。
これを常設監視するため、`fieldcheck` ロジックを `CurateService` の定期カナリアにした。

- **`CurateService.FalseGreenRules`**: enabled な sigmahq を `RuleFieldSupportWith` で判定し、field 非対応の
  ルール名を返す。既存の `InertRules`（挙動ベース＝7日発火0で inert を推定）の**静的 field 契約版**で、
  誤 enable の瞬間に検知できる（7日待ち不要）。`Status()` が enabled を無条件 supported 計上する穴を補完。
- **メトリクス**: `edr_curate_false_green_rules`（ゲージ、`>0` でアラート）。
- **配線**: `curate_scheduler` が inert カナリアと同ケイデンスで実行 → メトリクス set + `count>0` で警告ログ。

---

## 6. デプロイと反映状況

| 変更 | PR | main | 検証EC2 |
|---|---|---|---|
| PE バージョン情報（agent + server） | #370 / #374 / #377 | ✅ | ✅ agent は `ci.yml` 自動配信、実機 box で `ren7.exe` 実証 |
| IntegrityLevel | #379 | ✅ | ✅ `docker.yml` 反映、実機 box で実証 |
| OR/condition 考慮ゲート | #381 | ✅ | ✅ `docker.yml` 反映（curate 有効化にも波及） |
| DNS/network 派生 + LogonId + registry EventID | #383 / #385 / #386 | ✅ | ✅ `docker.yml` まとめ反映 |
| false-green カナリア | #387 | ✅ | ✅ `docker.yml` 反映 |

> 運用メモ: 本セッション終盤に GitHub Actions **予算枯渇による課金ブロック**が発生（全ジョブが 2 秒で失敗し、
> annotation に "The job was not started because an Actions budget is preventing further use."／ジョブログは
> log not found = 起動せず）。予算増額後 `gh run rerun <run-id>` で再実行して緑化した。

---

## 7. 結論

前 2 セッション（[07-01](検知率向上と隠れた故障の是正_20260701.md) / [07-02](検知率向上_20260702_curate衛生とplatformゲート.md)）
の「検知能力の空白を埋めたのではなく、既存機構の整合を恒久化した」という主題を、field-support の軸で完遂した:

1. **93 → 0**: 有効なのに永久 inert だったルールをすべて発火可能に（新規テレメトリは PE + 2 トークン属性のみ、
   残りは alias/導出/ゲート修正）。
2. **ゲート精度そのものの改善（#381）**: 「不足」に見えた多くは、ゲートが OR ブランチを考慮しない誤判定だった。
3. **回帰の構造的防止（#387）**: `edr_curate_false_green_rules` で「0」が将来崩れれば即座に可視化。

残タスクは、UAC バイパス／Elevated System Shell ルールの**実際の発火**（SYSTEM コンテキストの shell を
uncommon parent から起動する等の特定シナリオ作成）で、これは次回の Windows 能動計測で実施する。ゲート
フィールド（IntegrityLevel/LogonId 等）は既に本物のテレメトリになっている。

## 付録: 本セッションで処理した PR
#370 / #374 / #377（PE バージョン情報と ETW ベース名→フルパスの 2 段修正）/ #379（IntegrityLevel）/
#381（field-support ゲート OR/condition 考慮）/ #383（SourceIsIpv6・record_type・answer 導出）/
#385（LogonId）/ #386（registry EventID 合成）/ #387（false-green カナリア）
