# 名前付きパイプ(pipe_created)テレメトリで field 被覆軸の最後の実レバーを消化 — 2026-07-14 セッション総括

前日([検知率向上_20260713_PowerShell4103モジュールログ.md](検知率向上_20260713_PowerShell4103モジュールログ.md))で
PowerShell 4103 を消化し「残る field 実レバーは exotic な Cobalt Strike named-pipe のみ」と
結論づけた、その最後の 1 件を実装した(PR #464)。これで **field 被覆軸の実レバーは完全に
消化**され、「有効なのにテレメトリが供給されず永久に発火しない」タイプの検知ギャップは
field 軸では残っていない。

---

## 1. 対象 — なぜ field-gap カナリアに映らなかったか

対象は custom ルール **「Cobalt Strike Beacon via Named Pipe」**
([server/migrations/019](../server/migrations/019_sigma_community_rules.sql), rule id
`a1b2c3d4-0005-…-025`, `enabled=true` / severity 9 / `auto_isolate=true`)。detection は
**`PipeName|contains`** のみを選択(`\postex_` / `\mojo.` / `\interprocess_` / `\msagent_` /
`\DserNamePipe` / `\wkssvc_`)= C2 フレームワーク(Cobalt Strike & クローン)がビーコン連結・
ポストエクスプロイトに使う予測可能な名前付きパイプの名前。

このルールは有効だが `PipeName` がテレメトリに一切流れないため**永久に inert** だった。
**field-gap カナリア(`FieldGapReport`)は `source='sigmahq'` のみを走査**するのに対し、本ルールは
**`custom` ソース**ゆえカナリアに映らなかった。これは 2026-07-08 の inert 監査
(logsource-category に対応するテレメトリ型が無い、という別の死蔵次元)で特定していた最後の 1 件。
= 死蔵ルールには「fieldcheck/false-green(フィールド欠落)」「コンパイル失敗」「テレメトリ型欠落」の
3 次元があり、本件は 3 番目・かつ custom ソースという二重の盲点だった。

---

## 2. 実装(PR #464, マージ済)

CreateRemoteThread(#445)/ 4103(#458)で確立した「ETW collector が sender 経由で JSON-prefix
ログイベントを直接送出する」パターンを踏襲。**新カテゴリを end-to-end** で通す(既存経路不変・
proto 変更なし)。

### エージェント
- **`ETWPipeCollector`**([agent/internal/platform/windows/pipe_etw.go](../agent/internal/platform/windows/pipe_etw.go))
  = **Microsoft-Windows-Kernel-File** プロバイダ(`{edd08927-…}`)を Create キーワード
  (`KERNEL_FILE_KEYWORD_CREATE 0x80` | `CREATE_NEW_FILE 0x1000`)で購読。名前付きパイプは
  `\Device\NamedPipe\` 配下のファイルオブジェクトなので、コールバックで `FileName` がこの
  プレフィックスを持つものだけを残す。
- **`PipeName`** = Sysmon 形式(`\Device\NamedPipe\msagent_5x` → `\msagent_5x`、ルールの
  `\msagent_` に一致)。**`Image`** = `pidToName(headerPID)`(best-effort)。
- **`BuildNamedPipeEvent`**([agent/internal/collector/named_pipe.go](../agent/internal/collector/named_pipe.go))
  = `pipe_created:<uuid>:<json>`(inner JSON = `{pipe_name, image_path, pid}`)を
  `EVENT_TYPE_LOG` で送出。
- opt-in `EDR_AGENT_ETW` / sender 経由 / 非 Windows は nil stub / session 失敗で no-op。

### サーバ
- **ingestion**([handler.go](../server/internal/ingestion/handler.go)): `promoteEventType` +
  `normalizeEventData` に `pipe_created:` プレフィックス展開。
- **alias**([alert_pipeline.go](../server/internal/detection/alert_pipeline.go)):
  `pipe_name`→`PipeName`(`image_path`→`Image` は既存)。
- **field-gate**([field_support.go](../server/internal/detection/field_support.go)):
  `SupportedSigmaFields` の kitchen に `pipe_name` を追加。

### テスト
- `BuildNamedPipeEvent` wire-format / `pipe_name`→`PipeName` alias + field-support /
  `promoteEventType` の pipe_created ケース。
- agent Windows+host build + collector test PASS / server build 緑。detection・ingestion の
  ユニットテストは Defender ローカル制約のため **CI(Linux)で実行**、全チェック緑。

---

## 3. 設計上の注意点・限界

- **ETW プロバイダ選定**: 名前付きパイプ専用の ETW キーワードは無い。Kernel-File の Create
  キーワードは**全ファイル作成を配信**し、コールバックで `\Device\NamedPipe\` プレフィックスに
  絞る(cheap prefix check)。opt-in・additive だが、常時オンにするとファイル作成 firehose の
  コールバックコストがかかる。**本番グレードの低オーバーヘッド源は名前付きパイプ minifilter**
  (Sysmon が EID17/18 に採用している方式)。
- **実機発火は Windows 箱で follow-up**(方針A=コード先行)。Create の正確な EventID /
  プロパティ名 / header PID の populated 有無(manifest プロバイダは golang-etw が System
  ヘッダを 0 埋めする場合がある。Kernel-Registry で既知)は実機で確定。`PipeName` のみで
  ルールは発火するため、Image が取れなくても検知は成立する。

---

## 4. 運用インシデント: 共有リポで作業ツリーを別ブランチに奪われる

マージ直前、**並行セッションが共有作業ディレクトリを別ブランチ(`feat/detection-consumer-scale`)
に checkout** したため、手元の `git show HEAD:<path>` や `ls` が別ブランチを指し「自分の変更が
消えた」と一時誤診断した。**真実は push 済みで無事**(`origin/<自分のbranch>` に全ファイル・
CI 緑を確認)。

- 教訓: **push 後はローカル HEAD が並行セッションに動かされる前提**で検証する。自分の成果の
  確認は `git show origin/<自分のbranch>:<path>` で行い、ローカル HEAD/作業ツリーを信用しない。
- `gh pr merge` はリモート操作なのでローカル checkout 位置に依存せずマージできる。
- 本ドキュメント整備もこの理由で、共有作業ツリーを触らず **`git worktree` で origin/main を
  別ディレクトリに展開**して行った(read-only 計測と同じ非破壊手順)。

---

## 5. 結論: field 被覆軸は完全にクローズ

- **field 被覆軸の実レバーは完全に消化**した: 4103 module log(#458)/ named-pipe(#464)。
  「有効なのにテレメトリが供給されず発火しない」検知ギャップは field 軸では残っていない
  (field 被覆 98.6% + custom 側の最後の 1 件も解消)。
- 検知率の次のフロンティアは field 被覆でなく、**別軸の運用信頼性**へ完全に移った。特に
  「保存されるのに検知されない」= **detection-engine consumer の慢性ラグ**(NATS jsz
  num_pending が数百万、DB ルール経路が追いつかず未発火)が最大の実ギャップで、consumer 水平
  スケール(別セッションの `feat/detection-consumer-scale`)が着手中。

---

## 付録: 本セッションで処理した PR
- **#464** — 名前付きパイプ(pipe_created)テレメトリ(`ETWPipeCollector` +
  pipe_created ingestion/alias/field-gate + テスト3種)【マージ済、CI 全緑】
