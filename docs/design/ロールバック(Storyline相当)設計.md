# ロールバック（SentinelOne Storyline 相当）設計

**目的**: 競合評価（`docs/競合評価.md` §7）で「唯一 SentinelOne(Storyline) に劣る機能ギャップ」「roadmap 短期・優先度高」
とされた**ロールバック機能**を実装する設計。インシデント（悪性プロセス/脅威）が加えた**ファイルシステム変更を
再構成し、感染前の状態へ一括で戻す**——特にランサムウェアで暗号化・削除されたファイルの復元。

**位置づけ**: `docs/EDR競争力向上ロードマップ` の短期項目。SOAR/レスポンス（隔離・kill・検疫）の延長線上の
「修復（remediation）」レイヤ。

---

## 0. 前提の再確認 — まず既存を精査した（新規実装ではなく差分設計）

規律に従い着手前にコード精査した。**単一ファイルの検疫と復元は既存**であり、設計はその上に
「インシデント単位の変更ジャーナル＋反転プランニング」を積む差分となる。

### 既にあるもの（再利用する土台）
| 機能 | 実体 | 用途 |
|---|---|---|
| **ファイル検疫＋復元** | `agent .../collector.FileQuarantine`（`Quarantine`/**`Restore`**/`List`、Linux/macOS/Windows 実装） | 単一ファイルを退避し元パスへ戻せる＝**復元の実行部は既にある** |
| レスポンスアクション配信 | `detection.AgentCommander`（`IsolateEndpoint`/`KillProcess`/`QuarantineFile`） | サーバ→エージェントのコマンド配信口 |
| アクション監査 | `response_actions` テーブル（008）+ `ResponseActionLog` | 実行記録 |
| ファイルイベント収集 | agent `file_collector`（Linux eBPF `file_monitor` 他）/ FIM | 変更ジャーナルの**入力源** |

### 本当に無いもの（＝この設計で埋める差分）
1. **変更ジャーナル（インシデント→変更の対応台帳）** — どの脅威がどのファイルをどう変えたかを紐付けて記録する層。
2. **ロールバック・プランニング** — 記録された変更列から**反転操作の集合**（元内容の復元／攻撃生成物の削除）を
   再構成する頭脳。★本設計の中核・純ロジック。
3. **変更前バックアップ（copy-on-write）** — modify/delete の**前に**元内容を退避しておく agent 側の仕組み
   （ランサム復元に必須）。検疫の Restore は「隔離した実体」を戻すが、暗号化で**上書き**されたファイルの
   元内容は別途 pre-image バックアップが要る。
4. **修復オーケストレーション/API** — インシデント単位の preview / rollback 実行。

---

## 1. アーキテクチャ

```
[endpoint]                                   [server]
悪性プロセス実行
  │ file modify/delete/create
  ▼
agent copy-on-write バックアップ(pre-image)  ──telemetry/action──▶  RemediationJournal(DB)
  （検疫 Restore の退避ストアを流用）                                   │  incident→変更の台帳
                                                                       ▼
                                                       RollbackService.Plan(incident)
                                                          変更列 → 反転操作の集合(純ロジック)
                                                                       │ preview
                                                                       ▼
アナリストが preview を確認 → rollback 実行 ──command──▶ AgentCommander.RestoreFile/DeleteFile
  agent が pre-image を書き戻し / 生成物を削除                          │
                                                          MarkReverted(journal 更新)
```

## 2. データモデル（migration 315: `remediation_journal`）

| 列 | 型 | 意味 |
|---|---|---|
| id | TEXT PK | |
| incident_id / alert_id | TEXT | 紐付く脅威 |
| agent_id | TEXT | 対象端末 |
| path | TEXT | 操作対象ファイル |
| operation | TEXT | `create`/`modify`/`delete`/`rename` |
| backup_ref | TEXT | pre-image バックアップID（modify/delete の元内容。create は空） |
| old_path | TEXT | rename 元 |
| occurred_at | TIMESTAMPTZ | 発生時刻（反転の順序決定に使用） |
| reverted | BOOL / reverted_at | ロールバック済みか |

## 3. ★中核：ロールバック・プランニング（純ロジック）

インシデントの変更列（時系列）から、感染前状態へ戻す**最小の反転操作集合**を再構成する。
`server/internal/rollback` に純関数として実装（DB 非依存＝テスト可能）。

### 反転の原理（path 単位）
各 path について、インシデントが**最初に**行った操作で「感染前に存在したか」と「元内容」が決まる:

| インシデントの最初の操作 | 感染前の状態 | 反転操作 |
|---|---|---|
| `create` | 存在しなかった | **delete**（攻撃生成物を削除。中間状態不問） |
| `modify` | 存在した（backup_ref=変更前内容） | **restore**（最初の modify 前の pre-image を書き戻す） |
| `delete` | 存在した（backup_ref=削除前内容） | **restore**（削除前 pre-image を書き戻す） |

- **最初の操作が決定的**: 同 path を複数回 modify しても、戻すべきは「最初の modify の**前**」の内容。中間状態は無視。
- **created→deleted（差し引きゼロ）**: 最初=create → 反転=delete（既に消えていれば no-op で安全）。
- **backup_ref 欠落（バックアップ失敗）**: restore 必要だが pre-image が無い → **`NeedsManual` フラグで表面化**
  （黙って落とさない＝誠実さ。アナリストに手動対応を促す）。
- 決定性: 出力は path 昇順に整列（テスト・レビュー容易）。

### 出力
`RollbackPlan{ IncidentID, Ops []RollbackOp{ Path, Action(restore|delete), BackupRef, NeedsManual, Reason } }`

## 4. 段階実装計画

| Ph | 内容 | 依存 | この場で可 |
|---|---|---|---|
| **Ph1** ✅**実装済（2026-07-09）** | **ロールバック・プランニング純ロジック**（変更列→反転操作）＋テスト。`server/internal/rollback/rollback.go`＝`Plan(incidentID, entries) RollbackPlan`。create→delete / modify・delete→restore(最初のpre-image) / backup欠落→NeedsManual / path昇順の決定的出力。テスト8件（多重modifyは最初のpre-image・created→deletedはdelete・欠落はNeedsManual・順不同でも最初の操作が決定・空/空パス）緑。 | 無し | ✅ サーバ完結・テスト可 |
| **Ph2** ✅**実装済（2026-07-09）** | `remediation_journal`(migration 315) + `RollbackService`（`RecordChange`/`Plan`/`Preview`/`MarkReverted` の DB 配線）。純 `Plan` に委譲し DB は journal の永続化/読込のみ。fake DB テスト5件（INSERT で空=NULL / Plan がロード→反転 / Preview=Plan / MarkReverted の UPDATE と rows-affected / 空パスは no-op）。 | DB | ✅ fake DB でテスト済 |
| **Ph3** ✅**実装済（2026-07-09）** | API: `GET /api/v1/admin/incidents/:id/rollback/preview` / `POST .../rollback`(admin, `RollbackHandler`) + 実行オーケストレーション `rollback.Execute`（restore/delete 配信・NeedsManual はスキップ）+ `CommandStore.DeleteFile` 追加（`RestoreFile` は既存を再利用）。破壊的操作のため preview と execute を分離。テスト: `rollback.Execute` 3件（restore+delete配信/NeedsManualスキップ/配信エラー表面化）+ handler 3件（preview の needs_manual/execute の配信+MarkReverted/agent_id 必須）。 | Ph2 | ✅ fake でテスト済 |
| Ph4 | ★agent **copy-on-write pre-image バックアップ**（modify/delete の前に元内容を退避。検疫の退避ストアを流用）＋実機検証 | **agent 改修＋実機** | ✗ |

**推奨**: Ph1（中核の頭脳）を先に固め、Ph2–3（DB/API）はサーバ側で続け、Ph4（agent copy-on-write）は
JA3(Ph4) と同様「センサ深度の別トラック・実機検証必須」。

## 5. FP・安全設計
- ロールバックは**破壊的**（ファイルを書き換える）。必ず **preview→アナリスト承認→実行**の二段。自動実行しない。
- restore は検疫 Restore と同じ TOCTOU 対策（`O_NOFOLLOW`・fd ベース）を踏襲。
- `NeedsManual` を必ず表面化し、「戻せたつもりで戻せていない」を防ぐ。
- 反転操作も `response_actions` に記録（監査証跡）。

## 7. Ph4 詳細設計 — agent copy-on-write pre-image バックアップ

Ph1–3（プランニング／DB／API・実行配信）はサーバ側で完結・実装済み。**残る Ph4 だけが agent 改修＋実機
検証を要する重量級**——ランサムで**上書き/削除された元内容を戻す**ための pre-image バックアップである。
着手前の精査で、**ファイル退避ストアと復元実行部は既存**（`FileQuarantine`＝dir＋生成ID＋`index.json`／
`Restore`）と判明。Ph4 はこれを「変更前に**コピー**して退避する CoW ストア」へ拡張する差分。

### 7.0 ★重要な前提 — Ph1–3 だけで「部分ロールバック」は既に可能
反転操作のうち **create の反転（生成物の delete）は pre-image バックアップ不要**（消すだけ）。また**検疫済み
ファイルの restore** も既存の退避実体で戻せる。つまり **「攻撃が作ったファイルの除去」と「検疫したファイルの
復元」は Ph1–3 で今すぐ機能する**。Ph4 が要るのは **modify/delete された（検疫していない）ファイルの元内容
復元**——ランサム暗号化の本丸——に限られる。この切り分けを明示する（過大約束を避ける）。

### 7.1 中核の難所 — 「変更**前**」に元内容を確保する
`FileEvent`（`Action: create|modify|delete|rename`, `Path`, `OldPath`, `PID`, `ProcessName`）は変更を**事後**に
観測する。しかし上書き後には元内容は無い。→ **書き込み前に割り込んで pre-image を退避する**必要がある
（＝真の copy-on-write）。これはカーネルレベルの前置フック無しには達成できない。

### 7.2 バックアップのスコープ制御（全書き込みは非現実的）
全ファイル書込を退避すると容量・性能が破綻する。**保護対象を絞る**:
- **保護パス・ポリシー**（ユーザ文書・共有・重要ディレクトリを対象、`/tmp`・ビルド生成物は除外）。
- **ランサム挙動トリガ**：短時間の多数ファイル改変・高エントロピー書込（既存 `ransomware_handler` の
  entropy 検知と接続）を検出したら、そのプロセスが触る保護パスを CoW 対象に昇格。
- **容量クォータ＋リングバッファ**（古い pre-image から evict）。これで退避量を有界化。

### 7.3 OS 別の前置フック（サブフェーズ）
| サブPh | OS | 手法 | 依存・リスク |
|---|---|---|---|
| **Ph4a** | Linux | **fanotify** `FAN_OPEN_PERM`/`FAN_MODIFY`（permission event）で open-for-write を捕捉→元内容を CoW ストアへコピー→許可 | `CAP_SYS_ADMIN`。既存 eBPF file_monitor と別機構（perm event が要る） |
| Ph4b | Windows | **minifilter ドライバ**（`IRP_MJ_WRITE` pre-callback で pre-image コピー）または **VSS スナップショット** | minifilter は**ドライバ署名(W5 EV+WHQL)依存**＝JA3 Windows と同じゲート。VSS は署名不要だが粒度が粗い |
| Ph4c | macOS | ESF は書込 payload の前置コピー不可 → 実質 VSS 相当が無い。最劣後（保護パスの定期スナップショットで代替） | entitlement 制約 |

### 7.4 CoW バックアップストア（既存検疫ストアを拡張）
- `FileBackup` インターフェース（`FileQuarantine` と同型）: `Backup(path) (backupRef, err)`（**move でなく copy**）/
  `Restore(backupRef, restorePath)` / `Evict(backupRef)`。dir＋生成ID＋`index.json`（`backupRef→{OrigPath,Hashes,Size,At}`）。
- **TOCTOU 対策**は検疫と同一（`O_NOFOLLOW`・fd ベースのコピー、シンボリックリンク差し替え防止）。
- クォータ超過で古い ref を evict。復元実行は Ph3 の `restore_file` コマンドが `Restore(backupRef, path)` を呼ぶ
  （backup_ref をそのまま渡す既存経路）。

### 7.5 サーバへの登録（journal 連携＝Ph2 の RecordChange）
- CoW 退避時、agent は変更を `RollbackService.RecordChange`（Ph2）へ登録：
  `{incident_id?, agent_id, path, operation, backup_ref, old_path, occurred_at}`。
- インシデント紐付け：まだインシデント未確定の時点の退避は `incident_id` 空で先行記録し、後で検知が同 PID/
  プロセスをインシデント化した際に**遡って紐付け**（プロセス系譜で PID→incident を解決）。この「先行退避→
  事後紐付け」がランサム復元の肝（暗号化が始まってからでは遅い）。

### 7.6 Ph4 内サブフェーズ（推奨順）
1. ✅**Ph4a-1 実装済（2026-07-09）: CoW バックアップストア（`agent/internal/backup`）**。`Store.Backup(path)→ref`
   (**move でなく copy**)/`Restore(ref, path)`/`Evict`/クォータ超過で古い ref から自動 evict/`index.json` 永続化。
   ★TOCTOU: Lstat の symlink 拒否＋`O_NOFOLLOW`（unix、windows は build tag で no-op＋Lstat で担保）。テスト5件
   （バックアップ→上書き→復元でランサム復元フロー/evict/クォータで古い順 evict/symlink 拒否/index 永続化）。
   **linux・darwin・windows の3クロスコンパイル緑**。Ph3 の restore 実行がこの `Restore(ref, path)` を呼ぶ。
2. Ph4a-2: Linux fanotify perm-event 前置フック＋保護パス／ランサム挙動トリガ＋実機検証。
3. Ph4a-3: journal 先行登録＋PID→incident 遡及紐付け。
4. Ph4b: Windows（VSS 優先→不可なら minifilter＋署名調達）。
5. Ph4c: macOS（保護パス定期スナップショットで代替）。

> ★**最小の第一歩**: Ph4a-1（`FileBackup` の copy/restore/evict 純 I/O）は、fanotify 等の前置フックと独立で、
> Ph4a-2 以降の重量級（カーネル・OS 差・実機）を後段に分離できる。JA3 Ph4a-1（純ロジック先行）と同じ戦略。

## 8. スコープ外
- ブロックレベルのファイルシステムスナップショット（VSS/Btrfs snapshot 連携は将来）。本設計は変更単位の
  pre-image バックアップ方式（Storyline と同型）。
- レジストリ・ロールバック（Windows）は同モデルの拡張として別途（本設計はファイル系を先行）。
