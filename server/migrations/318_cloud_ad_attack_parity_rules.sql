--
-- ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
--
-- 本流の同名ファイルは、スキーマ変更のあとに検知ルールの INSERT が続く。
-- 公開版は検知コンテンツをパックで配るので、**スキーマ変更だけを残し、
-- INSERT を落とした版**がこれ。
--
-- ファイルごと除外できないのは、events_event_type_check の付け替えなど
-- スキーマ側が公開版でも必要なため。番号とファイル名は本流と同一にする
-- （schema_migrations は version としてファイル名を持つので、名前を変えると
-- 適用済みの環境で再実行される）。
--
-- 落としたルールは rulepacks/ に入っている。公開版に同梱されるのは
-- baseline.json のみ。
--

-- 318: detection-server (DB RuleEngine) パリティ。
--
-- api-server のビルトイン SigmaEvaluator に本スプリントで拡充した高価値の
-- クラウド/AD 攻撃検知を、もう一方の検知エンジン(detection-server RuleEngine)にも
-- 移植する。両エンジンで被覆することで、片方のイベント経路しか通らない攻撃も捕捉できる。
--
-- 全ルールは CommandLine|contains のみで選択(RuleEngine の field mapping で解決可能=
-- 死蔵を避ける)。platform は linux/windows/macos を明示(クラウドCLI/Impacket 等は
-- クロスプラットフォーム。process_creation category-only なので実質ユニバーサル)。
-- 冪等化は WHERE NOT EXISTS。以後の回帰は migration_rules_test.go 群
-- (compile / match時err / field-support / coverage)が固定する。

-- ── 前提: rules.source に 'builtin-parity' を許可する ─────────
-- このバッチ(318〜356)は全ルールを source='builtin-parity' で INSERT する。
-- しかし rules_source_check(001 で作成 / 276 で再定義)はこの値を許可しておらず、
-- 制約違反で INSERT が ERROR → RunMigrations が失敗 → api-server が起動不能になる
-- (CHECK 違反は "無言 drop" ではなく HARD ERROR。migrate.go は os.Exit(1))。
-- パリティ移行の先頭(=最初に 'builtin-parity' を INSERT する 318)で制約を広げる。
-- 冪等(DROP IF EXISTS → ADD)。276 の許可集合を保持し 'builtin-parity' を追加。
-- 以後の回帰は migration_source_constraint_test.go の適合テストが固定する。
ALTER TABLE rules DROP CONSTRAINT IF EXISTS rules_source_check;
ALTER TABLE rules ADD CONSTRAINT rules_source_check
    CHECK (source = ANY (ARRAY[
        'community'::text,
        'custom'::text,
        'threat-intel'::text,
        'ai-generated'::text,
        'builtin'::text,
        'sigmahq'::text,
        'builtin-parity'::text
    ]));

-- ── T1526 : クラウドサービス/IAM 探索 ───────────────────────
