#!/usr/bin/env python3
"""検査が、製品ではなく検査自身の写しを試していないこと。

対象:
  server/internal/store/tenant_roles.go
  server/internal/api/handlers/incident_comments_handler.go
  server/internal/store/reproduced_logic_test.go

`internal/store` の検査ファイルには、製品のロジックを**書き写した**
ヘルパーが並んでいます:

    // hasRolePure は HasRole メソッドの純粋なロジック部分を再現する
    // ヘルパー（テスト専用）

**写しを試しても、製品の側は無傷のまま壊せます。** 実測 (2026-08-11):
`HasRole` の `>=` を `<=` に変えても、落ちる検査は1本もありませんでした
—— viewer が tenant_admin の要件を満たし、tenant_admin が満たさなくなる、
権限判定のまるごとの反転です。

もう1つの形があります。**製品にその規則が無いのに、検査だけが持っている**
場合です。`isValidCommentBody` は「空白のみは無効」「10,000 文字超は無効」
と言いますが、製品は `binding:"required"` しか見ておらず、**空白だけの
本文も、100万文字の本文も通していました。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  「送る側が、切り出した組み立てを通らなくなる」も置いてみて、生き残った
  ので外しました。**同じ文字列を書き直すだけなので、振る舞いが変わりません**
  —— 殺せる検査がありません。代わりに、組み立てそのものを壊す変異
  （購読パターンから外れるサブジェクトを送る）を置いてあります。

  「数えた結果を上限にかけなくなる」も置いてみて、生き残ったので外しました。
  数える側も上限の判定も別に留めてありますが、**その2つを繋ぐ1行を消すのは
  「その検査を消す」のと同じ**で、殺せる検査がありません。代わりに、
  判定 (`reproductionComplaint`) と数え方 (`reproductionMarkers`) を
  それぞれ壊す変異を置いてあります。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

R = 'server/internal/store/tenant_roles.go'
C = 'server/internal/api/handlers/incident_comments_handler.go'
G = 'server/internal/store/reproduced_logic_test.go'

CASES = [
    # ── 権限比較 ───────────────────────────────────────────────────────────
    (R, '\treturn currentWeight >= requiredWeight\n}',
        '\treturn currentWeight <= requiredWeight\n}',
     '権限判定を反転する（viewer が tenant_admin の要件を満たします）'),
    (R, '\trequiredWeight, ok := roleWeight[requiredRole]\n\tif !ok {\n\t\treturn false\n\t}',
        '\trequiredWeight, ok := roleWeight[requiredRole]\n\tif !ok {\n\t\treturn true\n\t}',
     '知らない要求ロールを「満たしている」に倒す'),
    (R, '\tcurrentWeight, ok := roleWeight[currentRole]\n\tif !ok {\n\t\treturn false\n\t}',
        '\tcurrentWeight, ok := roleWeight[currentRole]\n\tif !ok {\n\t\treturn true\n\t}',
     '知らない現在ロールを「強い」に倒す'),
    (R, '\treturn roleAtLeast(currentRole, requiredRole), nil',
        '\treturn true, nil',
     'HasRole が、切り出した判定を通らなくなる'),

    # ── コメント本文 ───────────────────────────────────────────────────────
    (C, '\tif strings.TrimSpace(body) == "" {',
        '\tif strings.TrimSpace(body) == "" && body == "" {',
     '空白だけの本文を受け入れる（binding:"required" と同じに戻ります）'),
    (C, '\tif utf8.RuneCountInString(body) > maxCommentBodyLength {',
        '\tif utf8.RuneCountInString(body) > 0 && len(body) > maxCommentBodyLength {',
     '長さをバイト数で数える（日本語が3分の1の長さで弾かれます）'),
    (C, '\tif utf8.RuneCountInString(body) > maxCommentBodyLength {',
        '\tif utf8.RuneCountInString(body) > maxCommentBodyLength*100 {',
     '上限を実質外す（カラムは TEXT で、そのまま入ります）'),
    (C, '\tif msg := validateCommentBody(req.Body); msg != "" {\n'
        '\t\tc.JSON(http.StatusBadRequest, gin.H{"error": msg})\n\t\treturn\n\t}', '',
     '検証を呼ばなくなる'),

    # ── 表示設定の既定値 ───────────────────────────────────────────────────
    ('server/internal/store/user_preferences_store.go', '\t\tprefs.Theme = "dark"', '\t\tprefs.Theme = "light"',
     '既定のテーマを変える'),
    ('server/internal/store/user_preferences_store.go', '\tprefs = applyPreferenceDefaults(prefs)', '',
     'Upsert が、切り出した既定値を通らなくなる'),

    # ── 通知履歴 ───────────────────────────────────────────────────────────
    ('server/internal/store/notification_history.go', '\t\tnilIfBlank(e.ChannelID)', '\t\te.ChannelID',
     'チャンネルIDが空の通知を記録できなくする（元の実装）'),
    ('server/internal/store/notification_history.go', "COUNT(*) FILTER (WHERE status='failed')",
        "COUNT(*) FILTER (WHERE status='failure')",
     '失敗の集計が、実在しない状態を数える'),

    # ── ページの切り詰め ───────────────────────────────────────────────────
    ('server/internal/api/handlers/notification_history_handler.go', '\tif perPage < 1 || perPage > maxNotificationPerPage {',
        '\tif perPage > maxNotificationPerPage {',
     'per_page が 0 のとき 0 件返す（「履歴が無い」と見分けが付きません）'),
    ('server/internal/api/handlers/notification_history_handler.go', '\tif page < 1 {\n\t\tpage = 1\n\t}', '',
     '負のページを通す（負の OFFSET は Postgres が拒否します）'),
    ('server/internal/api/handlers/notification_history_handler.go', '\treturn page, perPage, (page - 1) * perPage',
        '\treturn page, perPage, page * perPage',
     'オフセットが1ページぶんずれる'),

    # ── WHERE 句の組み立て ─────────────────────────────────────────────────
    ('server/internal/store/incidents.go', '\t\twhere += " AND i.status IN (\'open\',\'investigating\',\'contained\')"',
        '\t\twhere += " AND i.status IN (\'open\',\'investigating\')"',
     'active の絞り込みから contained が落ちる（対応中のインシデントが'
     '一覧から消えます）'),
    ('server/internal/store/incidents.go', '\tif status == "active" {', '\tif false {',
     'active が「status = \'active\'」になる（該当なしと同じ姿です）'),
    ('server/internal/store/ioc.go', '\t\twhere += " AND i.is_active = TRUE"',
        '\t\twhere += fmt.Sprintf(" AND i.is_active = TRUE AND $%d = $%d", len(args)+1, len(args)+1)',
     '値を取らない条件がプレースホルダを進める（一覧が丸ごと落ちます）'),
    ('server/internal/store/audit.go', '\t\tconds = append(conds, fmt.Sprintf("user_id = $%d", len(args)+1))\n'
        '\t\targs = append(args, f.UserID)\n\t}', '\t}',
     '監査ログの UserID 絞り込みが消える（写しにも無かった分岐）'),
    ('server/internal/store/audit.go', '\t\tconds = append(conds, fmt.Sprintf("action = $%d", len(args)+1))',
        '\t\tconds = append(conds, fmt.Sprintf("action ILIKE $%d", len(args)+1))',
     'Action の完全一致が前方一致になる'),
    ('server/internal/store/audit.go', '\t\tconds = append(conds, "status_code >= 400")',
        '\t\tconds = append(conds, fmt.Sprintf("status_code >= $%d", len(args)+1))',
     'OnlyErrors がプレースホルダを進める（以降の引数がずれます）'),

    # ── ライブレスポンス ───────────────────────────────────────────────────
    ('server/internal/store/live_response.go', '\tif hasError || exitCode != 0 {', '\tif hasError {',
     '終了コードが 0 でないコマンドを「成功」として保存する（元の実装。'
     'コンソールは status だけを見ます）'),
    ('server/internal/store/live_response.go', '\tif hasError || exitCode != 0 {', '\tif hasError && exitCode != 0 {',
     '起動できなかったコマンドを「成功」として保存する'),
    ('server/internal/store/live_response.go', '\treturn "error"\n\t}\n\treturn "completed"',
        '\treturn "failed"\n\t}\n\treturn "completed"',
     'スキーマに無い状態名を使う（CHECK 制約に弾かれ、結果が1件も残りません）'),
    ('server/internal/store/live_response_store.go', '\tif in.Args == nil {\n\t\tin.Args = json.RawMessage("{}")\n\t}', '',
     'Args の既定値を入れない（jsonb は NOT NULL —— コマンドが待ち行列に'
     '載りません）'),

    # ── 一覧の絞り込み ─────────────────────────────────────────────────────
    ('server/internal/store/agents.go', '\t\t\t"(hostname ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(ip_addresses) ip WHERE ip::text ILIKE $%d))",\n\t\t\ti, i,',
        '\t\t\t"(hostname ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(ip_addresses) ip WHERE ip::text ILIKE $%d))",\n\t\t\ti, i+1,',
     '検索が引数を2つ使う形になる（引数が1つ足りず、端末の一覧が落ちます）'),
    ('server/internal/store/agents.go', '\tif len(conditions) == 0 {\n\t\treturn "", args\n\t}',
        '\tif false {\n\t\treturn "", args\n\t}',
     '条件が無くても WHERE を出す（構文エラーになります）'),
    ('server/internal/store/device_events.go', '\t\treturn 50\n\t}\n\tif limit > 500 {', '\t\treturn 0\n\t}\n\tif limit > 500 {',
     'デバイスイベントの既定件数が 0 になる（記録が無いのと同じ姿です）'),
    ('server/internal/store/device_events.go', '\tif limit > 500 {\n\t\treturn 500\n\t}', '',
     'デバイスイベントの上限が外れる（1回の要求で全件読みます）'),
    ('server/internal/store/fim_rules.go', '\t\treturn 100\n\t}\n\tif limit > 500 {', '\t\treturn 0\n\t}\n\tif limit > 500 {',
     'FIM ルールの既定件数が 0 になる（監視ルールが無いのと同じ姿です）'),
    ('server/internal/store/fim_rules.go', '\tif f.Enabled != nil {', '\tif f.Enabled != nil && *f.Enabled {',
     'enabled=false の絞り込みが効かなくなる（nil と false を同じに扱います）'),

    # ── webhook のイベント名 ───────────────────────────────────────────────
    ('server/internal/notification/webhook_events.go', '\t"agent.offline",\n}', '}',
     '送られるイベントの一覧から agent.offline が落ちる'),
    ('server/internal/notification/webhook_events.go', '\t"alert.any",\n', '\t"alert.any",\n\t"incident.created",\n',
     '送られないイベントを一覧に足す（画面がそれを出せるようになります）'),
    ('server/internal/notification/webhook_events.go',
     '\t\tif e == event {', '\t\tif e != "" {',
     '何でも「送られる」に分類する（画面の照合が意味を失います）'),
    ('frontend/app/settings/webhooks/page.tsx', "  { value: 'agent.offline',     label: 'エージェント: オフライン', color: 'text-purple-400' },",
        "  { value: 'agent.offline',     label: 'エージェント: オフライン', color: 'text-purple-400' },\n"
        "  { value: 'incident.created',  label: 'インシデント: 作成',       color: 'text-blue-400' },",
     '画面が、送られないイベントをまた出す'),
    ('server/internal/notification/webhook.go', '\tcase "critical":\n\t\treturn "alert.critical"', '\tcase "critical":\n\t\treturn "alert.urgent"',
     '対応付けが一覧に無いイベント名を返す'),

    # ── ライブレスポンスのサブジェクト ─────────────────────────────────────
    ('server/internal/store/command_store_lr.go', '\treturn "commands." + agentID + ".live_response_start"',
        '\treturn "commands." + agentID + ".live_response"',
     '購読パターンから外れるサブジェクトを送る（開始要求が届きません）'),

    # ── 既定ポリシー ───────────────────────────────────────────────────────
    ('server/internal/store/agent_policies.go', '\tif id == defaultPolicyID {', '\tif false {',
     '既定ポリシーを削除できるようにする（端末がどのポリシーも受け取らなくなります）'),
    ('server/internal/store/agent_policies.go', '\tif tag.RowsAffected() == 0 {',
        '\tif tag.RowsAffected() < 0 {',
     '0行の削除を成功として返す（「消えた」と「無かった」が同じになります）'),

    # ── タグ ───────────────────────────────────────────────────────────────
    ('server/internal/api/handlers/agent_tag_handler.go', '\t\tif _, ok := seen[t]; !ok {', '\t\tif true {',
     '重複するタグを除去しない'),
    ('server/internal/api/handlers/agent_tag_handler.go', '\treturn strings.ToLower(strings.TrimSpace(tag))', '\treturn strings.TrimSpace(tag)',
     'タグを小文字に揃えない（Prod と prod が別のタグになります）'),

    # ── 隔離・ルール・脆弱性の絞り込み ─────────────────────────────────────
    ('server/internal/store/quarantine.go', '\tif f.Status == "quarantined" {\n\t\tconds = append(conds, "restored_at IS NULL")',
        '\tif f.Status == "quarantined" {\n\t\tconds = append(conds, "restored_at IS NOT NULL")',
     '「隔離中」の絞り込みが復元済みを出す（隔離中のファイルが一覧から消えます）'),
    ('server/internal/store/quarantine.go', '\t\tconds = append(conds, fmt.Sprintf("(original_path ILIKE $%d OR hash_sha256 ILIKE $%d)", i, i))',
        '\t\tconds = append(conds, fmt.Sprintf("(original_path ILIKE $%d OR hash_sha256 ILIKE $%d)", i, i+1))',
     '隔離の検索が引数を2つ使う形になる（一覧が丸ごと落ちます）'),
    ('server/internal/store/rules.go', '\tif filter.Enabled != nil {', '\tif filter.Enabled != nil && *filter.Enabled {',
     '無効なルールだけの絞り込みが効かなくなる（nil と false を同じに扱います）'),
    # プレースホルダの番号は `ph()`（args の本数）から出すようになりました。
    # 別に持っていたカウンタは、最後の増分を誰も読まないまま残っていて、
    # golangci-lint の ineffassign が見つけました。
    ('server/internal/store/rules.go', '\t\tconditions = append(conditions, fmt.Sprintf("(name ILIKE %s OR description ILIKE %s)", p, p))',
        '\t\tconditions = append(conditions, fmt.Sprintf("(name ILIKE %s)", p))',
     'ルールの検索が説明文に当たらなくなる'),
    # 同じ番号を2回使う所です。**append の前に取らないと番号が1つずれます。**
    ('server/internal/store/rules.go', '\t\tp := ph() // 2か所で同じ番号を使うので、append の前に取ります。',
        '\t\tp := fmt.Sprintf("$%d", len(args)+2)',
     'ルールの検索が引数の無い番号を指す（一覧が丸ごと落ちます）'),
    ('server/internal/store/vulnerabilities.go', '\t\twhere += fmt.Sprintf(" AND v.severity = $%d", i)',
        '\t\twhere += fmt.Sprintf(" AND v.severity != $%d", i)',
     '脆弱性の深刻度の絞り込みが反転する'),

    # ── プレイブック・キャプチャ・セッション・テンプレート ─────────────────
    ('server/internal/store/playbooks.go', '\tcase c.MinSeverity > 0 && severity < c.MinSeverity:',
        '\tcase c.MinSeverity > 0 && severity <= c.MinSeverity:',
     '重要度の下限がちょうどのアラートで、自動対応が走らなくなる'),
    ('server/internal/store/playbooks.go', '\tcase c.Status != "" && status != c.Status:', '\tcase false:',
     'プレイブックの状態条件が効かなくなる'),
    ('server/internal/store/packet_capture_store.go', '\tcase "completed", "failed", "cancelled":\n\t\treturn nil, &now',
        '\tcase "completed", "failed", "cancelled":\n\t\treturn nil, nil',
     '終了時刻を入れない（終わったキャプチャが「実行中」のままになります）'),
    ('server/internal/store/packet_capture_store.go', '\tcase "running":\n\t\treturn &now, nil', '\tcase "running":\n\t\treturn &now, &now',
     '開始と終了を同時に入れる（実行時間が常に 0 になります）'),
    ('server/internal/store/sessions.go', '\t\treturn "0.0.0.0"', '\t\treturn ""',
     'inet 列に空文字列を渡す（セッションが1件も記録されません）'),
    ('server/internal/store/report_template_store.go', '\tif t.Sections == nil {\n\t\tt.Sections = []ReportTemplateSection{}\n\t}', '',
     'nil の節をそのまま返す（JSON で null になり、画面の .map() が落ちます）'),
    ('server/internal/store/report_template_store.go', '\t\treturn nil, fmt.Errorf("レポートテンプレートの節を読めませんでした: %w", err)',
        '\t\tt.Sections = nil',
     '読めない節を空として通す（白紙のレポートが出ます）'),

    # ── 通知設定の既定 ─────────────────────────────────────────────────────
    ('server/internal/store/notification_prefs.go', '\t\tMinSeverity: "critical",', '\t\tMinSeverity: "low",',
     '設定していない利用者の既定が緩くなる（通知が溢れます）'),
    ('server/internal/store/notification_prefs.go', '\tp := defaultNotificationPrefs(userID)',
        '\tp := &NotificationPrefs{UserID: userID}',
     'GetByUserID が、切り出した既定を通らなくなる'),

    # ── 隔離の状態 ─────────────────────────────────────────────────────────
    ('server/internal/store/quarantine.go', '\t} else if f.Status == "restored" {', '\t} else if f.Status != "" {',
     '知らない状態を「復元済み」として絞り込む（綴り違いが「隔離が無い」に見えます）'),

    # ── 上限そのもの ───────────────────────────────────────────────────────
    (G, 'const reproducedHelperCeiling = 0', 'const reproducedHelperCeiling = 20',
     '写しの上限を上げる'),
    (G, '\tif actual < ceiling {', '\tif false {',
     '減っても言わなくなる（次に増えた分がその差に隠れます）'),
    (G, '\tif actual > ceiling {', '\tif false {',
     '増えても言わなくなる'),
    (G, 'var reproductionMarkers = []string{"テスト専用", "再現する", "テスト内ヘルパー"}',
        'var reproductionMarkers = []string{"テスト専用"}',
     '数え方を狭める（最初これで 13 件に見えていました）'),
]

RUN = ('TestHasRolePure|TestRoleAtLeast|TestValidateCommentBody|'
       'TestCommentLengthCountsRunesNotBytes|TestNoNewLogicIsReproducedInTests|'
       'TestTheReproductionCeilingComplainsBothWays|TestAddCallsTheBodyValidator|'
       'TestHasRoleGoesThroughRoleAtLeast|TestApplyPrefsDefaults|'
       'TestNotificationStatsCountsSentAndFailed|TestOnlySentAndFailedCanBeStored|'
       'TestNotificationPageClamp|TestNotificationOffsetIsNeverNegative|'
       'TestUpsertAppliesTheSharedDefaults|TestBuildIncidentWhere|'
       'TestIncidentActiveExpandsToSeveralStatuses|TestBuildIOCWhere|'
       'TestIOCPlaceholdersStayInStepWithArgs|TestBuildAuditWhere|'
       'TestAuditFiltersThatTheCopyDidNotHave|TestAuditPlaceholdersStayInStepWithArgs|'
       'TestANonZeroExitIsNotCompleted|TestTheCompletionStatusIsOneTheSchemaAllows|'
       'TestCreateFillsArgsWithEmptyObject|TestAgentSearchMatchesHostnameAndIP|'
       'TestAgentEmptyFilterProducesNoWhereClause|TestAgentFilter_|'
       'TestDeviceEventLimitIsClamped|TestDeviceEventPlaceholdersStayInStepWithArgs|'
       'TestFIMRuleFilter_LimitClamped|TestFIMRuleWhereDistinguishesNilFromFalse|'
       'TestEveryMappedEventIsListed|TestEveryListedEventIsProducible|'
       'TestTheConsoleOffersOnlyEventsThatAreSent|TestIsEmittedWebhookEventSaysNo|'
       'TestTheSubjectMatchesWhatIngestionSubscribesTo|'
       'TestDeletingTheDefaultPolicyIsRefused|TestDeletingAMissingPolicyIsNotSuccess|'
       'TestDeduplicateTags|TestNormalizeThenDeduplicate|TestNormalizeTagName|'
       'TestBuildQuarantineWhere|TestBuildRuleWhere|TestBuildVulnWhere|'
       'TestQuarantineSearchUsesOneArgumentTwice|TestQuarantineStatusFilterIsNotInverted|'
       'TestRuleSearchMatchesNameAndDescription|TestRuleEnabledDistinguishesNilFromFalse|'
       'TestVulnFiltersAreNotInverted|TestVulnSearchUsesOneArgumentThreeTimes|'
       'TestPlaybookMatches|TestCaptureTimestamps|TestNormalizeIP|'
       'TestScanReportTemplate|TestNotificationPrefs_DefaultMinSeverity|'
       'TestQuarantineStatusBecomesTheRightCondition|'
       'TestOnlyKnownPushPlatformsCanBeStored|TestGetByUserIDReturnsTheSharedDefaults')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/store/', './internal/api/handlers/', './internal/notification/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))
