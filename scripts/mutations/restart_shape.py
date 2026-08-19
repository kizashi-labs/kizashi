#!/usr/bin/env python3
"""記憶を先に変えて、DBへの反映を捨てる形（`restart`）。

対象:
  server/internal/store/postgres.go
  server/internal/store/users.go
  server/internal/store/alerts.go
  server/internal/reports/scheduler.go
  server/internal/threatintel/feed.go
  server/internal/agentconfig/profile.go
  server/internal/api/handlers/auth_handler.go
  server/internal/api/handlers/discarded_write_test.go

捨てている書き込み 37 のうち、**呼び出し側が error を受け取れる 11 か所**
を直しました。直し方は3通りで、どれを使うかは形で決まります:

    DB を先に、記憶を後に   reports/scheduler ×3、threatintel/feed ×2
                            （記憶から先に消すと、消えたように見えて
                            **次の再起動で戻ります**）
    同じ transaction に      agentconfig/profile ×2（既定の一意性）、
                            store/alerts（MTTR の履歴）
                            —— 片方だけ効いた状態を残さないため
    失敗を答えにする         store/postgres ×2（絞り込めない接続を配らない）、
                            store/users（消費できない復旧コードを通さない）

**DB が要る変異は、`TEST_DATABASE_URL` があるときだけ走ります。**
無いときは、その一群を飛ばしたことを表示して 0 で終わります —— 検査自体は
Skip するので、走らせても「壊せなかった」ではなく「試していない」です。

置いていない変異:

  `agentconfig` と `alerts` の transaction を潰す変異は、**DB 無しでは
  殺せません**（`Begin` を `pool` に戻すだけでは、通る木で同じに動きます）。
  件数を留める `discardedWritesTotal` が、`_, _ =` に戻す方向は捕まえます。

  `TestTheBackupCodeCallDoesNotDiscardItsError` の「`verified, _ =` が
  無いこと」を潰す変異は置いていません。**通る木にその文字列は無いので、
  在っても無くても同じです** —— 同じ検査の「`ok, err :=` が在ること」の
  方が、元に戻す変異を捕まえます（そちらは殺せています）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

PG = 'server/internal/store/postgres.go'
US = 'server/internal/store/users.go'
AL = 'server/internal/store/alerts.go'
RS = 'server/internal/reports/scheduler.go'
TF = 'server/internal/threatintel/feed.go'
AC = 'server/internal/agentconfig/profile.go'
AH = 'server/internal/api/handlers/auth_handler.go'
W = 'server/internal/api/handlers/discarded_write_test.go'
SE = 'server/internal/api/handlers/discarded_store_error_test.go'

# ── DB が要るもの ────────────────────────────────────────────────────────────
DB_CASES = [
    (PG, '\t\tif _, err := c.Exec(ctx, "SELECT set_config(\'app.tenant_id\', $1, false)", tid); err != nil {\n'
         '\t\t\treturn false, fmt.Errorf("テナントを設定できない接続は使えません: %w", err)\n\t\t}',
         '\t\t_, _ = c.Exec(ctx, "SELECT set_config(\'app.tenant_id\', $1, false)", tid)\n'
         '\t\t_ = fmt.Sprint',
     '設定できない接続を「使える」と答える（**元の実装。空の app.tenant_id は '
     'RLS のエスケープ節で全テナントを通します**）'),
    (PG, '\tif _, err := c.Exec(context.Background(), "SELECT set_config(\'app.tenant_id\', \'\', false)"); err != nil {\n'
         '\t\tslog.Warn("テナントを消せない接続をプールから捨てます", "error", err)\n'
         '\t\treturn false\n\t}\n\treturn true',
         '\t_, _ = c.Exec(context.Background(), "SELECT set_config(\'app.tenant_id\', \'\', false)")\n'
         '\t_ = slog.Warn\n\treturn true',
     '消せなかった接続をプールに戻す（**元の実装。次にテナントを持たない'
     '呼び出しが前のテナントで絞られます**）'),
    (US, '\t\ttag, uerr := s.pool.Exec(ctx,\n'
         '\t\t\t"UPDATE mfa_backup_codes SET used = TRUE, used_at = NOW() WHERE id = $1 AND used = FALSE", c.id)\n'
         '\t\tif uerr != nil {\n'
         '\t\t\treturn false, fmt.Errorf("復旧コードを使用済みにできませんでした: %w", uerr)\n\t\t}\n'
         '\t\tif tag.RowsAffected() == 0 {\n'
         '\t\t\t// 先に誰か（別の要求）が同じコードを使いました。\n'
         '\t\t\treturn false, nil\n\t\t}\n\t\treturn true, nil',
         '\t\t_, _ = s.pool.Exec(ctx,\n'
         '\t\t\t"UPDATE mfa_backup_codes SET used = TRUE, used_at = NOW() WHERE id = $1", c.id)\n'
         '\t\treturn true, nil',
     '使用済みの印を捨てる（**元の実装。書けなくても true を返すので、'
     '同じ復旧コードが何度でも使えます**）'),
    (US, '"UPDATE mfa_backup_codes SET used = TRUE, used_at = NOW() WHERE id = $1 AND used = FALSE", c.id)',
         '"UPDATE mfa_backup_codes SET used = TRUE, used_at = NOW() WHERE id = $1", c.id)',
     '`used = FALSE` の条件を外す（**同時に出した同じコードが複数回'
     '通ります**）'),
    # **`rows` を開いたまま2本目の接続を取る形に戻します。**
    # pgx は `Next()` が false を返した時点で接続を返すので、走査を
    # 読み切ってから UPDATE すれば1本しか握りません。ループの中に戻すと、
    # あいだに bcrypt を挟んだまま2本目を要求します。
    (US, '\tfor _, c := range candidates {\n'
         '\t\tif bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(code)) != nil {\n'
         '\t\t\tcontinue\n\t\t}',
         '\tfor _, c := range candidates {\n'
         '\t\t_ = c\n\t}\n'
         '\tfor rows.Next() {\n'
         '\t\tvar c candidate\n'
         '\t\tif rows.Scan(&c.id, &c.hash) != nil {\n\t\t\tcontinue\n\t\t}\n'
         '\t\tif bcrypt.CompareHashAndPassword([]byte(c.hash), []byte(code)) != nil {\n'
         '\t\t\tcontinue\n\t\t}',
     '`rows` を開いたまま UPDATE する（**プールの本数を超えた同時要求が'
     '互いの接続を待って進まなくなります**）'),
]

# ── DB が無くても走るもの（件数で捕まえます） ────────────────────────────────
COUNT_CASES = [
    (RS, '\t\tif _, err := s.pool.Exec(ctx, `DELETE FROM scheduled_reports WHERE id = $1`, id); err != nil {\n'
         '\t\t\treturn fmt.Errorf("スケジュールを削除できませんでした（再起動で戻ります）: %w", err)\n\t\t}',
         '\t\t_, _ = s.pool.Exec(ctx, `DELETE FROM scheduled_reports WHERE id = $1`, id)',
     '定期レポートの削除が黙って捨てられる（**元の実装。消したはずの'
     'レポートが再起動でまた配信されます**）'),
    (RS, '\t\tif _, err := s.pool.Exec(ctx,\n'
         '\t\t\t`UPDATE scheduled_reports SET enabled=$2, updated_at=NOW() WHERE id=$1`,\n'
         '\t\t\tid, enabled); err != nil {\n'
         '\t\t\treturn fmt.Errorf("スケジュールの有効・無効を切り替えられませんでした（再起動で戻ります）: %w", err)\n\t\t}',
         '\t\t_, _ = s.pool.Exec(ctx,\n'
         '\t\t\t`UPDATE scheduled_reports SET enabled=$2, updated_at=NOW() WHERE id=$1`,\n'
         '\t\t\tid, enabled)',
     '有効・無効の切り替えが黙って捨てられる（**止めたはずのレポートが'
     '再起動でまた有効になります**）'),
    (TF, '\t\tif _, err := m.pool.Exec(ctx, `DELETE FROM threat_intel_feeds WHERE id=$1`, id); err != nil {\n'
         '\t\t\treturn fmt.Errorf("フィードを削除できませんでした（再起動で戻ります）: %w", err)\n\t\t}',
         '\t\t_, _ = m.pool.Exec(ctx, `DELETE FROM threat_intel_feeds WHERE id=$1`, id)',
     'フィードの削除が黙って捨てられる（**消したはずのフィードが'
     '再起動で戻ります**）'),
    (AC, '\t\tif _, err = tx.Exec(ctx, `\n'
         '\t\t\tUPDATE agent_config_profiles\n'
         '\t\t\tSET is_default = false\n'
         '\t\t\tWHERE os_type = $1 AND id != $2\n'
         '\t\t`, profile.OSType, profile.ID); err != nil {\n'
         '\t\t\treturn nil, fmt.Errorf("unsetting other defaults: %w", err)\n\t\t}',
         '\t\t_, _ = tx.Exec(ctx, `\n'
         '\t\t\tUPDATE agent_config_profiles\n'
         '\t\t\tSET is_default = false\n'
         '\t\t\tWHERE os_type = $1 AND id != $2\n'
         '\t\t`, profile.OSType, profile.ID)',
     '既定の一意性を保つ UPDATE が黙って捨てられる（**同じ OS に既定が'
     '2つ残ります**）'),
    (AL, '\t\tif _, err := tx.Exec(ctx, `\n'
         '\t\t\tINSERT INTO alert_status_changes (alert_id, from_status, to_status, changed_by)\n'
         '\t\t\tVALUES ($1::uuid, $2, $3, $4)`,\n'
         '\t\t\tid, prevStatus, *status, changedBy,\n'
         '\t\t); err != nil {\n'
         '\t\t\treturn fmt.Errorf("状態変更の履歴を残せませんでした（MTTR が実際より短く出ます）: %w", err)\n\t\t}',
         '\t\t_, _ = tx.Exec(ctx, `\n'
         '\t\t\tINSERT INTO alert_status_changes (alert_id, from_status, to_status, changed_by)\n'
         '\t\t\tVALUES ($1::uuid, $2, $3, $4)`,\n'
         '\t\t\tid, prevStatus, *status, changedBy,\n'
         '\t\t)',
     'MTTR の履歴が黙って捨てられる（**対応時間が実際より短く出ます**）'),
    (AH, '\t\tok, err := h.Users.UseBackupCode(c.Request.Context(), userID, req.Code)\n'
         '\t\tif err != nil {\n'
         '\t\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})\n'
         '\t\t\treturn\n\t\t}\n\t\tverified = ok',
         '\t\tverified, _ = h.Users.UseBackupCode(c.Request.Context(), userID, req.Code)',
     '呼び出し側が error を捨てる（**store が直っても、ここで元に戻ります**）'),
    (W, 'const discardedWritesTotal = 1', 'const discardedWritesTotal = 37',
     '直した 11 か所を、まだ捨てていることにする'),

    # ── 呼び出し側 ───────────────────────────────────────────────────────
    # 走査そのものへの変異は `store_error_to_the_screen.py` に移しました
    # （19 か所を全部直して 0 になったので、そちらが本体です）。

]

CASES = DB_CASES + COUNT_CASES

DB_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestAConnectionThatCannotBeTenantScopedIsNotHandedOut|'
         'TestClearingTheTenantFailureDestroysTheConnection|'
         'TestABackupCodeWorksExactlyOnce|'
         'TestABackupCodeIsNotAcceptedWhenItCannotBeConsumed|'
         'TestOnlyOneConcurrentUseOfABackupCodeSucceeds',
         './internal/store/'],
    cwd='server',
)

COUNT_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified|'
         'TestFailuresAreNotAnsweredWithAValue|TestHandlersDoNotDiscardStoreErrors|'
         'TestTheBackupCodeCallDoesNotDiscardItsError|'
         'TestTheStoreErrorRecogniserLooksAtTheShape',
         './internal/api/handlers/', './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    rc = 0
    if os.environ.get('TEST_DATABASE_URL'):
        rc |= DB_HARNESS.run(DB_CASES)
    else:
        print('TEST_DATABASE_URL がありません。DB が要る %d 件は走らせていません '
              '——「壊せなかった」ではなく「試していない」です。' % len(DB_CASES))
        print('実測 (2026-08-12): PostgreSQL 16.13 を立てて 5/5 killed。')
    rc |= COUNT_HARNESS.run(COUNT_CASES)
    sys.exit(rc)
