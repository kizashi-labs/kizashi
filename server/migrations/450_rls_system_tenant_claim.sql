-- 4 表の RLS に「全テナントを名乗る」項を足す
--
-- agents / alerts / incidents / users の方針は、いまこの形です:
--
--   USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
--          OR current_setting('app.tenant_id', TRUE) IS NULL
--          OR current_setting('app.tenant_id', TRUE) = '')
--
-- 後ろ 2 項が「テナント未設定なら全テナント可」の抜け道です。
-- **「設定し忘れた接続」と「全テナントを見る権利のある接続」が同じ形を
-- しています。** 落ちた側に倒れるのが「全部見える」なので、事故は静かで、
-- 見つかるのは漏れたあとです。実際に一度起きました —— APIキー認証が
-- tenant_id に空文字を置き、鍵 1 本であらゆるテナントの行に届いていました。
--
-- この migration は **抜け道を落としません。** 落とす前に、全テナント権が
-- 要る経路に名乗らせる必要があり、名乗り先の項がまだ無いためです。
-- ここで足すのはその項だけです:
--
--   OR current_setting('app.tenant_id', TRUE) = 'system'
--
-- 足しても見える行は増えません。**いまは未設定の接続が既に全行を見て
-- いるので、名乗った接続が全行を見るのは同じ範囲です。** 変わるのは
-- 「なぜ全行が見えているか」が接続ごとに区別できるようになることです。
--
-- 抜け道を落とすのは次の migration です。そのとき、名乗っていない接続は
-- 0 行になります —— **忘れたら見えない**ので、事故は漏れではなく機能停止
-- として出ます。片方は静かで、もう片方は騒がしい。
--
-- ## なぜロールを分けないか
--
-- docs/security/RLS-fail-closed設計.md は edr_worker ロールを作って
-- ロール別方針で分ける形でした。測った結果、この配備では効きません:
--
--   * 既定の配備は DSN が 1 本（APP_DATABASE_URL は未設定で DATABASE_URL に
--     落ちる）。**API と系が同じロールで繋ぐので、ロール別方針は両者を
--     区別できません。**
--   * CI の Postgres も所有者 edr の 1 本。**ロール案は CI で一度も
--     実行されません。**
--
-- 名乗りは方針の中で完結するので、どのロールで繋いでいても効きます。
-- ロール分割と併用もできます（多層防御としては上乗せになります）。
--
-- ## 'system' が uuid と衝突しないこと
--
-- tenant_id は uuid 列なので、tenant_id::text が 'system' になる行は
-- 作れません。外から来た文字列がこの値を名乗れないことは
-- store.prepareConnForTenant が落とします（tid == SystemTenant を拒否）。
--
-- WITH CHECK は書きません。**書かないと USING がそのまま WITH CHECK に
-- なります**（PostgreSQL の既定）ので、INSERT / UPDATE も同じ条件で
-- 絞られます。書き込みだけ別に足すと、2 つの条件がずれたときに
-- 読めない行が書けます（migration 446 と同じ判断）。

DROP POLICY IF EXISTS agents_tenant_isolation ON agents;
CREATE POLICY agents_tenant_isolation ON agents
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) = 'system'
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

DROP POLICY IF EXISTS alerts_tenant_isolation ON alerts;
CREATE POLICY alerts_tenant_isolation ON alerts
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) = 'system'
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

DROP POLICY IF EXISTS incidents_tenant_isolation ON incidents;
CREATE POLICY incidents_tenant_isolation ON incidents
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) = 'system'
           OR current_setting('app.tenant_id', TRUE) IS NULL
           OR current_setting('app.tenant_id', TRUE) = '');

-- users は 326 が「列があれば」で作っています。無い配備では触りません。
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'users' AND column_name = 'tenant_id') THEN
        DROP POLICY IF EXISTS users_tenant_isolation ON users;
        CREATE POLICY users_tenant_isolation ON users
            USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
                   OR current_setting('app.tenant_id', TRUE) = 'system'
                   OR current_setting('app.tenant_id', TRUE) IS NULL
                   OR current_setting('app.tenant_id', TRUE) = '');
    END IF;
END
$$;
