-- incidents の RLS から「テナント未設定なら全テナント可」を外す
--
-- 4 表のうち **3 表目**です（agents / 451、alerts / 453）。
-- 残るのは users だけです。
--
-- ## この表を 3 番目にした理由
--
-- incidents を書くのは相関エンジンと IncidentEscalator で、どちらも
-- `store.WithSystemAccess` で名乗る側です。**読みも書きも、agents と
-- alerts で通った経路と同じ形**なので、ここは新しい危険を持ち込みません。
--
-- users を最後に残すのは、**認証がテナントを決める前に利用者を引く**から
-- です（鶏と卵）。そこだけ形が違うので、揃ったあとに単独で見ます。
--
-- ## 確かめたこと
--
-- 木全体を `-count=1` で走らせて、落ちたのは台帳 1 件だけでした
-- （「incidents は抜け道を持たなくなりました」）。本番の経路は
-- 落ちていません。
--
-- 名乗った接続が incidents に**書ける**ことは
-- `system_claim_insert_test.go` が持ちます。alerts のとき、名乗りが
-- `tenant_id` 列の DEFAULT を壊していたことがここで分かりました
-- （`'system'::uuid` が不正。migration 452 で修正）。**読みだけ確かめて
-- 落とすと、系が書けなくなったことに気づけません。**
--
-- ## 戻し方
--
--   DROP POLICY IF EXISTS incidents_tenant_isolation ON incidents;
--   CREATE POLICY incidents_tenant_isolation ON incidents
--       USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
--              OR current_setting('app.tenant_id', TRUE) = 'system'
--              OR current_setting('app.tenant_id', TRUE) IS NULL
--              OR current_setting('app.tenant_id', TRUE) = '');
--
-- **戻したら permissiveWhenUnset に incidents を書き戻し、
-- two_tenant_failclosed_test.go の alreadyFailClosed からも外してください。**
--
-- WITH CHECK は書きません（USING がそのまま WITH CHECK になります）。

DROP POLICY IF EXISTS incidents_tenant_isolation ON incidents;
CREATE POLICY incidents_tenant_isolation ON incidents
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
           OR current_setting('app.tenant_id', TRUE) = 'system');
