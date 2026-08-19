-- uninstall_guards / uninstall_attempts の RLS から「テナント未設定なら全テナント可」を外す
--
-- 379 が作った方針は、agents / alerts と同じ形をしていました:
--
--   USING (tenant_id::text = current_setting('app.tenant_id', TRUE)
--          OR current_setting('app.tenant_id', TRUE) IS NULL
--          OR current_setting('app.tenant_id', TRUE) = '')
--
-- 後ろ2項は「テナントを持たない系（取り込み・検知・スケジューラ）が全行を
-- 見るため」の抜け道です。**設定し忘れた接続と、全テナントを見る権利を
-- 持つ接続が、同じ形になります。** 落ちた側に倒れるのが「全部見える」
-- なので、事故は静かで、見つかるのは漏れたあとです。
--
-- この2表は他の4表と事情が違います。**テナントを決められない経路が
-- 1つもありません。**
--
--   管理コンソール (GetStatus / SetPassword / ClearPassword / ListAttempts)
--       JWT のテナント。単一テナント配備では JWT が持たないので、
--       tenantScope が既定テナントに落として **ctx にも載せます**。
--       載せるまでは tenantMiddleware が素通りしていて、`app.tenant_id` は
--       空のままでした。
--
--   ハートビート (GuardMaterialForHeartbeat, HTTP / gRPC とも)
--       端末は名乗りませんが、agents 行がテナントを持っています。
--       gRPC 側は前から引いていて、ctx に載せていなかっただけです。
--       引けないときは配りません（素性の分からない相手に既定テナントの
--       保護材料を渡さない）。
--
--   アンインストール試行の通報 (ReportAttempt, 認証なし)
--       同じく agents 行から。削除済み・未登録の端末からの通報は既定
--       テナントへ落とします —— **記録を落とすのがいちばん悪い答え**で、
--       この経路は「攻撃者が解体している最中の端末からの通報」のために
--       あります。
--
-- 落とすのはこの2表だけです。agents / alerts / incidents / users の抜け道は
-- 取り込み・検知エンジン・相関エンジンが依存していて、外すには系と HTTP を
-- 別の DB ロールに分ける必要があります（docs/判断待ちの一覧.md）。
-- ここで agents の方針に触らないのは意図的で、**上の「端末の行から
-- テナントを引く」がテナント未設定の接続で通ることに寄りかかっています。**

-- 379 と同じく FOR ALL（既定）で、WITH CHECK は書きません。**書かないと
-- USING がそのまま WITH CHECK になります**（PostgreSQL の既定）ので、
-- INSERT / UPDATE も同じ条件で絞られます。書き込みだけ別に足すと、
-- 2つの条件がずれたときに読めない行が書けます。
DROP POLICY IF EXISTS uninstall_guards_tenant_isolation ON uninstall_guards;
CREATE POLICY uninstall_guards_tenant_isolation ON uninstall_guards
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE));

DROP POLICY IF EXISTS uninstall_attempts_tenant_isolation ON uninstall_attempts;
CREATE POLICY uninstall_attempts_tenant_isolation ON uninstall_attempts
    USING (tenant_id::text = current_setting('app.tenant_id', TRUE));
