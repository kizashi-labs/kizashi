-- tenant_id 列の DEFAULT が「名乗り」で落ちないようにする
--
-- ## 何が壊れていたか
--
-- alerts / incidents / users の tenant_id 列は、DEFAULT で app.tenant_id を
-- 読みます（migration 328 / 326）:
--
--   COALESCE(NULLIF(current_setting('app.tenant_id', true), '')::uuid,
--            '00000000-0000-0000-0000-000000000001'::uuid)
--
-- migration 450 で入れた**名乗り**は、この列にとって毒でした ——
-- `app.tenant_id = 'system'` のとき `'system'::uuid` が評価され、
--
--   ERROR: invalid input syntax for type uuid: "system"
--
-- で INSERT ごと落ちます。**検知エンジンと取り込みは名乗る側**なので、
-- アラートが 1 件も書けない状態でした。
--
-- `SaveAlert` は tenant_id を書きません —— 列の DEFAULT が ctx のテナントを
-- 読むことに寄りかかった設計で、それは意図されたものです
-- (`store.encryptionTenant` の注釈: 「同じ出どころなので、行の tenant_id と
-- 鍵のテナントは構造上ずれません」)。名乗りを入れたとき、そこを
-- 見ていませんでした。
--
-- ## なぜ検査をすり抜けたか
--
-- store の検査はほとんどスーパーユーザで繋ぎます。RLS は素通りしますが、
-- **列の DEFAULT は接続主体に関係なく評価されます** —— つまり RLS の話では
-- なく、「名乗った接続から書く」経路を通す検査が 1 本も無かっただけです。
-- fail-closed の演習 (two_tenant_failclosed_test.go) も、**テナントの ctx で
-- 書いて素の ctx で拒まれること**は見ていましたが、名乗りで書いていません
-- でした。
--
-- system_claim_insert_test.go がその穴を塞ぎます。
--
-- ## 直し方
--
-- 名乗りを uuid にしようとせず、**既定テナントへ落とします。**
--
--   COALESCE(NULLIF(NULLIF(current_setting('app.tenant_id', true), ''),
--                   'system')::uuid,
--            '00000000-0000-0000-0000-000000000001'::uuid)
--
-- これは **migration 450 より前の挙動と同じ**です。名乗る前は
-- app.tenant_id が空だったので、DEFAULT は既定テナントを入れていました。
-- 名乗りを足したせいで壊れた分を、元に戻すだけです。
--
-- **行き先が既定テナントでよいのか**は別の問題として残ります。検知エンジンが
-- テナント T の端末のアラートを書くなら、行も T であるべきです。いまは
-- 既定テナントに入ります —— これは 450 の前からそうで、この migration が
-- 作った状態ではありません。直すには生成経路で agent→tenant を解決して
-- 明示的に渡す必要があり、それは別の作業です
-- (docs/security/RLS-fail-closed設計.md の Phase 0)。
--
-- WITH CHECK は通ります。名乗った接続は方針の `= 'system'` の項で通るので、
-- 行の tenant_id が既定テナントでも書けます。

ALTER TABLE alerts ALTER COLUMN tenant_id SET DEFAULT
    COALESCE(
        NULLIF(NULLIF(current_setting('app.tenant_id', TRUE), ''), 'system')::uuid,
        '00000000-0000-0000-0000-000000000001'::uuid);

ALTER TABLE incidents ALTER COLUMN tenant_id SET DEFAULT
    COALESCE(
        NULLIF(NULLIF(current_setting('app.tenant_id', TRUE), ''), 'system')::uuid,
        '00000000-0000-0000-0000-000000000001'::uuid);

-- users は 326 が「列があれば」で作っています。無い配備では触りません。
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'users' AND column_name = 'tenant_id') THEN
        ALTER TABLE users ALTER COLUMN tenant_id SET DEFAULT
            COALESCE(
                NULLIF(NULLIF(current_setting('app.tenant_id', TRUE), ''), 'system')::uuid,
                '00000000-0000-0000-0000-000000000001'::uuid);
    END IF;
END
$$;
