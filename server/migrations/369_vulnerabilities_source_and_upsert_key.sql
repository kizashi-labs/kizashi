-- 369: vulnerabilities に source 列と (agent_id, cve_id, affected_package) の一意制約を足す。
--
-- internal/sync/wazuh.go の取り込みは
--
--   INSERT INTO vulnerabilities (..., source) VALUES (..., 'wazuh')
--   ON CONFLICT (agent_id, cve_id, affected_package) DO UPDATE ...
--
-- と書いているが、016 が作ったテーブルには **source 列も、その一意制約も無い**。
-- Postgres は存在しない列でも、対応するユニーク制約の無い ON CONFLICT でも文全体を
-- 拒否するので、この取り込みは一件も書けていない。エラーは呼び出し側で握られており、
-- 「Wazuh から脆弱性が来ていない」と「書き込みが落ちている」が区別できなかった。
--
-- どちらも「コードが期待するスキーマ」と「移行が作ったスキーマ」のズレで、2026-08-03 に
-- 同型のものが6件見つかっている (#615 agents.os / #624 alerts / ueba_anomalies /
-- ueba_baselines / audit_logs.action / agents.ip_address)。本移行はそのうち
-- vulnerabilities 分を、**列を消すのではなく足す**方向で解消する。source は
-- 「どのスキャナ由来か」という捨てたくない情報なので、コード側を削るのは誤り。

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'internal';

-- UPSERT キー。既存行に重複があるとインデックス作成が失敗するので、先に畳んでおく。
-- 実際にはこのテーブルへの書き込み経路が両方壊れていたため空のはずだが、
-- 「空だと思っていたら入っていた」で移行が落ちる方が高くつく。
DELETE FROM vulnerabilities a
 USING vulnerabilities b
 WHERE a.ctid < b.ctid
   AND a.agent_id = b.agent_id
   AND a.cve_id IS NOT DISTINCT FROM b.cve_id
   AND a.affected_package = b.affected_package;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_vulnerabilities_agent_cve_package
    ON vulnerabilities (agent_id, cve_id, affected_package);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities (source);
