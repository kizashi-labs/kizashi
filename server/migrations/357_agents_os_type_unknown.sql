-- 357: agents.os_type の CHECK に 'unknown' を追加(Wazuh 取込経路の 23514 根治)。
--
-- 背景: migration 001 で os_type は CHECK (os_type IN ('windows','linux','darwin'))
-- と定義され、以降どのマイグレーションも緩和していない。一方で Wazuh webhook 経路
-- (internal/api/handlers/ingest_handler.go の upsertAgent)は未知ホストのエージェント行を
--     INSERT INTO agents (..., os_type, ...) VALUES (..., 'unknown', ...)
-- で自動作成していたため、**毎回必ず** 23514 check_violation で失敗していた。
-- upsertAgent の失敗は WazuhAlert が 500 を返して打ち切るため、未登録ホスト由来の
-- Wazuh アラートは 1 件も保存されず黙って捨てられていた(実 DB で再現確認済み)。
--
-- なぜ 'unknown' を正規値に昇格させるか(単に windows/linux へ寄せないか):
--   * Wazuh の webhook ペイロードには OS フィールドが存在しない(agent は id/name/ip のみ)。
--     rule.groups や location からの推定は best-effort であり、必ず外れる入力がある。
--   * Wazuh は AIX / Solaris / HP-UX も管理対象にできる。これらに windows/linux/darwin の
--     いずれかを当てるのは誤ったラベル付けで、後段の os_type 突合(autoupdate の
--     platform = a.os_type、agent_config_profiles の os_type 一致)を静かに誤爆させる。
--   * 読み出し側は既に 'unknown' を想定値として扱っている
--     (store/agents.go ProtectionModeByOS の COALESCE(...,'unknown')、
--      compliance/evaluator.go loadAgentData の COALESCE(os_type,'unknown'))。
--     つまり「不明」は既にドメイン上の正当な状態で、CHECK だけが追随していなかった。
-- 未知を 'unknown' として素直に永続化し、後で本物の OS が判明した時点で昇格させる
-- (ingest_handler 側で os_type='unknown' の行のみ上書きする)方が、誤ラベルより安全。
--
-- 冪等: 制約を落として貼り直すだけなので再実行安全。既存行は windows/linux/darwin の
-- いずれかであり新 CHECK を必ず満たすため、NOT VALID は不要。

ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_os_type_check;

ALTER TABLE agents ADD CONSTRAINT agents_os_type_check
    CHECK (os_type IN ('windows', 'linux', 'darwin', 'unknown'));
