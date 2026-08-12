-- 289: レトロアクティブ IOC ハンティングの watermark 用状態テーブル。
--
-- ライブの IOCMatcher は「新しいイベント × 全IOC」を毎分照合するが、フィードで
-- 新規追加された IOC(例: ThreatFox 4,169件)は過去のイベントには照合されない。
-- RetroIOCHunter は逆に「過去のイベント履歴 × 新規IOC」を定期照合し、既に
-- 起きていた侵害を発見する。両者で全マトリクスを重複なく被覆する。
--
-- last_hunted_at は「ここまでの first_seen を持つ IOC は履歴照合済み」を表す
-- watermark。各実行で first_seen > last_hunted_at の IOC だけを過去に照合し、
-- 実行後に now() へ前進させることで、各 IOC を履歴に対し一度だけ照合する。
CREATE TABLE IF NOT EXISTS ioc_hunt_state (
    id             INTEGER PRIMARY KEY DEFAULT 1,
    last_hunted_at TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ioc_hunt_state_singleton CHECK (id = 1)
);

-- 初期 watermark = now() - 24h。初回実行では直近24時間に追加された IOC
-- (直近のフィード同期分)を履歴に照合する。全 IOC を一括照合してアラートを
-- 溢れさせないための保守的な初期値。
INSERT INTO ioc_hunt_state (id, last_hunted_at)
VALUES (1, NOW() - INTERVAL '24 hours')
ON CONFLICT (id) DO NOTHING;
