-- 脅威アクター/敵対者インテリの永続化テーブル。
-- STIX 2.1 インポートで受け取る named SDO(threat-actor / intrusion-set /
-- malware / tool / campaign)をここに保存する。従来これらは import 時にログ
-- 出力されるだけで捨てられており、/threat-intel/actors エンドポイントは空配列を
-- 返すスタブだった。このテーブルで STIX インポート → 脅威アクターDB → UI
-- (脅威アクター画面)を接続する。
CREATE TABLE IF NOT EXISTS threat_actors (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id       TEXT UNIQUE,                 -- STIX id(threat-actor--… / malware--… 等)。手動作成時は NULL
    name          TEXT NOT NULL,
    actor_type    TEXT NOT NULL DEFAULT 'threat-actor',  -- threat-actor|intrusion-set|malware|tool|campaign
    description   TEXT,
    aliases       TEXT[] NOT NULL DEFAULT '{}',
    malware_types TEXT[] NOT NULL DEFAULT '{}', -- malware SDO の malware_types
    mitre_ids     TEXT[] NOT NULL DEFAULT '{}', -- external_references / relationship 由来の ATT&CK ID
    labels        TEXT[] NOT NULL DEFAULT '{}',
    source        TEXT NOT NULL DEFAULT 'stix-import',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- name は手動作成/STIX混在で重複しうるため UNIQUE にはせず、STIX 由来の冪等
-- upsert は stix_id をキーにする。名前検索・型フィルタ用のインデックス。
CREATE INDEX IF NOT EXISTS idx_threat_actors_name ON threat_actors(lower(name));
CREATE INDEX IF NOT EXISTS idx_threat_actors_type ON threat_actors(actor_type);
