CREATE TABLE IF NOT EXISTS data_classification_labels (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        VARCHAR(100) NOT NULL UNIQUE,
  level       INT NOT NULL,  -- 1=public, 2=internal, 3=confidential, 4=restricted, 5=secret
  color       VARCHAR(20) NOT NULL DEFAULT '#6b7280',
  description TEXT,
  handling_rules TEXT,
  is_active   BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS data_assets (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         VARCHAR(500) NOT NULL,
  type         VARCHAR(100) NOT NULL,  -- file, database, api, service, storage
  location     TEXT,
  label_id     UUID REFERENCES data_classification_labels(id),
  owner        VARCHAR(255),
  description  TEXT,
  pii_detected BOOLEAN NOT NULL DEFAULT false,
  phi_detected BOOLEAN NOT NULL DEFAULT false,
  pci_detected BOOLEAN NOT NULL DEFAULT false,
  last_scanned TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_data_assets_label ON data_assets(label_id);
INSERT INTO data_classification_labels (name, level, color, description) VALUES
  ('Public', 1, '#22c55e', '一般公開可能な情報'),
  ('Internal', 2, '#3b82f6', '社内限定情報'),
  ('Confidential', 3, '#f59e0b', '機密情報'),
  ('Restricted', 4, '#ef4444', '制限付き情報'),
  ('Secret', 5, '#7c3aed', '最高機密情報')
ON CONFLICT (name) DO NOTHING;
