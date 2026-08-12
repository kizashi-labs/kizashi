CREATE TABLE IF NOT EXISTS compliance_evidence_tasks (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  framework      VARCHAR(100) NOT NULL,  -- SOC2, ISO27001, PCI-DSS, HIPAA, NIST
  control_id     VARCHAR(100) NOT NULL,
  description    TEXT,
  collection_method VARCHAR(100) NOT NULL,  -- auto, manual, api, screenshot
  schedule       VARCHAR(100),  -- cron expression for auto
  is_active      BOOLEAN NOT NULL DEFAULT true,
  last_collected TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS compliance_evidence_items (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id        UUID NOT NULL REFERENCES compliance_evidence_tasks(id) ON DELETE CASCADE,
  framework      VARCHAR(100) NOT NULL,
  control_id     VARCHAR(100) NOT NULL,
  name           VARCHAR(500) NOT NULL,
  evidence_type  VARCHAR(100) NOT NULL,  -- screenshot, log_export, config_snapshot, report, attestation
  content        TEXT,
  file_path      VARCHAR(1000),
  collected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  collected_by   VARCHAR(255),
  status         VARCHAR(50) NOT NULL DEFAULT 'pending_review',  -- pending_review, approved, rejected
  reviewer_id    UUID,
  reviewed_at    TIMESTAMPTZ,
  expires_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_evidence_items_task ON compliance_evidence_items(task_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_items_framework ON compliance_evidence_items(framework, control_id);
