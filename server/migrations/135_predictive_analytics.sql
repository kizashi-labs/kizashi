CREATE TABLE IF NOT EXISTS security_predictions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  prediction_type VARCHAR(100) NOT NULL,  -- alert_volume, incident_risk, vuln_exposure, breach_probability
  target_entity  VARCHAR(255),  -- hostname, user, or 'global'
  predicted_value NUMERIC(12,4) NOT NULL,
  confidence     NUMERIC(4,2) NOT NULL,
  prediction_for DATE NOT NULL,
  features_used  JSONB NOT NULL DEFAULT '{}',
  model_version  VARCHAR(50) NOT NULL DEFAULT 'v1.0',
  was_accurate   BOOLEAN,
  actual_value   NUMERIC(12,4),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_predictions_type ON security_predictions(prediction_type, prediction_for DESC);
CREATE TABLE IF NOT EXISTS prediction_models (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           VARCHAR(255) NOT NULL,
  model_type     VARCHAR(100) NOT NULL,
  target_metric  VARCHAR(100) NOT NULL,
  accuracy       NUMERIC(5,2),
  last_trained   TIMESTAMPTZ,
  feature_importance JSONB NOT NULL DEFAULT '{}',
  is_active      BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
