CREATE TABLE IF NOT EXISTS wireless_networks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ssid TEXT NOT NULL,
  bssid TEXT NOT NULL,
  channel INT NOT NULL DEFAULT 0,
  frequency TEXT NOT NULL DEFAULT '2.4GHz',
  security_type TEXT NOT NULL DEFAULT 'WPA2',
  signal_strength INT NOT NULL DEFAULT 0,
  is_authorized BOOL NOT NULL DEFAULT FALSE,
  is_rogue BOOL NOT NULL DEFAULT FALSE,
  vendor TEXT NOT NULL DEFAULT '',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(bssid)
);
CREATE INDEX IF NOT EXISTS idx_wireless_rogue ON wireless_networks(is_rogue);

CREATE TABLE IF NOT EXISTS iot_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address TEXT NOT NULL,
  mac_address TEXT NOT NULL,
  device_name TEXT NOT NULL DEFAULT '',
  device_type TEXT NOT NULL DEFAULT 'unknown',
  manufacturer TEXT NOT NULL DEFAULT '',
  firmware_version TEXT NOT NULL DEFAULT '',
  open_ports JSONB NOT NULL DEFAULT '[]',
  vulnerabilities JSONB NOT NULL DEFAULT '[]',
  risk_score INT NOT NULL DEFAULT 0,
  is_managed BOOL NOT NULL DEFAULT FALSE,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(mac_address)
);
CREATE INDEX IF NOT EXISTS idx_iot_risk ON iot_devices(risk_score DESC);
