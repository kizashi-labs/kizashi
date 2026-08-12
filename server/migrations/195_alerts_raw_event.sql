-- Add raw_event column to alerts table for storing encrypted or plain event data.
-- Stored as TEXT so it can hold either a raw JSON string or an AES-256-GCM
-- encrypted blob prefixed with "enc:" (base64-encoded ciphertext).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS raw_event TEXT;
