-- 227_fix_access_review_columns.sql
-- Migration 160 created access_review_campaigns with reviewer_id UUID,
-- but handlers (written for migration 210) expect reviewer TEXT and user_name TEXT.
-- Add the missing columns and backfill from existing FK references.

-- Add reviewer TEXT to campaigns
ALTER TABLE access_review_campaigns
    ADD COLUMN IF NOT EXISTS reviewer TEXT NOT NULL DEFAULT '';

-- Backfill reviewer from linked user email
UPDATE access_review_campaigns ar
    SET reviewer = COALESCE((SELECT email FROM users WHERE id = ar.reviewer_id), '')
    WHERE reviewer = '' AND reviewer_id IS NOT NULL;

-- Add user_name TEXT to items (migration 160 used subject_user_id UUID)
ALTER TABLE access_review_items
    ADD COLUMN IF NOT EXISTS user_name TEXT NOT NULL DEFAULT '';

-- Backfill user_name from subject_user_id
UPDATE access_review_items ari
    SET user_name = COALESCE((SELECT email FROM users WHERE id = ari.subject_user_id), '')
    WHERE user_name = '' AND subject_user_id IS NOT NULL;
