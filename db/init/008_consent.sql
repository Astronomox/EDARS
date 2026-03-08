-- db/init/008_consent.sql
-- ════════════════════════════════════════════════════════════════
-- Migration: Legal Consent Recording
-- Run order: After 007_tenant_rls.sql
-- Idempotent: Yes
--
-- LEGAL PURPOSE:
--   These columns are the legal proof that each user explicitly
--   accepted the Terms of Service and Privacy Policy at the exact
--   moment they created their account.
--
--   Without this, you cannot prove consent under:
--     - GDPR Article 7 (EU)
--     - UK GDPR
--     - Nigeria Data Protection Act 2023 (NDPA) Section 2.2
--
--   The version strings let you know exactly WHICH version of
--   the ToS/Privacy Policy each user accepted. If you update
--   your policies, you can identify users who need to re-consent.
-- ════════════════════════════════════════════════════════════════

-- ── Consent columns on users ──────────────────────────────────

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tos_accepted_at
    TIMESTAMPTZ DEFAULT NULL;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tos_version
    TEXT DEFAULT NULL;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS privacy_policy_accepted_at
    TIMESTAMPTZ DEFAULT NULL;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS privacy_policy_version
    TEXT DEFAULT NULL;

-- ── Index: find users who need to re-consent after policy update

CREATE INDEX IF NOT EXISTS idx_users_tos_version
  ON users(tenant_id, tos_version)
  WHERE tos_version IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_privacy_version
  ON users(tenant_id, privacy_policy_version)
  WHERE privacy_policy_version IS NOT NULL;

-- ── Comment on columns for documentation ─────────────────────

COMMENT ON COLUMN users.tos_accepted_at IS
  'Timestamp when user explicitly accepted the Terms of Service. '
  'NULL means pre-consent era or account created before this migration. '
  'Required for GDPR Article 7 compliance.';

COMMENT ON COLUMN users.tos_version IS
  'Version string of ToS accepted (format: YYYY-MM). '
  'Matches CURRENT_TOS_VERSION env var at time of registration.';

COMMENT ON COLUMN users.privacy_policy_accepted_at IS
  'Timestamp when user explicitly accepted the Privacy Policy. '
  'Required for GDPR and NDPA compliance.';

COMMENT ON COLUMN users.privacy_policy_version IS
  'Version string of Privacy Policy accepted (format: YYYY-MM).';
