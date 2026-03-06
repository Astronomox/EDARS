-- ═══════════════════════════════════════════════════════════════
-- EDARS Migration 009 — Legal Consent Recording
-- ═══════════════════════════════════════════════════════════════
-- Adds consent tracking columns to the users table.
-- These columns are your legal proof that the user accepted
-- the Terms of Service and Privacy Policy at registration time.
--
-- GDPR Art.7: "The controller shall be able to demonstrate
-- that the data subject has consented to processing."
--
-- NDPA (Nigeria) Sec.25: Processors must demonstrate consent.
--
-- DEPENDS ON: 006_add_tenancy.sql (users table must exist)
-- IDEMPOTENT: Uses ADD COLUMN IF NOT EXISTS.
-- ═══════════════════════════════════════════════════════════════

-- ─── 1. ToS consent timestamp and version ───────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tos_accepted_at
        TIMESTAMPTZ DEFAULT NULL;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tos_version
        TEXT DEFAULT NULL;

-- ─── 2. Privacy Policy consent timestamp and version ────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS privacy_policy_accepted_at
        TIMESTAMPTZ DEFAULT NULL;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS privacy_policy_version
        TEXT DEFAULT NULL;

-- ─── 3. Backfill existing users ─────────────────────────────
-- Existing dev-seed users are assumed to have accepted the
-- initial version at their creation time.
UPDATE users
SET
    tos_accepted_at            = created_at,
    tos_version                = '2026-03',
    privacy_policy_accepted_at = created_at,
    privacy_policy_version     = '2026-03'
WHERE tos_accepted_at IS NULL;

-- ─── 4. Index for compliance queries ────────────────────────
-- "Show me all users who accepted version X of the ToS"
CREATE INDEX IF NOT EXISTS idx_users_tos_version
    ON users (tos_version);

CREATE INDEX IF NOT EXISTS idx_users_privacy_version
    ON users (privacy_policy_version);

-- NOTE: These columns must NEVER be set to NULL once populated.
-- They are a legal record. The only way to "withdraw consent"
-- is the right-to-erasure flow (tenant deletion), which
-- anonymises the entire user record.
