# EDARS — Data Dictionary & PII Retention Policy

> **Classification**: INTERNAL — CONFIDENTIAL
> **Last Updated**: 2026-03-06
> **Owner**: Engineering / Data Protection Officer

---

## Purpose

This document catalogues every field in the EDARS database that could constitute
Personally Identifiable Information (PII) as defined under GDPR (EU 2016/679),
CCPA (California), NDPR (Nigeria), and equivalent data protection laws. It also
documents retention policies and legal bases for processing.

---

## PII Fields Inventory

| Table | Column | Data Type | PII Classification | Legal Basis | Retention Policy | Notes |
|-------|--------|-----------|--------------------|-|-|-|
| `users` | `email` | `VARCHAR(255)` | **Direct PII** | Legitimate interest (account access) | Account lifetime + 30 days post-deletion | Unique per tenant; used for authentication |
| `users` | `full_name` | `VARCHAR(255)` | **Direct PII** | Legitimate interest (display name) | Account lifetime + 30 days post-deletion | Shown in UI and reports |
| `users` | `password_hash` | `VARCHAR(255)` | **Derived PII** | Contractual necessity | Account lifetime | bcrypt cost 12; raw password NEVER stored |
| `users` | `last_login_at` | `TIMESTAMPTZ` | **Behavioural** | Legitimate interest (security monitoring) | Account lifetime | May reveal usage patterns |
| `audit_log` | `ip_address` | `INET` | **Direct PII** (in some jurisdictions) | Legitimate interest (security & compliance) | 2 years | Classified as PII under GDPR (Recital 30); required for security incident investigation |
| `audit_log` | `user_agent` | `TEXT` | **Indirect PII** | Legitimate interest (security forensics) | 2 years | Can contribute to device fingerprinting |
| `audit_log` | `metadata` | `JSONB` | **May contain PII** | Varies by action type | 2 years | Reviewed quarterly for PII leakage; MUST NOT contain passwords or tokens |
| `user_sessions` | `ip_address` | `INET` | **Direct PII** | Legitimate interest (session security) | 30 days after session expiry | |
| `user_sessions` | `user_agent` | `TEXT` | **Indirect PII** | Legitimate interest | 30 days after session expiry | |
| `user_sessions` | `device_fingerprint` | `VARCHAR(64)` | **Indirect PII** | Legitimate interest | 30 days after session expiry | SHA-256 hash of device characteristics |
| `user_sessions` | `geo_country` | `VARCHAR(3)` | **Indirect PII** | Legitimate interest | 30 days after session expiry | ISO 3166-1 alpha-3 |
| `user_sessions` | `geo_city` | `VARCHAR(128)` | **Indirect PII** | Legitimate interest | 30 days after session expiry | Derived from IP; not stored if geo-lookup disabled |
| `failed_logins` | `ip_address` | `INET` | **Direct PII** | Legitimate interest (brute-force protection) | 90 days | Auto-purged; triggers IP blocking |
| `failed_logins` | `email_attempted` | `VARCHAR(255)` | **Direct PII** | Legitimate interest | 90 days | May reference non-existent accounts |
| `blocked_ips` | `ip_address` | `INET` | **Direct PII** | Legitimate interest | Until unblocked or expired | Permanent bans reviewed quarterly |
| `usage_events` | `user_id` | `INT` | **Indirect PII** | Contractual necessity (billing) | 13 months (billing cycle + 1) | Links to users table |
| `tenants` | `name` | `VARCHAR(255)` | **Organisational PII** | Contractual necessity | Account lifetime | Company/org name |

---

## Fields Explicitly NOT Stored

| Data Type | Reason |
|-----------|--------|
| Raw passwords | Only bcrypt hashes stored (cost factor 12) |
| Full card numbers | Payment processing delegated to Stripe |
| Bank account details | Not in scope; handled by payment processor |
| Payment tokens | Stripe manages tokenisation |
| Government ID numbers | Not collected |
| Biometric data | Not collected |

---

## Data Subject Rights (GDPR Article 15-22)

### Right to Access (Art. 15)
- Admin can export all user data via `/api/v1/exports/audit` endpoint
- PII masking views (`v_users_masked`) prevent unauthorised access

### Right to Rectification (Art. 16)
- Users can update their profile via the application
- All changes are logged in the immutable audit trail

### Right to Erasure / "Right to be Forgotten" (Art. 17)
- **Status**: NOT YET IMPLEMENTED
- **Requirement**: Must write deletion request to audit_log BEFORE erasing data
- **Design note**: User records should be anonymised (email → `deleted-{uuid}@redacted.edars`, full_name → `[Redacted]`) rather than hard-deleted, to preserve audit trail referential integrity
- **Action item**: Implement in Phase 2

### Right to Data Portability (Art. 20)
- The `/api/v1/exports` endpoints support JSON and CSV export
- Export events are metered and audit-logged

---

## Automated Decision-Making (Art. 22)

**Current status**: The anomaly detection and forecasting engines perform statistical
analysis but do NOT make automated decisions that produce legal effects concerning
individuals. These systems analyse aggregate financial transaction data, not individual
user behaviour.

**Behavioural scoring / user profiling**: OUT OF SCOPE for this phase. Any future
implementation requires legal review and explicit DPO sign-off before development
begins.

---

## Retention Schedule Summary

| Data Category | Retention Period | Purge Mechanism |
|---------------|-----------------|-----------------|
| Active user accounts | Indefinite (while active) | Admin deactivation |
| Deactivated user accounts | 30 days post-deactivation | Anonymisation job (TBD) |
| Audit logs | 2 years | Partition drop (quarterly review) |
| Session records | 30 days post-expiry | `cleanup_expired_sessions()` |
| Failed login records | 90 days | Date-based partition drop |
| Usage events | 13 months | Partition drop (monthly) |
| Blocked IPs | Until manually unblocked or expired | Admin review (quarterly) |

---

## Encryption at Rest

| Layer | Mechanism |
|-------|-----------|
| Database filesystem | Relies on host OS disk encryption (LUKS / BitLocker) |
| Column-level (PII) | pgcrypto AES-256 via `encrypt_pii()` / `decrypt_pii()` functions |
| Backups | Must be encrypted; configuration is infrastructure-team responsibility |

## Encryption in Transit

| Layer | Mechanism |
|-------|-----------|
| Client → Nginx | TLS 1.3 (HSTS enforced) |
| Nginx → Gateway | Internal Docker network (not encrypted; acceptable per threat model) |
| Gateway → DB/Redis | Internal Docker network |
