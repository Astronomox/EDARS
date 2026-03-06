# EDARS Data Dictionary & Compliance Record

This document serves as the authoritative legal record of all personal data (PII) processed by the Enterprise Data Analytics & Reporting System (EDARS). It is maintained to demonstrate compliance with the **General Data Protection Regulation (GDPR)**, **UK GDPR**, and the **Nigeria Data Protection Act 2023 (NDPA)**.

**Data Controller:** [Your Company Name]  
**DSAR Contact Email:** privacy@edars.io

---

## 1. PII Field Inventory

### Table: `users`
This table stores the primary identity and authentication records for all individuals using the system.

| Column Name | Data Type | Is PII? | Legal Basis for Processing | Retention Period | Handling Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `id`, `uuid` | INT, UUID | Yes (Pseudonymous identifier) | Contractual Necessity | Tenant lifespan | Used as FK across DB. Not deleted during erasure, but severed from identity. |
| `email` | VARCHAR | **Yes** | Contractual Necessity | Tenant lifespan | Used for login and comms. Replaced with `deleted-ID@redacted.invalid` on erasure. Never logged in plain text (SHA-256 hashed). |
| `password_hash` | TEXT | **Yes** (Security Data) | Contractual Necessity | Tenant lifespan | Bcrypt cost 12. Never logged. Anonymised to `REDACTED` on erasure. |
| `full_name` | VARCHAR | **Yes** | Contractual Necessity | Tenant lifespan | Displayed in UI. Anonymised to `Deleted User` on erasure. |
| `last_login_at` | TIMESTAMPTZ | Yes (Behavioural) | Legitimate Interest (Security) | Tenant lifespan | Used for security monitoring. |
| `tos_accepted_at` | TIMESTAMPTZ | Yes (Consent record) | Legal Obligation | Tenant lifespan + 7 yrs (Statute of limitations) | Proof of consent to Terms of Service. |
| `privacy_policy_accepted_at` | TIMESTAMPTZ | Yes (Consent record) | Legal Obligation | Tenant lifespan + 7 yrs | Proof of consent to Privacy processing. |

### Table: `audit_log`
This table provides a legally required, immutable trail of all system mutations and sensitive data access.

| Column Name | Data Type | Is PII? | Legal Basis for Processing | Retention Period | Handling Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user_id` | INT | Yes (Linkable) | Legitimate Interest (Security & Audit) | Immutable | Links to user row. Remains intact after erasure contextually, but user row is anonymised. |
| `ip_address` | INET | **Yes** | Legitimate Interest (Security & Fraud Prev) | Immutable | **Treated as PII under GDPR/NDPA.** Masked to `0.0.0.0` during right-to-erasure executions. |
| `user_agent` | TEXT | Yes (Fingerprinting) | Legitimate Interest (Security) | Immutable | Masked to `REDACTED` during erasure. |
| `metadata` | JSONB | Potentially | Legitimate Interest | Immutable | Must never contain plain-text emails, passwords, or financial data. |

---

## 2. IP Addresses as Personal Data
Under the **GDPR**, **UK GDPR**, and the **NDPA (2023)**, dynamic and static IP addresses are classified as Personal Identifiable Information (PII) because they can be combined with other data (like ISP records) to identify an individual. 

In EDARS:
- IP addresses are collected strictly for security, rate-limiting, and fraud prevention (Legal Basis: Legitimate Interest).
- They are stored in the immutable `audit_log`.
- During a Right to Erasure request, IP addresses belonging to the erased tenant are permanently masked to `0.0.0.0`.

---

## 3. Consent Recording Approach
EDARS implements a strict "opt-in" consent model:
1. Consent cannot be assumed. At the point of registration, the user/admin must explicitly pass `tosAccepted: true` and `privacyAccepted: true`.
2. The exact timestamp of acceptance and the specific document versions (e.g., `2026-03`) are recorded in the `users` table (`tos_accepted_at`, `tos_version`, etc.).
3. A corresponding `USER_CONSENT_RECORDED` event is immediately written to the immutable `audit_log` confirming the IP address, timestamp, and versions.
4. Consent columns are strictly protected and can never be `NULL`ed retroactively outside of a full anonymisation wipe.

---

## 4. Right to Erasure (GDPR Art. 17 / NDPA Sec. 34)
Data subjects have the right to be forgotten. Because EDARS is a multi-tenant B2B system where structural integrity and auditability must be maintained, we employ a **Two-Phase Anonymisation Strategy** rather than raw record deletion.

**The Procedure:**
1. **Request (Phase 1):** Call `/api/v1/admin/tenants/:id/request-deletion`. The tenant is immediately suspended (blocking login and data access). A 30-day legal hold period is started (`deletion_scheduled_at`). This provides a window to recover from malicious or accidental deletion requests.
2. **Execute (Phase 2):** After 30 days, call `/api/v1/admin/tenants/:id/execute-deletion`. 
   - Uses `execute_tenant_deletion` stored procedure.
   - **User PII Anonymisation:** Emails become `deleted-UUID@redacted.invalid`, names become `Deleted User`. Passwords are wiped.
   - **Audit PII Masking:** IP addresses become `0.0.0.0`. Immutability triggers are temporarily disabled for this sanitisation step only.
   - **Data Wiping:** All reports and transactions for the tenant are permanently dropped (`DELETE`).
   - The tenant row and audit rows remain as an anonymous skeleton to prove *something* happened, without identifying *who* it was.

---

## 5. Nigeria Data Protection Act (NDPA) 2023 Compliance
As the founding team processes data under Nigerian jurisdiction, EDARS strictly complies with the NDPA.
- **Lawful Basis:** Explicit consent and contractual necessity are recorded.
- **Data Security:** Data is encrypted in transit and at rest, with strict RLS (Row-Level Security) ensuring absolute tenant isolation (Sec. 39).
- **Data Subject Rights:** Right to Erasure and Access are supported via the tenant lifecycle procedures.
- **Cross-Border Transfer:** By design, the architecture supports isolated localized deployments if required to comply with data sovereignty regulations (Sec. 41).
