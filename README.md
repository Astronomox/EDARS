# EDARS — Enterprise Data Analytics & Reporting System

> Secure, scalable, multi-tenant microservices platform for enterprise reporting with defence-in-depth security, GDPR/NDPA compliance, and plan-based feature gating.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      EXTERNAL NETWORK                           │
│                                                                 │
│  Client ──► Nginx (TLS 1.3) ──►┐                               │
│              :80/:443           │                               │
│                                 │ Bot Blocking                  │
│                                 │ Rate Limiting (3-tier)        │
│                                 │ Security Headers              │
│                                 │                               │
│                                 ▼                               │
│                          API Gateway (Node.js)                  │
│                              :3000                              │
│                                                                 │
│   ┌─ Request Tracer ── Sanitiser ── HMAC Verify ──┐            │
│   │  Threat Intel ── Rate Limiter ── Auth + JWT    │            │
│   │  Tenancy (Plan Gate) ── Audit Logger           │            │
│   │  Circuit Breaker ── IP Whitelist               │            │
│   └────────────────────────────────────────────────┘            │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                   INTERNAL NETWORK (isolated)                   │
│                                                                 │
│  Analytics Engine (Python/FastAPI) ◄── service token auth       │
│         :8000                         caching, trend analysis   │
│                                       anomaly detection         │
│                                       ML forecasting            │
│                                                                 │
│  PostgreSQL 16 ◄── RLS + partitioning + immutable audit         │
│         :5432      multi-tenant isolation, PII masking          │
│                    security hardening, hash chain audit          │
│                                                                 │
│  Redis 7 ◄── rate limit state + query caching + token blacklist │
│         :6379                                                   │
│                                                                 │
│  Prometheus + Alertmanager ◄── metrics, alerts, dashboards      │
│         :9090 / :9093                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose v2+
- OpenSSL (for TLS certificate generation)

### 1. Generate TLS Certificates
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout proxy/certs/server.key \
  -out proxy/certs/server.crt \
  -subj "/C=US/ST=State/L=City/O=EDARS/CN=localhost"
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env — rotate ALL secrets before production
# Generate secure secrets with:
#   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 3. Launch the Stack
```bash
docker-compose up --build -d
```

### 4. Verify Health
```bash
curl http://localhost/nginx-health    # Nginx
curl http://localhost:3000/health     # API Gateway
curl http://localhost:9090/-/healthy  # Prometheus
```

---

## API Endpoints

### Authentication
| Method | Endpoint                         | Auth   | Description                       |
|--------|----------------------------------|--------|-----------------------------------|
| POST   | `/api/v1/auth/login`             | None   | Login, returns JWT                |
| POST   | `/api/v1/auth/register`          | Admin  | Create new user (consent required)|
| POST   | `/api/v1/auth/refresh`           | JWT    | Rotate refresh token              |
| POST   | `/api/v1/auth/logout`            | JWT    | Logout + token blacklist          |
| POST   | `/api/v1/auth/change-password`   | JWT    | Password change + strength check  |
| GET    | `/api/v1/auth/password-policy`   | None   | Password requirements             |

### Reports
| Method | Endpoint                   | Roles                     | Description               |
|--------|----------------------------|---------------------------|---------------------------|
| GET    | `/api/v1/reports`          | All authenticated         | List reports (RLS-scoped) |
| GET    | `/api/v1/reports/:uuid`    | All authenticated         | Get report detail         |
| POST   | `/api/v1/reports`          | Analyst, Manager, Admin   | Create & trigger report   |

### Analytics
| Method | Endpoint                            | Roles / Plan        | Description                    |
|--------|-------------------------------------|----------------------|--------------------------------|
| GET    | `/api/v1/analytics/dashboard`       | All authenticated    | Dashboard metrics              |
| GET    | `/api/v1/analytics/sales-summary`   | Growth+              | Sales report                   |
| GET    | `/api/v1/analytics/user-activity`   | Analyst+             | User activity analytics        |
| GET    | `/api/v1/analytics/department-kpis` | Enterprise only      | Department KPIs                |
| GET    | `/api/v1/analytics/trends`          | Growth+              | MoM growth, rolling averages   |
| GET    | `/api/v1/analytics/anomalies`       | Growth+              | Z-score spending outliers      |

### Users
| Method | Endpoint                           | Roles | Description              |
|--------|------------------------------------|-------|--------------------------|
| GET    | `/api/v1/users/me`                 | All   | Current user profile     |
| GET    | `/api/v1/users`                    | Admin | List all users           |
| PATCH  | `/api/v1/users/:uuid/deactivate`   | Admin | Deactivate user          |

### Exports
| Method | Endpoint                    | Roles    | Description              |
|--------|-----------------------------|----------|--------------------------|
| GET    | `/api/v1/exports/:type`     | Growth+  | CSV/JSON bulk export     |

### Audit
| Method | Endpoint          | Roles | Description               |
|--------|-------------------|-------|---------------------------|
| GET    | `/api/v1/audit`   | Admin | Query immutable audit log |

### Admin (IP-Whitelisted)
| Method | Endpoint                                 | Description                        |
|--------|------------------------------------------|------------------------------------|
| POST   | `/api/v1/admin/refresh-views`            | Refresh materialized views         |
| GET    | `/api/v1/admin/anomalies`                | Spending outlier detection (z-score)|
| GET    | `/api/v1/admin/inactive-users`           | Dormant account identification     |
| GET    | `/api/v1/admin/department-health/:id`    | Composite health scoring           |
| GET    | `/api/v1/admin/threats`                  | Threat intelligence summary        |
| POST   | `/api/v1/admin/threats/unblock`          | Unblock IP address                 |
| GET    | `/api/v1/admin/security-dashboard`       | Security analytics dashboard       |
| POST   | `/api/v1/admin/tenants`                  | Create new tenant                  |
| GET    | `/api/v1/admin/tenants`                  | List all tenants                   |
| PATCH  | `/api/v1/admin/tenants/:id/suspend`      | Suspend tenant                     |
| DELETE | `/api/v1/admin/tenants/:id/request-deletion` | Schedule tenant deletion (30d hold)|
| DELETE | `/api/v1/admin/tenants/:id/execute-deletion` | Execute anonymisation after hold   |

### Health & Metrics
| Method | Endpoint      | Auth | Description               |
|--------|---------------|------|---------------------------|
| GET    | `/health`     | None | Liveness + readiness      |
| GET    | `/metrics`    | None | Prometheus metrics        |

---

## Security Stack — 14 Layers

| #  | Layer                   | Mechanism                                                    |
|----|-------------------------|--------------------------------------------------------------|
| 1  | Transport               | TLS 1.3 + HSTS preload + session cache                      |
| 2  | Bot Protection          | User-agent scanner blocking (sqlmap, nikto, nessus, etc.)    |
| 3  | Honeypot Traps          | Fake endpoints trap scanners → auto-block                    |
| 4  | Rate Limiting           | 3-tier (auth/export/api) at Nginx + Redis                    |
| 5  | Threat Intelligence     | IP scoring, escalating blocks, permanent bans                |
| 6  | HMAC Request Signing    | Tamper-proof request verification with nonce replay defence   |
| 7  | Input Sanitisation      | XSS/injection pattern stripping                              |
| 8  | Authentication          | JWT HS256 + bcrypt cost 12 + token blacklist + secret rotation|
| 9  | Account Lockout         | 5 failures → 15min lock (Redis)                              |
| 10 | Plan-Based Gating       | 3-tier feature gates (free/growth/enterprise)                |
| 11 | Authorisation           | 4-tier RBAC + IP whitelisting                                |
| 12 | Data Isolation          | PostgreSQL RLS per tenant + PII masking views                |
| 13 | Circuit Breaking        | CLOSED/OPEN/HALF_OPEN state machine for downstream services  |
| 14 | Audit Trail             | Immutable append-only + DB triggers + SHA-256 hash chain     |

---

## Multi-Tenancy

EDARS implements full database-level multi-tenancy:

- **Tenant Isolation**: PostgreSQL RLS policies enforce data isolation per tenant
- **Plan Gating**: Routes gated by tenant plan tier (free → growth → enterprise)
- **Usage Metering**: Event-based tracking for billing (api_call, report_generated, etc.)
- **GDPR Right to Erasure**: Two-phase deletion with 30-day legal hold
- **PII Masking**: Non-admin users see masked emails/names via DB views

## Database Migrations

Migrations run in order on first `docker-compose up`:

| #   | File                         | Purpose                                                    |
|-----|------------------------------|------------------------------------------------------------|
| 001 | `001_schema.sql`             | 5 tables, quarterly partitioning, UUIDs, audit triggers    |
| 002 | `002_rls.sql`                | Row-Level Security with forced policies                    |
| 003 | `003_seed.sql`               | 12 departments, 20 users, 85+ transactions, seed data     |
| 004 | `004_advanced.sql`           | GIN indexes, 3 materialized views, 5 stored procedures     |
| 005 | `005_security_hardening.sql` | PII encryption, session mgmt, IP blocking, audit hash chain|
| 005 | `005_tenants.sql`            | Tenants table, create_tenant procedure, dev seed           |
| 006 | `006_add_tenancy.sql`        | Add tenant_id FK to all data tables, backfill              |
| 007 | `007_tenant_rls.sql`         | Rewrite RLS policies for tenant isolation, edars_app role  |
| 008 | `008_consent.sql`            | GDPR/NDPA consent tracking columns                         |
| 009 | `009_tenant_lifecycle.sql`   | Right to erasure (request + execute deletion)              |

---

## Seed Users

| Email                    | Role    | Department  | Password (dev only) |
|--------------------------|---------|-------------|---------------------|
| admin@edars.internal     | admin   | Engineering | P@ssw0rd123!        |
| j.smith@edars.internal   | manager | Sales       | P@ssw0rd123!        |
| m.jones@edars.internal   | analyst | Engineering | P@ssw0rd123!        |
| a.patel@edars.internal   | viewer  | Marketing   | P@ssw0rd123!        |
| r.chen@edars.internal    | analyst | Finance     | P@ssw0rd123!        |

---

## Testing

### Unit Tests (Gateway)
```bash
cd gateway && npm test
```

### Unit Tests (Analytics)
```bash
cd analytics && pytest tests/ -v
```

### Integration Tests (requires Docker stack)
```bash
cd gateway && npm run test:integration
```

### Load Test (requires [k6](https://k6.io))
```bash
k6 run tests/load/k6-load-test.js
```

### Linting
```bash
# Node.js
cd gateway && npm run lint && npm run format:check

# Python
cd analytics && ruff check . && ruff format --check .
```

---

## Monitoring

The stack includes production-ready monitoring:

- **Prometheus** — scrapes gateway, analytics, PostgreSQL exporter, Redis exporter
- **Alertmanager** — routes alerts via email/webhook/PagerDuty
- **Alert Rules** — high error rate, gateway down, high latency, circuit breaker open, threat blocks, memory pressure, DB pool exhaustion

Access Prometheus at `http://localhost:9090` (internal network only).

---

## CI/CD

GitHub Actions pipeline (`.github/workflows/ci.yml`):

1. **Lint** — ESLint + Prettier (Node), ruff + mypy (Python)
2. **Unit Tests** — Jest with Redis service (Node), Pytest (Python)
3. **Coverage** — uploaded to Codecov
4. **Docker Build** — on PRs to main and merges
5. **Image Push** — to GitHub Container Registry on merge to main
6. **Deploy** — SSH-based staging deploy with manual approval gate

---

## Production Checklist

- [ ] Replace self-signed TLS cert with CA-issued certificate
- [ ] Rotate JWT_SECRET, SERVICE_TOKEN, HMAC_SECRET, and all DB passwords
- [ ] Enable SSL on PostgreSQL connection
- [ ] Configure automated database backups with PITR
- [ ] Deploy behind cloud load balancer for HA
- [ ] Enable OCSP stapling in Nginx config
- [ ] Set ALLOWED_ORIGINS to production domain(s)
- [ ] Set ADMIN_IP_WHITELIST to actual admin IPs
- [ ] Change edars_app database role password
- [ ] Run `npm audit` and `pip audit` before deploy
- [ ] Configure Alertmanager receivers (email/Slack/PagerDuty)
- [ ] Set up Grafana dashboards connected to Prometheus
- [ ] Review and tune rate limiter thresholds for production traffic
