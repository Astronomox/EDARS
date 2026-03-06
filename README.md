# EDARS — Enterprise Data Analytics & Reporting System

> Secure, scalable microservices platform for enterprise reporting with defence-in-depth security.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL NETWORK                         │
│                                                             │
│  Client ──► Nginx (TLS 1.3) ──► API Gateway (Node.js)      │
│              :80/:443              :3000                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   INTERNAL NETWORK (isolated)               │
│                                                             │
│  Analytics Engine (Python/FastAPI) ◄── service token auth   │
│           :8000                                             │
│                                                             │
│  PostgreSQL 16 ◄── RLS + partitioning + immutable audit     │
│           :5432                                             │
│                                                             │
│  Redis 7 ◄── rate limit state + query caching               │
│           :6379                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose v2+
- OpenSSL (for TLS certificate generation)

### 1. Generate TLS Certificates (if not already present)
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
```

### 3. Launch the Stack
```bash
docker-compose up --build -d
```

### 4. Verify Health
```bash
curl http://localhost/nginx-health    # Nginx
curl http://localhost:3000/health     # API Gateway (direct, for debugging)
```

## API Endpoints

### Authentication
| Method | Endpoint               | Auth     | Description           |
|--------|------------------------|----------|-----------------------|
| POST   | `/api/v1/auth/login`   | None     | Login, returns JWT    |
| POST   | `/api/v1/auth/register`| Admin    | Create new user       |

### Reports
| Method | Endpoint                   | Roles                     | Description               |
|--------|----------------------------|---------------------------|---------------------------|
| GET    | `/api/v1/reports`          | All authenticated         | List reports (RLS-scoped) |
| GET    | `/api/v1/reports/:uuid`    | All authenticated         | Get report detail         |
| POST   | `/api/v1/reports`          | Analyst, Manager, Admin   | Create & trigger report   |

### Analytics
| Method | Endpoint                          | Roles              | Description              |
|--------|-----------------------------------|---------------------|--------------------------|
| GET    | `/api/v1/analytics/dashboard`     | All authenticated   | Dashboard metrics        |
| GET    | `/api/v1/analytics/sales-summary` | Analyst+            | Sales report             |
| GET    | `/api/v1/analytics/user-activity` | Analyst+            | User activity analytics  |
| GET    | `/api/v1/analytics/department-kpis` | Manager+          | Department KPIs          |

### Users
| Method | Endpoint                         | Roles | Description              |
|--------|----------------------------------|-------|--------------------------|
| GET    | `/api/v1/users/me`              | All   | Current user profile     |
| GET    | `/api/v1/users`                 | Admin | List all users           |
| PATCH  | `/api/v1/users/:uuid/deactivate`| Admin | Deactivate user          |

### Audit
| Method | Endpoint          | Roles | Description              |
|--------|-------------------|-------|--------------------------|
| GET    | `/api/v1/audit`   | Admin | Query immutable audit log|

## Security Layers

1. **Transport**: TLS 1.3, HSTS with preload, comprehensive security headers
2. **Authentication**: JWT (HS256, 8h expiry), bcrypt (cost 12)
3. **Authorisation**: 4-tier RBAC (Viewer → Analyst → Manager → Admin)
4. **Data Isolation**: PostgreSQL Row-Level Security per department
5. **Rate Limiting**: 100 req / 15 min per IP (Redis-backed)
6. **Audit Trail**: Immutable append-only log with triggers preventing UPDATE/DELETE
7. **Network Isolation**: Analytics + DB on internal-only Docker network
8. **Payload Protection**: 10KB body size limit on all endpoints

## Seed Users

| Email                    | Role    | Department  | Password (dev only)  |
|--------------------------|---------|-------------|----------------------|
| admin@edars.internal     | admin   | Engineering | P@ssw0rd123!         |
| j.smith@edars.internal   | manager | Sales       | P@ssw0rd123!         |
| m.jones@edars.internal   | analyst | Engineering | P@ssw0rd123!         |
| a.patel@edars.internal   | viewer  | Marketing   | P@ssw0rd123!         |
| r.chen@edars.internal    | analyst | Finance     | P@ssw0rd123!         |

## Production Checklist

- [ ] Replace self-signed TLS cert with CA-issued certificate
- [ ] Rotate JWT_SECRET, SERVICE_TOKEN, and all DB passwords
- [ ] Enable SSL on PostgreSQL connection
- [ ] Configure automated database backups with PITR
- [ ] Deploy behind cloud load balancer for HA
- [ ] Enable OCSP stapling in Nginx config
- [ ] Set ALLOWED_ORIGINS to production domain(s)
- [ ] Run `npm audit` and `pip audit` before deploy
