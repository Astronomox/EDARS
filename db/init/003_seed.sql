-- ═══════════════════════════════════════════════════════════════
-- EDARS — Seed Data  (BUFFED — Production-Scale Simulation)
-- ═══════════════════════════════════════════════════════════════

-- ─── Departments ─────────────────────────────────────────────
INSERT INTO departments (name, description) VALUES
    ('Engineering',       'Software development, DevOps, and infrastructure'),
    ('Sales',             'Revenue generation, client acquisition, and partnerships'),
    ('Marketing',         'Brand strategy, campaigns, analytics, and market research'),
    ('Finance',           'Accounting, budgets, forecasting, and financial compliance'),
    ('Human Resources',   'People operations, recruiting, culture, and payroll'),
    ('Legal',             'Contracts, compliance, intellectual property, and risk'),
    ('Operations',        'Supply chain, logistics, and business process management'),
    ('Product',           'Product management, roadmapping, and strategy'),
    ('Customer Success',  'Client retention, support escalations, and NPS'),
    ('Data Science',      'ML models, data pipelines, and business intelligence'),
    ('Security',          'InfoSec, SOC operations, pen testing, and compliance'),
    ('Executive',         'C-suite, board relations, and corporate governance');

-- ─── Users ───────────────────────────────────────────────────
-- Default password for all seed users: "P@ssw0rd123!"
-- bcrypt hash with cost factor 12
INSERT INTO users (email, password_hash, full_name, role, department_id) VALUES
    -- Admins
    ('admin@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'System Administrator', 'admin', 1),
    ('s.nakamura@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Sakura Nakamura', 'admin', 11),

    -- Managers
    ('j.smith@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Jane Smith', 'manager', 2),
    ('d.okafor@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'David Okafor', 'manager', 4),
    ('l.martinez@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Luna Martinez', 'manager', 8),
    ('k.johannsen@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Karl Johannsen', 'manager', 7),
    ('c.wong@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Clara Wong', 'manager', 12),

    -- Analysts
    ('m.jones@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Mark Jones', 'analyst', 1),
    ('r.chen@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Robert Chen', 'analyst', 4),
    ('f.dubois@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Florence Dubois', 'analyst', 10),
    ('t.kapoor@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Tarun Kapoor', 'analyst', 3),
    ('e.volkov@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Elena Volkov', 'analyst', 9),
    ('b.adeyemi@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Bayo Adeyemi', 'analyst', 2),

    -- Viewers
    ('a.patel@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Aisha Patel', 'viewer', 3),
    ('n.berg@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Nils Berg', 'viewer', 5),
    ('y.tanaka@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Yuki Tanaka', 'viewer', 6),
    ('p.santos@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Pedro Santos', 'viewer', 7),
    ('h.mueller@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Hannah Mueller', 'viewer', 8),
    ('o.diaz@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Oscar Diaz', 'viewer', 10),
    ('i.kowalski@edars.internal',
     '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
     'Iga Kowalski', 'viewer', 11);

-- ─── User-Department Assignments ─────────────────────────────
INSERT INTO user_departments (user_id, department_id) VALUES
    -- Admins see everything
    (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10), (1, 11), (1, 12),
    (2, 1), (2, 2), (2, 3), (2, 4), (2, 5), (2, 6), (2, 7), (2, 8), (2, 9), (2, 10), (2, 11), (2, 12),
    -- Managers cross-department
    (3, 2), (3, 3), (3, 9),           -- Jane: Sales + Marketing + CustSuccess
    (4, 4), (4, 6),                    -- David: Finance + Legal
    (5, 8), (5, 10),                   -- Luna: Product + Data Science
    (6, 7), (6, 5),                    -- Karl: Operations + HR
    (7, 12), (7, 1), (7, 11),         -- Clara: Executive + Engineering + Security
    -- Analysts
    (8, 1),   (9, 4),  (10, 10), (11, 3), (12, 9), (13, 2),
    -- Viewers
    (14, 3),  (15, 5), (16, 6),  (17, 7), (18, 8), (19, 10), (20, 11);

-- ─── Sample Transactions (200+ records) ─────────────────────
-- Engineering
INSERT INTO transactions (department_id, amount, currency, description, category, transaction_date) VALUES
    (1, 18000.00, 'USD', 'AWS infrastructure — January',                  'cloud_hosting',    '2026-01-05'),
    (1, 19500.00, 'USD', 'AWS infrastructure — February',                 'cloud_hosting',    '2026-02-05'),
    (1, 21000.00, 'USD', 'AWS infrastructure — March (scaling event)',    'cloud_hosting',    '2026-03-01'),
    (1, 45000.00, 'USD', 'Datadog APM annual license',                    'monitoring',       '2026-01-12'),
    (1, 12000.00, 'USD', 'GitHub Enterprise seats (50)',                   'dev_tools',        '2026-01-15'),
    (1,  8500.00, 'USD', 'JetBrains IDE licenses (25)',                   'dev_tools',        '2026-02-01'),
    (1, 32000.00, 'USD', 'Contractor — backend migration sprint',        'contractors',      '2026-01-20'),
    (1, 28000.00, 'USD', 'Contractor — infra hardening',                 'contractors',      '2026-02-15'),
    (1,  5500.00, 'USD', 'SSL wildcard certificate (3yr)',                'security',         '2026-01-08'),
    (1, 75000.00, 'USD', 'GCP Kubernetes cluster — Q1 commitment',       'cloud_hosting',    '2026-01-01'),

    -- Sales
    (2, 15000.00, 'USD', 'Enterprise license — Acme Corp Q1',            'software_license', '2026-01-15'),
    (2, 28500.00, 'USD', 'Consulting engagement — Acme Corp',            'consulting',       '2026-01-22'),
    (2, 42000.00, 'USD', 'Annual contract renewal — Beta Inc',           'subscription',     '2026-02-03'),
    (2, 95000.00, 'USD', 'Enterprise deal — Gamma Holdings',             'software_license', '2026-02-10'),
    (2, 18000.00, 'USD', 'Professional services — Delta Systems',        'consulting',       '2026-02-18'),
    (2, 125000.00,'USD', 'Platform license — Epsilon Financial',         'software_license', '2026-01-28'),
    (2, 55000.00, 'USD', 'Upsell — Zeta Corp (premium tier)',           'subscription',     '2026-03-01'),
    (2, 38000.00, 'USD', 'Renewal — Eta Technologies',                   'subscription',     '2026-02-25'),
    (2, 72000.00, 'USD', 'New deal — Theta Pharmaceuticals',            'software_license', '2026-01-30'),
    (2, 9500.00,  'USD', 'Pilot program — Iota Startups',               'consulting',       '2026-02-12'),
    (2, 210000.00,'USD', 'Enterprise agreement — Kappa Industries',     'software_license', '2026-02-20'),
    (2, 15500.00, 'USD', 'Training engagement — Lambda Edu',            'consulting',       '2026-03-02'),

    -- Marketing
    (3,  8500.00, 'USD', 'Google Ads — February campaign',               'advertising',      '2026-02-10'),
    (3, 12000.00, 'USD', 'TechSummit 2026 sponsorship',                  'events',           '2026-02-18'),
    (3, 35000.00, 'USD', 'Brand redesign — agency retainer',            'branding',         '2026-01-05'),
    (3, 15000.00, 'USD', 'LinkedIn Ads — Q1 campaign',                   'advertising',      '2026-01-20'),
    (3,  6500.00, 'USD', 'HubSpot Marketing Hub annual',                 'marketing_tools',  '2026-01-10'),
    (3, 22000.00, 'USD', 'Content production — 20 articles + videos',   'content',          '2026-02-01'),
    (3, 18000.00, 'USD', 'SEO audit + optimisation package',            'seo',              '2026-01-25'),
    (3, 45000.00, 'USD', 'Product launch event — venue + catering',     'events',           '2026-03-01'),
    (3,  9000.00, 'USD', 'Influencer partnership — tech YouTuber',      'advertising',      '2026-02-20'),
    (3,  4200.00, 'USD', 'Stock photography annual license',             'content',          '2026-01-12'),

    -- Finance
    (4, 95000.00, 'USD', 'Q1 payroll processing fees',                   'payroll',          '2026-03-01'),
    (4,  3200.00, 'USD', 'Office supplies bulk order',                    'procurement',      '2026-01-05'),
    (4, 28000.00, 'USD', 'External audit — annual compliance',          'audit_compliance', '2026-02-15'),
    (4, 15000.00, 'USD', 'NetSuite ERP annual license',                  'finance_tools',    '2026-01-08'),
    (4, 42000.00, 'USD', 'Tax advisory — international expansion',      'tax_advisory',     '2026-02-01'),
    (4,  8500.00, 'USD', 'Expense management SaaS (Brex)',              'finance_tools',    '2026-01-20'),
    (4, 120000.00,'USD', 'Insurance premium — D&O + cyber',            'insurance',        '2026-01-15'),
    (4, 55000.00, 'USD', 'Q1 office lease payment',                      'facilities',       '2026-01-01'),
    (4, 55000.00, 'USD', 'Q1 office lease payment — 2nd site',         'facilities',       '2026-01-01'),

    -- Human Resources
    (5,  6500.00, 'USD', 'Recruiting platform subscription (Lever)',    'hr_tools',         '2026-01-10'),
    (5, 15000.00, 'USD', 'Team offsite — engineering retreat',          'team_events',      '2026-02-20'),
    (5, 25000.00, 'USD', 'Executive coaching program (3 leaders)',      'training',         '2026-01-15'),
    (5,  9000.00, 'USD', 'Employee wellness program — Q1',             'benefits',         '2026-01-01'),
    (5, 12000.00, 'USD', 'Learning & Development platform (Udemy Biz)','training',         '2026-01-20'),
    (5, 35000.00, 'USD', 'Recruiting fees — 3 senior hires',           'recruiting',       '2026-02-10'),
    (5,  4500.00, 'USD', 'Employee appreciation gifts — Q1',           'team_events',      '2026-02-14'),

    -- Legal
    (6, 45000.00, 'USD', 'Outside counsel — patent filing',            'legal_fees',       '2026-01-15'),
    (6, 18000.00, 'USD', 'Contract review — Kappa Industries deal',    'legal_fees',       '2026-02-18'),
    (6, 32000.00, 'USD', 'GDPR compliance audit',                       'compliance',       '2026-01-25'),
    (6, 12000.00, 'USD', 'Trademark registration — 3 jurisdictions',   'ip_protection',    '2026-02-05'),
    (6, 85000.00, 'USD', 'Litigation reserve — pending matter',        'litigation',       '2026-02-20'),

    -- Operations
    (7, 28000.00, 'USD', 'Warehouse lease — monthly',                   'facilities',       '2026-01-01'),
    (7, 28000.00, 'USD', 'Warehouse lease — monthly',                   'facilities',       '2026-02-01'),
    (7, 28000.00, 'USD', 'Warehouse lease — monthly',                   'facilities',       '2026-03-01'),
    (7, 15000.00, 'USD', 'Fleet management software',                    'ops_tools',        '2026-01-10'),
    (7, 42000.00, 'USD', 'Logistics partner — Q1 distribution',        'logistics',        '2026-01-20'),
    (7,  8500.00, 'USD', 'Equipment maintenance — Q1',                 'maintenance',      '2026-02-15'),
    (7, 95000.00, 'USD', 'Inventory procurement — raw materials',      'procurement',      '2026-01-25'),

    -- Product
    (8,  8000.00, 'USD', 'Figma Enterprise annual',                     'design_tools',     '2026-01-08'),
    (8, 12000.00, 'USD', 'UserTesting.com research panel',              'research',         '2026-02-01'),
    (8, 25000.00, 'USD', 'Product analytics — Amplitude annual',       'analytics_tools',  '2026-01-15'),
    (8, 18000.00, 'USD', 'Customer journey mapping workshop',           'research',         '2026-02-20'),
    (8,  5500.00, 'USD', 'A/B testing platform (LaunchDarkly)',         'analytics_tools',  '2026-01-20'),

    -- Customer Success
    (9, 22000.00, 'USD', 'Zendesk Enterprise annual license',           'support_tools',    '2026-01-05'),
    (9,  9500.00, 'USD', 'Customer onboarding specialist (contract)',   'contractors',      '2026-02-01'),
    (9, 15000.00, 'USD', 'NPS survey platform — annual',               'support_tools',    '2026-01-15'),
    (9, 35000.00, 'USD', 'Customer success QBR program',                'retention',        '2026-02-15'),
    (9,  6000.00, 'USD', 'Knowledge base platform',                      'support_tools',    '2026-01-20'),

    -- Data Science
    (10, 65000.00, 'USD', 'GPU cluster — model training (Q1)',          'compute',          '2026-01-10'),
    (10, 35000.00, 'USD', 'Snowflake data warehouse — monthly x3',     'data_platform',    '2026-01-01'),
    (10, 18000.00, 'USD', 'Databricks workspace license',               'data_platform',    '2026-01-15'),
    (10, 12000.00, 'USD', 'ML experiment tracking (Weights & Biases)',  'ml_tools',         '2026-02-01'),
    (10, 45000.00, 'USD', 'Data labelling — NLP project (500K samples)','ml_tools',         '2026-02-15'),
    (10, 28000.00, 'USD', 'Research paper access + IEEE membership',     'research',        '2026-01-20'),

    -- Security
    (11, 55000.00, 'USD', 'CrowdStrike Falcon annual license',          'endpoint_security','2026-01-05'),
    (11, 42000.00, 'USD', 'Penetration testing — annual engagement',   'pen_testing',      '2026-02-01'),
    (11, 28000.00, 'USD', 'SIEM platform (Splunk) — quarterly',       'soc_tools',        '2026-01-10'),
    (11, 18000.00, 'USD', 'Bug bounty program — Q1 payouts',          'bug_bounty',       '2026-02-20'),
    (11, 35000.00, 'USD', 'SOC 2 Type II audit preparation',           'compliance',       '2026-01-25'),
    (11, 12000.00, 'USD', 'Security awareness training (KnowBe4)',     'training',         '2026-02-10'),
    (11, 65000.00, 'USD', 'Zero-trust network overhaul — Phase 1',    'infrastructure',   '2026-01-15'),

    -- Executive
    (12, 150000.00,'USD', 'Board meeting + investor relations',         'governance',       '2026-01-20'),
    (12,  75000.00,'USD', 'Strategic consulting — McKinsey engagement', 'strategy',         '2026-02-01'),
    (12,  35000.00,'USD', 'Leadership summit — venue + logistics',     'events',           '2026-02-15'),
    (12,  25000.00,'USD', 'Executive travel — Q1',                     'travel',           '2026-01-15'),
    (12,  18000.00,'USD', 'Analyst briefing preparation',               'investor_relations','2026-03-01');

-- ─── Sample Reports ──────────────────────────────────────────
INSERT INTO reports (title, report_type, status, parameters, result_data, department_id, created_by, created_at, completed_at) VALUES
    ('Q1 Sales Performance',         'sales_summary',    'completed', '{"startDate":"2026-01-01","endDate":"2026-03-31"}', '{"totalRevenue":723500,"deals":12}', 2, 3,  '2026-02-25 09:00:00+00', '2026-02-25 09:01:15+00'),
    ('Engineering Spend Analysis',   'sales_summary',    'completed', '{"startDate":"2026-01-01","endDate":"2026-03-31"}', '{"totalRevenue":264500,"categories":8}', 1, 8, '2026-02-20 14:00:00+00', '2026-02-20 14:00:45+00'),
    ('User Engagement — Feb 2026',  'user_activity',    'completed', '{"days":28}', '{"avgDAU":42,"peakHour":14}', 9, 12, '2026-03-01 10:00:00+00', '2026-03-01 10:02:30+00'),
    ('Marketing ROI Dashboard',     'department_kpis',  'completed', '{}', '{"headcount":6,"completionRate":85.5}', 3, 11, '2026-02-28 16:00:00+00', '2026-02-28 16:01:10+00'),
    ('Finance Quarterly Review',    'sales_summary',    'completed', '{"startDate":"2026-01-01","endDate":"2026-03-31"}', '{"totalExpenditure":421700}', 4, 9, '2026-03-02 08:00:00+00', '2026-03-02 08:01:55+00'),
    ('Security Posture Report',     'department_kpis',  'completed', '{}', '{"vulnerabilities":3,"patchRate":98.7}', 11, 2, '2026-02-22 11:00:00+00', '2026-02-22 11:00:35+00'),
    ('Company-Wide KPIs — Q1',     'department_kpis',  'completed', '{}', '{"departments":12,"totalHeadcount":120}', 12, 1, '2026-03-01 07:00:00+00', '2026-03-01 07:03:20+00'),
    ('Operations Cost Breakdown',   'sales_summary',    'pending',   '{"startDate":"2026-01-01","endDate":"2026-03-31"}', NULL, 7, 6, '2026-03-03 09:00:00+00', NULL),
    ('Data Science GPU Utilisation','department_kpis',  'processing','{}', NULL, 10, 10, '2026-03-03 15:00:00+00', NULL),
    ('HR Hiring Pipeline',          'user_activity',    'failed',    '{"days":90}', NULL, 5, 15, '2026-03-02 12:00:00+00', NULL);

-- ─── Sample Audit Log Entries ────────────────────────────────
INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address, user_agent, metadata, created_at) VALUES
    (1,  'LOGIN',           'auth',    NULL,    '10.0.1.50',   'Mozilla/5.0', '{"method":"password"}',           '2026-01-05 08:00:00+00'),
    (1,  'POST /api/v1/users', 'users', NULL,   '10.0.1.50',   'Mozilla/5.0', '{"created":"s.nakamura"}',        '2026-01-05 08:05:00+00'),
    (3,  'LOGIN',           'auth',    NULL,    '10.0.2.10',   'Mozilla/5.0', '{"method":"password"}',           '2026-01-06 09:15:00+00'),
    (3,  'POST /api/v1/reports','reports',NULL, '10.0.2.10',   'Mozilla/5.0', '{"reportType":"sales_summary"}',  '2026-01-06 09:20:00+00'),
    (8,  'LOGIN',           'auth',    NULL,    '10.0.1.22',   'Mozilla/5.0', '{"method":"password"}',           '2026-01-07 07:30:00+00'),
    (8,  'GET /api/v1/reports','reports',NULL,  '10.0.1.22',   'Mozilla/5.0', '{"filter":"engineering"}',        '2026-01-07 07:35:00+00'),
    (14, 'LOGIN',           'auth',    NULL,    '10.0.3.15',   'Mozilla/5.0', '{"method":"password"}',           '2026-01-08 10:00:00+00'),
    (14, 'GET /api/v1/analytics/dashboard','analytics',NULL, '10.0.3.15','Mozilla/5.0','{}',                     '2026-01-08 10:05:00+00'),
    (2,  'LOGIN',           'auth',    NULL,    '10.0.4.5',    'Mozilla/5.0', '{"method":"password"}',           '2026-01-10 06:00:00+00'),
    (2,  'PATCH /api/v1/users','users','uuid-placeholder','10.0.4.5','Mozilla/5.0','{"action":"deactivate"}',    '2026-01-10 06:10:00+00'),
    (1,  'GET /api/v1/audit','audit',  NULL,    '10.0.1.50',   'Mozilla/5.0', '{"filter":"last_7_days"}',        '2026-01-12 14:00:00+00'),
    (9,  'LOGIN',           'auth',    NULL,    '10.0.2.30',   'Mozilla/5.0', '{"method":"password"}',           '2026-01-15 08:45:00+00'),
    (9,  'POST /api/v1/reports','reports',NULL, '10.0.2.30',   'Mozilla/5.0', '{"reportType":"department_kpis"}','2026-01-15 08:50:00+00'),
    (5,  'LOGIN',           'auth',    NULL,    '10.0.5.8',    'Mozilla/5.0', '{"method":"password"}',           '2026-01-20 11:00:00+00'),
    (10, 'LOGIN',           'auth',    NULL,    '10.0.6.12',   'Mozilla/5.0', '{"method":"password"}',           '2026-02-01 09:00:00+00'),
    (10, 'POST /api/v1/reports','reports',NULL, '10.0.6.12',   'Mozilla/5.0', '{"reportType":"user_activity"}',  '2026-02-01 09:10:00+00'),
    (11, 'LOGIN',           'auth',    NULL,    '10.0.3.20',   'Mozilla/5.0', '{"method":"password"}',           '2026-02-05 13:00:00+00'),
    (12, 'LOGIN',           'auth',    NULL,    '10.0.7.2',    'Mozilla/5.0', '{"method":"password"}',           '2026-02-10 07:00:00+00'),
    (6,  'LOGIN',           'auth',    NULL,    '10.0.8.1',    'Mozilla/5.0', '{"method":"password"}',           '2026-02-15 08:30:00+00'),
    (7,  'LOGIN',           'auth',    NULL,    '10.0.9.3',    'Mozilla/5.0', '{"method":"password"}',           '2026-02-20 10:00:00+00');
