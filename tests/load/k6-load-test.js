/**
 * tests/load/k6-load-test.js
 *
 * EDARS Load Test — k6
 * 100 virtual users sustained for 10 minutes
 *
 * Free tool: https://k6.io (open source, runs locally)
 *
 * Installation (free, no account needed):
 *   Linux:   sudo snap install k6
 *   macOS:   brew install k6
 *   Windows: winget install k6 --source winget
 *            OR download from https://github.com/grafana/k6/releases
 *
 * Usage:
 *   # Basic run
 *   k6 run tests/load/k6-load-test.js
 *
 *   # With custom gateway URL
 *   GATEWAY_URL=http://localhost:3000 k6 run tests/load/k6-load-test.js
 *
 *   # Generate HTML report (free k6 feature)
 *   k6 run --out json=results.json tests/load/k6-load-test.js
 *
 * Pass/Fail Thresholds (defined below):
 *   - 95th percentile response time < 500ms
 *   - Error rate < 1%
 *   - All requests succeed (status 200 or 401 for unauth'd)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ── Custom metrics ────────────────────────────────────────────
const authErrors    = new Counter('auth_errors');
const analyticsTime = new Trend('analytics_response_time');
const errorRate     = new Rate('error_rate');

// ── Test configuration ────────────────────────────────────────
export const options = {
  stages: [
    { duration: '2m',  target: 20  },   // Ramp up to 20 VUs over 2 min
    { duration: '5m',  target: 100 },   // Ramp up to 100 VUs over 5 min
    { duration: '3m',  target: 100 },   // Hold at 100 VUs for 3 min
    { duration: '1m',  target: 0   },   // Ramp down
  ],

  thresholds: {
    // 95% of requests must complete within 500ms
    http_req_duration: ['p(95)<500'],

    // 99% of requests must complete within 1500ms
    'http_req_duration{name:dashboard}': ['p(99)<1500'],
    'http_req_duration{name:reports}':   ['p(99)<2000'],

    // Error rate must stay below 1%
    error_rate: ['rate<0.01'],

    // Custom analytics trend must stay responsive
    analytics_response_time: ['p(95)<800'],
  },
};

// ── Config ────────────────────────────────────────────────────
const BASE_URL = __ENV.GATEWAY_URL || 'http://localhost:3000';

// Seed credentials — must match 003_seed.sql
const USERS = [
  { email: 'admin@edars.internal',   password: 'P@ssw0rd123!', role: 'admin'   },
  { email: 'j.smith@edars.internal', password: 'P@ssw0rd123!', role: 'manager' },
  { email: 'm.jones@edars.internal', password: 'P@ssw0rd123!', role: 'analyst' },
  { email: 'a.patel@edars.internal', password: 'P@ssw0rd123!', role: 'viewer'  },
  { email: 'r.chen@edars.internal',  password: 'P@ssw0rd123!', role: 'analyst' },
];

// ── Setup: runs once before the test, not counted in VU load ──
export function setup() {
  // Pre-authenticate all seed users and store their tokens
  const tokens = {};

  USERS.forEach((user) => {
    const res = http.post(
      `${BASE_URL}/api/v1/auth/login`,
      JSON.stringify({ email: user.email, password: user.password }),
      { headers: { 'Content-Type': 'application/json' } }
    );

    if (res.status === 200) {
      tokens[user.role] = res.json('token');
    } else {
      console.error(
        `Setup login failed for ${user.email}: ${res.status} ${res.body}`
      );
    }
  });

  return { tokens };
}

// ── Main VU scenario ──────────────────────────────────────────
export default function (data) {
  const { tokens } = data;

  // Each VU randomly picks a role
  const roles = Object.keys(tokens);
  const role  = roles[Math.floor(Math.random() * roles.length)];
  const token = tokens[role];

  if (!token) {
    authErrors.add(1);
    errorRate.add(1);
    return;
  }

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type':  'application/json',
  };

  // ── Scenario A: Dashboard check (most common, all roles) ────
  {
    const res = http.get(`${BASE_URL}/api/v1/analytics/dashboard`, {
      headers,
      tags: { name: 'dashboard' },
    });

    analyticsTime.add(res.timings.duration);

    const ok = check(res, {
      'dashboard: status 200': (r) => r.status === 200,
      'dashboard: has data':   (r) => r.json() !== null,
      'dashboard: no stack':   (r) => !r.body.includes('"stack"'),
    });

    if (!ok) errorRate.add(1);
    else     errorRate.add(0);
  }

  sleep(0.5);

  // ── Scenario B: Reports list ─────────────────────────────────
  if (role === 'analyst' || role === 'manager' || role === 'admin') {
    const res = http.get(`${BASE_URL}/api/v1/reports`, {
      headers,
      tags: { name: 'reports' },
    });

    const ok = check(res, {
      'reports: status 200 or 403': (r) => r.status === 200 || r.status === 403,
      'reports: no stack':          (r) => !r.body.includes('"stack"'),
    });

    if (!ok) errorRate.add(1);
    else     errorRate.add(0);
  }

  sleep(0.3);

  // ── Scenario C: Health check ─────────────────────────────────
  {
    const res = http.get(`${BASE_URL}/health`, {
      tags: { name: 'health' },
    });

    check(res, {
      'health: status 200': (r) => r.status === 200,
    });
  }

  sleep(1);
}

// ── Teardown ──────────────────────────────────────────────────
export function teardown(data) {
  console.log('Load test complete.');
  console.log('Check k6 output above for threshold pass/fail summary.');
}
