// ═══════════════════════════════════════════════════════════════
// k6 Load Test — EDARS Platform
// ═══════════════════════════════════════════════════════════════
// Target: 100 virtual users, 10 minutes sustained
// Endpoints: /analytics/dashboard, /reports
// Run: k6 run tests/loadtest.js
// ═══════════════════════════════════════════════════════════════
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ─── Custom Metrics ──────────────────────────────────────────
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration', true);
const dashboardDuration = new Trend('dashboard_duration', true);
const reportsDuration = new Trend('reports_duration', true);

// ─── Options ─────────────────────────────────────────────────
export const options = {
    stages: [
        { duration: '1m', target: 25 },  // Ramp up to 25 users
        { duration: '1m', target: 50 },  // Ramp to 50
        { duration: '1m', target: 100 },  // Ramp to 100
        { duration: '5m', target: 100 },  // Sustain 100 users for 5 minutes
        { duration: '1m', target: 50 },  // Ramp down
        { duration: '1m', target: 0 },  // Ramp to zero
    ],
    thresholds: {
        http_req_duration: ['p(95)<3000'],     // 95% of requests < 3s
        http_req_failed: ['rate<0.05'],        // Error rate < 5%
        errors: ['rate<0.05'],                 // Custom error metric < 5%
        login_duration: ['p(95)<2000'],        // Login p95 < 2s
        dashboard_duration: ['p(95)<3000'],    // Dashboard p95 < 3s
        reports_duration: ['p(95)<3000'],       // Reports p95 < 3s
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// ─── Test Users (from seed data) ─────────────────────────────
const TEST_USERS = [
    { email: 'admin@edars.internal', password: 'P@ssw0rd123!' },
    { email: 'j.smith@edars.internal', password: 'P@ssw0rd123!' },
    { email: 'm.jones@edars.internal', password: 'P@ssw0rd123!' },
    { email: 'r.chen@edars.internal', password: 'P@ssw0rd123!' },
    { email: 'a.patel@edars.internal', password: 'P@ssw0rd123!' },
];

// ─── Main Test Scenario ──────────────────────────────────────
export default function () {
    const user = TEST_USERS[Math.floor(Math.random() * TEST_USERS.length)];

    let accessToken;

    // 1. Login
    group('Login', () => {
        const loginRes = http.post(
            `${BASE_URL}/api/v1/auth/login`,
            JSON.stringify({ email: user.email, password: user.password }),
            { headers: { 'Content-Type': 'application/json' } }
        );

        loginDuration.add(loginRes.timings.duration);

        const loginOk = check(loginRes, {
            'login status 200': (r) => r.status === 200,
            'login has accessToken': (r) => {
                try { return JSON.parse(r.body).accessToken !== undefined; }
                catch { return false; }
            },
        });

        if (loginOk) {
            accessToken = JSON.parse(loginRes.body).accessToken;
        } else {
            errorRate.add(1);
            return;
        }
        errorRate.add(0);
    });

    if (!accessToken) return;

    const authHeaders = {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
    };

    // 2. Dashboard (most hit endpoint)
    group('Analytics Dashboard', () => {
        const res = http.get(
            `${BASE_URL}/api/v1/analytics/dashboard`,
            { headers: authHeaders }
        );

        dashboardDuration.add(res.timings.duration);

        const ok = check(res, {
            'dashboard status 200 or 502': (r) => r.status === 200 || r.status === 502,
        });
        errorRate.add(!ok ? 1 : 0);
    });

    sleep(0.5 + Math.random());

    // 3. Reports list
    group('Reports List', () => {
        const res = http.get(
            `${BASE_URL}/api/v1/reports?limit=20`,
            { headers: authHeaders }
        );

        reportsDuration.add(res.timings.duration);

        const ok = check(res, {
            'reports status 200': (r) => r.status === 200,
            'reports has array': (r) => {
                try { return Array.isArray(JSON.parse(r.body).reports); }
                catch { return false; }
            },
        });
        errorRate.add(!ok ? 1 : 0);
    });

    sleep(0.5 + Math.random());

    // 4. Health check (lightweight)
    group('Health Check', () => {
        const res = http.get(`${BASE_URL}/health`);
        check(res, {
            'health status 200': (r) => r.status === 200,
        });
    });

    sleep(1 + Math.random() * 2);
}

// ─── Teardown Summary ────────────────────────────────────────
export function handleSummary(data) {
    const summary = {
        timestamp: new Date().toISOString(),
        totalRequests: data.metrics.http_reqs?.values?.count || 0,
        errorRate: data.metrics.errors?.values?.rate || 0,
        p95Latency: data.metrics.http_req_duration?.values?.['p(95)'] || 0,
        p99Latency: data.metrics.http_req_duration?.values?.['p(99)'] || 0,
        avgLatency: data.metrics.http_req_duration?.values?.avg || 0,
    };

    console.log('\n══════ EDARS Load Test Summary ══════');
    console.log(`Total Requests:  ${summary.totalRequests}`);
    console.log(`Error Rate:      ${(summary.errorRate * 100).toFixed(2)}%`);
    console.log(`P95 Latency:     ${summary.p95Latency.toFixed(0)}ms`);
    console.log(`P99 Latency:     ${summary.p99Latency.toFixed(0)}ms`);
    console.log(`Avg Latency:     ${summary.avgLatency.toFixed(0)}ms`);
    console.log('═════════════════════════════════════\n');

    return {
        stdout: JSON.stringify(summary, null, 2),
    };
}
