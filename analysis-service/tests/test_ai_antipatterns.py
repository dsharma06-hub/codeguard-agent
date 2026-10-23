"""Unit tests for AI-generated code antipatterns analyzer."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.ai_antipatterns import (
    scan_source_for_antipatterns,
    detect_sensitive_routes,
    detect_hardcoded_production_endpoints,
    detect_rate_limiting_signals,
    is_private_or_local_host,
    is_well_known_third_party,
    is_test_or_mock_file,
)

client = TestClient(app)


# ==============================================================================
# Pattern 1 Tests: Missing Rate Limiting on Sensitive Endpoints
# ==============================================================================

def test_sensitive_route_login_flagged():
    code = """
    const express = require('express');
    const app = express();

    app.post('/login', (req, res) => {
        res.json({ status: 'ok' });
    });
    """
    findings, has_rate_limiting = scan_source_for_antipatterns(code, "routes/auth.js")
    assert has_rate_limiting is False
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MISSING_RATE_LIMITING"
    assert f.severity == "MEDIUM"
    assert f.category == "AI Antipattern"
    assert f.cwe_id == "CWE-307"
    assert "login" in f.title.lower()


def test_sensitive_route_nested_auth_paths_flagged():
    code = """
    import express from 'express';
    const router = express.Router();

    router.post('/api/v1/auth/signin', authController.signin);
    router.post('/users/register', userController.register);
    router.post('/auth/reset-password', resetController);
    """
    findings, has_rate_limiting = scan_source_for_antipatterns(code, "src/api/auth.ts")
    assert has_rate_limiting is False
    assert len(findings) == 3
    for f in findings:
        assert f.rule_id == "MISSING_RATE_LIMITING"
        assert f.severity == "MEDIUM"
        assert f.cwe_id == "CWE-307"


def test_sensitive_route_destructuring_password_flagged():
    code = """
    app.post('/api/session', (req, res) => {
        const { username, password } = req.body;
        authenticateUser(username, password);
    });
    """
    findings, _ = scan_source_for_antipatterns(code, "controllers/session.js")
    assert len(findings) == 1
    assert findings[0].rule_id == "MISSING_RATE_LIMITING"
    assert "password" in findings[0].description.lower()


def test_sensitive_route_suppressed_when_rate_limiting_imported():
    code = """
    const express = require('express');
    const rateLimit = require('express-rate-limit');
    const app = express();

    app.post('/login', (req, res) => {
        res.json({ token: 'abc' });
    });
    """
    findings, has_rate_limiting = scan_source_for_antipatterns(code, "server.js")
    assert has_rate_limiting is True
    assert len(findings) == 0


def test_sensitive_route_suppressed_when_limiter_middleware_used():
    code = """
    import express from 'express';
    const app = express();

    app.use(authLimiter);

    app.post('/signin', handleSignin);
    """
    findings, has_rate_limiting = scan_source_for_antipatterns(code, "app.ts")
    assert has_rate_limiting is True
    assert len(findings) == 0


def test_sensitive_route_suppressed_when_applied_on_route():
    code = """
    const router = require('express').Router();

    router.post('/login', loginLimiter, (req, res) => {
        res.send('ok');
    });
    """
    findings, _ = scan_source_for_antipatterns(code, "routes/login.js")
    assert len(findings) == 0


def test_non_sensitive_routes_not_flagged():
    code = """
    app.get('/items', (req, res) => res.json([]));
    app.post('/analytics/events', (req, res) => {
        const { eventName, timestamp } = req.body;
        res.status(200).send();
    });
    """
    findings, _ = scan_source_for_antipatterns(code, "routes/items.js")
    assert len(findings) == 0


def test_sensitive_routes_ignored_in_test_files():
    code = """
    app.post('/login', (req, res) => res.send('mock'));
    """
    findings, _ = scan_source_for_antipatterns(code, "tests/auth.test.ts")
    assert len(findings) == 0


# ==============================================================================
# Pattern 2 Tests: Hardcoded Production Endpoints
# ==============================================================================

def test_hardcoded_prod_url_in_fetch_flagged():
    code = """
    async function loadData() {
        const res = await fetch("https://api.mycompany.com/v1/users");
        return res.json();
    }
    """
    findings, _ = scan_source_for_antipatterns(code, "src/services/api.ts")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "HARDCODED_PRODUCTION_ENDPOINT"
    assert f.severity == "LOW"
    assert f.category == "AI Antipattern"
    assert f.cwe_id == "CWE-1188"
    assert "api.mycompany.com" in f.title


def test_hardcoded_prod_url_in_axios_methods_flagged():
    code = """
    import axios from 'axios';

    export const syncUser = (data) => axios.post('https://backend.prod.codeguard.io/users', data);
    """
    findings, _ = scan_source_for_antipatterns(code, "client.js")
    assert len(findings) == 1
    assert findings[0].rule_id == "HARDCODED_PRODUCTION_ENDPOINT"
    assert "backend.prod.codeguard.io" in findings[0].title


def test_hardcoded_prod_url_in_axios_object_config_flagged():
    code = """
    axios({
        method: 'get',
        url: 'https://staging.internal-api.org/status',
    });
    """
    findings, _ = scan_source_for_antipatterns(code, "network.ts")
    assert len(findings) == 1
    assert findings[0].rule_id == "HARDCODED_PRODUCTION_ENDPOINT"


def test_localhost_and_private_ips_not_flagged():
    code = """
    fetch("http://localhost:3000/api");
    fetch("http://127.0.0.1:8000/data");
    fetch("http://0.0.0.0:5000/health");
    fetch("http://192.168.1.15:4000/stream");
    fetch("http://10.0.0.1:9000/metrics");
    """
    findings, _ = scan_source_for_antipatterns(code, "dev.js")
    assert len(findings) == 0


def test_env_variable_urls_not_flagged():
    code = """
    fetch(process.env.API_BASE_URL + '/users');
    fetch(`${process.env.BACKEND_URL}/auth`);
    const url = getApiUrl();
    fetch(url);
    """
    findings, _ = scan_source_for_antipatterns(code, "safe.js")
    assert len(findings) == 0


def test_well_known_third_party_apis_not_flagged():
    code = """
    fetch("https://api.github.com/repos/expressjs/cors");
    fetch("https://api.stripe.com/v1/charges");
    fetch("https://maps.googleapis.com/maps/api/geocode/json");
    fetch("https://discord.com/api/webhooks/123");
    fetch("http://www.w3.org/2000/svg");
    """
    findings, _ = scan_source_for_antipatterns(code, "third_party.ts")
    assert len(findings) == 0


def test_hardcoded_urls_ignored_in_test_files():
    code = """
    fetch("https://api.mycompany.com/test-endpoint");
    """
    findings, _ = scan_source_for_antipatterns(code, "test/api.spec.js")
    assert len(findings) == 0


# ==============================================================================
# Endpoint Integration Tests
# ==============================================================================

def test_analyze_antipatterns_endpoint():
    res = client.post(
        "/analyze/antipatterns",
        json={
            "filename": "server.js",
            "content": "app.post('/register', handleRegister);\nfetch('https://api.mycorp.com/users');"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["findings_count"] == 2
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "MISSING_RATE_LIMITING" in rule_ids
    assert "HARDCODED_PRODUCTION_ENDPOINT" in rule_ids
    assert data["has_rate_limiting"] is False


def test_analyze_general_endpoint_includes_antipatterns():
    res = client.post(
        "/analyze",
        json={
            "filename": "server.ts",
            "content": "app.post('/login', (req, res) => res.send('ok'));"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["findings_count"] == 1
    assert data["findings"][0]["rule_id"] == "MISSING_RATE_LIMITING"
    assert data["has_rate_limiting"] is False
