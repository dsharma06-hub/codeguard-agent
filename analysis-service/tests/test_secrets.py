"""Tests for Tree-sitter hardcoded secrets detector and analysis API."""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.secrets import (
    scan_source_for_secrets,
    redact_secret,
    calculate_shannon_entropy,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_CODE_PATH = FIXTURES_DIR / "sample_code.ts"
CLEAN_CODE_PATH = FIXTURES_DIR / "clean_code.ts"

client = TestClient(app)


class TestRedaction:
    """Tests verifying secret masking behavior."""

    def test_redact_standard_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"  # 20 chars
        redacted = redact_secret(secret)
        assert redacted.startswith("AKIA")
        assert redacted.endswith("MPLE")
        assert "*" * (len(secret) - 8) in redacted
        assert "IOSFODNN7EXA" not in redacted

    def test_redact_short_secret(self):
        secret = "1234"
        assert redact_secret(secret) == "****"

    def test_redact_medium_secret(self):
        secret = "12345678"
        redacted = redact_secret(secret)
        assert "3456" not in redacted
        assert "*" in redacted


class TestFalsePositiveResistance:
    """Tests ensuring safe developer code patterns are NOT flagged."""

    def test_clean_production_code_has_zero_findings(self):
        with open(CLEAN_CODE_PATH, "r", encoding="utf-8") as f:
            code = f.read()
        findings = scan_source_for_secrets(code, file_path="clean_code.ts")
        assert len(findings) == 0, f"Expected 0 findings in clean code, got: {[f.title for f in findings]}"

    def test_safe_api_url_is_ignored(self):
        code = 'const API_URL = "https://api.stripe.com/v1";'
        findings = scan_source_for_secrets(code, file_path="config.ts")
        assert len(findings) == 0

    def test_safe_endpoint_path_is_ignored(self):
        code = 'const AUTH_ENDPOINT = "/api/v1/oauth/callback";'
        findings = scan_source_for_secrets(code, file_path="routes.ts")
        assert len(findings) == 0

    def test_safe_token_type_is_ignored(self):
        code = 'const TOKEN_TYPE = "Bearer";'
        findings = scan_source_for_secrets(code, file_path="auth.ts")
        assert len(findings) == 0

    def test_dummy_placeholder_is_ignored(self):
        code = 'const API_KEY = "YOUR_API_KEY_HERE";'
        findings = scan_source_for_secrets(code, file_path="example.ts")
        assert len(findings) == 0

    def test_cors_headers_with_bare_key_are_ignored(self):
        code = """
        headers.push([{
            key: 'Access-Control-Allow-Origin',
            value: '*'
        }, {
            key: 'Access-Control-Allow-Methods',
            value: 'GET,HEAD,PUT,PATCH,POST,DELETE'
        }, {
            key: 'Access-Control-Allow-Headers',
            value: 'Content-Type,Authorization'
        }]);
        """
        findings = scan_source_for_secrets(code, file_path="cors.js")
        assert len(findings) == 0

    def test_non_credential_key_names_are_ignored(self):
        code = """
        const obj = {
            key: "some_regular_cache_key_string",
            keys: "primary_and_foreign_keys",
            cacheKey: "user-session-cache-key-xyz",
            primaryKey: "record-identifier-uuid-value",
            keyboard: "standard-104-keyboard-layout",
            keyword: "SELECT_ALL_FROM_TABLE"
        };
        """
        findings = scan_source_for_secrets(code, file_path="keys.ts")
        assert len(findings) == 0

    def test_value_shape_rejects_headers_mimetypes_and_enums(self):
        code = """
        const apiKey = "Access-Control-Allow-Origin";
        const secretToken = "application/json; charset=utf-8";
        const clientSecret = "production";
        const authCredential = "Strict-Transport-Security";
        const accessKey = "Content-Security-Policy-Report-Only";
        """
        findings = scan_source_for_secrets(code, file_path="config.ts")
        assert len(findings) == 0

    def test_genuine_compound_key_with_high_entropy_secret_is_detected(self):
        code = 'const clientSecret = "9f8b2c4e1a7d6e3f5b0c9a8d7e6f5a4b";'
        findings = scan_source_for_secrets(code, file_path="client.js")
        assert len(findings) == 1
        assert findings[0].secret_type == "GENERIC_HIGH_ENTROPY_SECRET"


class TestSecretDetection:
    """Tests verifying accurate detection of real secrets."""

    def test_sample_code_catches_all_expected_secrets(self):
        with open(SAMPLE_CODE_PATH, "r", encoding="utf-8") as f:
            code = f.read()

        findings = scan_source_for_secrets(code, file_path="sample_code.ts")

        # Expecting exactly 6 secrets in sample_code.ts
        assert len(findings) == 6

        # Check types of caught secrets
        secret_types = [f.secret_type for f in findings]
        assert "AWS_ACCESS_KEY" in secret_types
        assert "STRIPE_API_KEY" in secret_types
        assert "GITHUB_TOKEN" in secret_types
        assert "JWT_TOKEN" in secret_types
        assert "GENERIC_HIGH_ENTROPY_SECRET" in secret_types

        # Verify line numbers match lines in sample_code.ts
        lines = [f.line_number for f in findings]
        assert 31 in lines  # AWS_ACCESS_KEY_ID
        assert 34 in lines  # STRIPE_SECRET_KEY
        assert 37 in lines  # GITHUB_TOKEN
        assert 40 in lines  # JWT_AUTH
        assert 43 in lines  # CLIENT_SECRET
        assert 48 in lines  # apiKey in paymentConfig

        # Verify findings schema and redactions
        for f in findings:
            assert f.rule_id == "HARDCODED_SECRET"
            assert f.severity == "CRITICAL"
            assert f.category == "Secret Leak"
            assert f.cwe_id == "CWE-798"
            assert "*" in f.redacted_value
            assert "*" in f.code_snippet
            assert f.remediation.startswith("Move sensitive credentials")

            # Crucial security assertion: NEVER return the raw unmasked secret!
            if f.secret_type == "AWS_ACCESS_KEY":
                assert "AKIAIOSFODNN7EXAMPLE" not in f.code_snippet
                assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_value
                assert "AKIA************MPLE" in f.redacted_value

    def test_detection_in_javascript_and_jsx(self):
        js_code = 'const clientSecret = "sk_live_1234567890abcdefghijklmn12";'
        findings = scan_source_for_secrets(js_code, file_path="service.js")
        assert len(findings) == 1
        assert findings[0].secret_type == "STRIPE_API_KEY"

        jsx_code = '<ApiClient apiKey="sk_live_1234567890abcdefghijklmn12" />'
        findings_jsx = scan_source_for_secrets(jsx_code, file_path="Widget.tsx")
        assert len(findings_jsx) == 1
        assert findings_jsx[0].secret_type == "STRIPE_API_KEY"


class TestAnalyzeApiRoutes:
    """Tests for the HTTP analysis endpoints."""

    def test_post_analyze_secrets_with_content(self):
        payload = {
            "filename": "auth.ts",
            "content": 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";'
        }
        res = client.post("/analyze/secrets", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "completed"
        assert data["findings_count"] == 1
        assert data["findings"][0]["rule_id"] == "HARDCODED_SECRET"
        assert data["findings"][0]["redacted_value"] == "AKIA************MPLE"
        assert data["duration_ms"] >= 0

    def test_post_analyze_secrets_with_file_path(self):
        payload = {
            "file_path": str(CLEAN_CODE_PATH)
        }
        res = client.post("/analyze/secrets", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 0

    def test_post_analyze_general_endpoint(self):
        payload = {
            "filename": "keys.ts",
            "content": 'const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";'
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["secret_type"] == "GITHUB_TOKEN"

    def test_post_analyze_missing_input_returns_400(self):
        res = client.post("/analyze/secrets", json={})
        assert res.status_code == 400

    def test_post_analyze_missing_file_returns_404(self):
        res = client.post("/analyze/secrets", json={"file_path": "non_existent_file.ts"})
        assert res.status_code == 404
