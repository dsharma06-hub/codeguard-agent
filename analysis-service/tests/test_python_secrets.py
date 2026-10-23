"""Unit and API integration tests for Python Hardcoded Secret detection."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.secrets import scan_source_for_secrets
from app.analyzers.sql_injection import scan_source_for_sql_injection
from app.analyzers.xss import scan_source_for_xss

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_PYTHON_PATH = FIXTURES_DIR / "python_clean_code.py"
SECRETS_PYTHON_PATH = FIXTURES_DIR / "python_secrets_cases.py"

client = TestClient(app)


class TestPythonFalsePositives:
    """Verifies that safe Python patterns and conventions do NOT trigger secret leak findings."""

    def test_clean_python_fixture_has_zero_findings(self):
        with open(CLEAN_PYTHON_PATH, "r", encoding="utf-8") as f:
            code = f.read()
        findings = scan_source_for_secrets(code, file_path="clean.py")
        assert len(findings) == 0, f"Expected 0 findings in clean Python code, got: {[f.title for f in findings]}"

    def test_os_environ_subscript_is_not_flagged(self):
        code = 'SECRET_KEY = os.environ["DJANGO_SECRET_KEY_PRODUCTION_98765"]'
        findings = scan_source_for_secrets(code, file_path="settings.py")
        assert len(findings) == 0

    def test_os_environ_get_is_not_flagged(self):
        code = 'API_KEY = os.environ.get("STRIPE_LIVE_SECRET_KEY_12345")'
        findings = scan_source_for_secrets(code, file_path="config.py")
        assert len(findings) == 0

    def test_os_getenv_is_not_flagged(self):
        code = 'DB_PASSWORD = os.getenv("DATABASE_ROOT_PASSWORD_98765")'
        findings = scan_source_for_secrets(code, file_path="db.py")
        assert len(findings) == 0

    def test_dummy_and_placeholder_values_not_flagged(self):
        code = """
SECRET_KEY = "your-secret-key-here"
DEFAULT_PASSWORD = "changeme"
TEMP_KEY = "TODO"
SAMPLE_API_KEY = "your_api_key_here"
TEST_VALUE = "placeholder"
"""
        findings = scan_source_for_secrets(code, file_path="settings.py")
        assert len(findings) == 0

    def test_cors_header_regression_in_python_dict(self):
        code = """
headers = {
    "key": "Access-Control-Allow-Origin",
    "value": "*"
}
"""
        findings = scan_source_for_secrets(code, file_path="server.py")
        assert len(findings) == 0

    def test_docstrings_with_tokens_are_not_flagged(self):
        code = '''
"""
Module docstring: Example AWS key AKIAIOSFODNN7EXAMPLE or sk_live_1234567890abcdefghijklmn12.
"""

class CloudClient:
    """Class docstring with ghp_1234567890abcdefghijklmnopqrstuvwxyzAB."""
    
    def connect(self):
        """Method docstring with sk_live_1234567890abcdefghijklmn12."""
        return True
'''
        findings = scan_source_for_secrets(code, file_path="client.py")
        assert len(findings) == 0

    def test_comments_with_tokens_are_not_flagged(self):
        code = """
# AWS access key example: AKIAIOSFODNN7EXAMPLE
# Stripe test token: sk_live_1234567890abcdefghijklmn12
# GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB
x = 42
"""
        findings = scan_source_for_secrets(code, file_path="utils.py")
        assert len(findings) == 0


class TestPythonTruePositives:
    """Verifies that genuine secrets in various Python AST forms are detected."""

    def test_simple_assignment_aws_key(self):
        code = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_source_for_secrets(code, file_path="aws.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "AWS_ACCESS_KEY"
        assert findings[0].rule_id == "HARDCODED_SECRET"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].category == "Secret Leak"
        assert findings[0].line_number == 1

    def test_keyword_argument_password(self):
        code = 'connect_db(host="localhost", password="SuperSecretPassword123!")'
        findings = scan_source_for_secrets(code, file_path="db.py")
        assert len(findings) == 1
        assert "password" in findings[0].title.lower()
        assert findings[0].line_number == 1

    def test_dict_entry_api_key(self):
        code = '''
CONFIG = {
    "api_key": "sk_live_1234567890abcdefghijklmn12",
}
'''
        findings = scan_source_for_secrets(code, file_path="config.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "STRIPE_API_KEY"

    def test_class_attributes_and_django_settings(self):
        code = '''
class Settings:
    SECRET_KEY = "django-insecure-8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    STRIPE_KEY = "sk_live_1234567890abcdefghijklmn12"
'''
        findings = scan_source_for_secrets(code, file_path="settings.py")
        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert any("SECRET_KEY" in t for t in titles)
        assert any("Stripe" in t for t in titles)

    def test_compound_high_entropy_identifiers(self):
        code = '''
client_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
db_password = "SuperSecretDbPassword987!"
webhook_signing_key = "whsec_abcdef1234567890abcdef123456"
'''
        findings = scan_source_for_secrets(code, file_path="auth.py")
        assert len(findings) == 3
        vars_found = [f.title for f in findings]
        assert any("client_secret" in v for v in vars_found)
        assert any("db_password" in v for v in vars_found)
        assert any("webhook_signing_key" in v for v in vars_found)

    def test_fstring_with_secret_signature(self):
        code = 'AUTH_HEADER = f"Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"'
        findings = scan_source_for_secrets(code, file_path="api.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "GITHUB_TOKEN"

    def test_format_call_with_secret_signature(self):
        code = 'AUTH_HEADER = "Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyzAB".format()'
        findings = scan_source_for_secrets(code, file_path="api.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "GITHUB_TOKEN"

    def test_private_key_pem_multiline_string(self):
        code = '''
KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y9X7M4eKqP...
-----END RSA PRIVATE KEY-----"""
'''
        findings = scan_source_for_secrets(code, file_path="keys.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "PRIVATE_KEY"

    def test_jwt_token_detection(self):
        code = 'TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        findings = scan_source_for_secrets(code, file_path="auth.py")
        assert len(findings) == 1
        assert findings[0].secret_type == "JWT_TOKEN"

    def test_full_python_secrets_fixture(self):
        with open(SECRETS_PYTHON_PATH, "r", encoding="utf-8") as f:
            code = f.read()
        findings = scan_source_for_secrets(code, file_path="secrets.py")
        assert len(findings) >= 10, f"Expected at least 10 findings, got {len(findings)}"
        
        # Verify secret masking on every single finding
        for f in findings:
            assert f.rule_id == "HARDCODED_SECRET"
            assert f.severity == "CRITICAL"
            assert f.category == "Secret Leak"
            assert "*" in f.redacted_value
            assert "*" in f.code_snippet
            assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_value
            assert "AKIAIOSFODNN7EXAMPLE" not in f.code_snippet


class TestPythonApiRouting:
    """Verifies that API endpoints correctly process Python files."""

    def test_post_analyze_general_with_python_file(self):
        payload = {
            "filename": "app.py",
            "content": 'STRIPE_KEY = "sk_live_1234567890abcdefghijklmn12"'
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["secret_type"] == "STRIPE_API_KEY"
        assert data["findings"][0]["redacted_value"].startswith("sk_l")
        assert "1234567890abcdefghijkl" not in data["findings"][0]["redacted_value"]

    def test_post_analyze_secrets_with_python_file(self):
        payload = {
            "filename": "config.py",
            "content": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"'
        }
        res = client.post("/analyze/secrets", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["secret_type"] == "AWS_ACCESS_KEY"

    def test_sqli_analyzer_safely_skips_python(self):
        findings = scan_source_for_sql_injection("query = 'SELECT * FROM users'", file_path="models.py")
        assert findings == []

    def test_xss_analyzer_safely_skips_python(self):
        findings = scan_source_for_xss("html = '<div>' + user_input", file_path="views.py")
        assert findings == []
