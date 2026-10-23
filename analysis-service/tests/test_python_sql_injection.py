"""Tests for Python SQL Injection AST analyzer and API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.python_sql_injection import scan_python_source_for_sql_injection
from app.analyzers.sql_injection import scan_source_for_sql_injection

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_FIXTURE_PATH = FIXTURES_DIR / "python_sql_injection_vulnerable.py"
CLEAN_FIXTURE_PATH = FIXTURES_DIR / "python_sql_injection_clean.py"

client = TestClient(app)


@pytest.fixture(scope="module")
def vuln_findings():
    with open(VULN_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_sql_injection(code, file_path="vulnerable.py")


@pytest.fixture(scope="module")
def clean_findings():
    with open(CLEAN_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_sql_injection(code, file_path="clean.py")


class TestPythonSqlInjectionTruePositives:
    """Verifies accurate detection of genuine Python SQL injection patterns."""

    def test_total_findings_count(self, vuln_findings):
        # 15 distinct cases: 14 CRITICAL, 1 MEDIUM (sanitizer)
        assert len(vuln_findings) == 15

    def test_case1_dbapi_fstring(self, vuln_findings):
        f = next((item for item in vuln_findings if "cursor.execute(f\"SELECT * FROM users" in item.code_snippet), None)
        assert f is not None, "Case 1 (dbapi f-string) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SQL_INJECTION"
        assert f.cwe_id == "CWE-89"
        assert f.sink_expression == "cursor.execute"
        assert "request.args.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case2_dbapi_concat(self, vuln_findings):
        f = next((item for item in vuln_findings if "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)" in item.code_snippet), None)
        assert f is not None, "Case 2 (dbapi concat) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "cursor.execute"
        assert "request.args.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case3_multihop_reassignment(self, vuln_findings):
        f = next((item for item in vuln_findings if "cursor.execute(query_str)" in item.code_snippet), None)
        assert f is not None, "Case 3 (multi-hop reassignment) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "cursor.execute"
        assert "request.form.get" in f.source_expression
        assert f.source_line is not None
        assert f.sink_line is not None
        assert f.sink_line > f.source_line

    def test_case4_django_raw_fstring(self, vuln_findings):
        f = next((item for item in vuln_findings if "CustomUser.objects.raw(f\"SELECT * FROM users" in item.code_snippet), None)
        assert f is not None, "Case 4 (django raw f-string) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "CustomUser.objects.raw"
        assert "request.args.get" in f.source_expression

    def test_case5_django_extra_where(self, vuln_findings):
        f = next((item for item in vuln_findings if "CustomUser.objects.extra(where=[f\"role = '{role}'\"])" in item.code_snippet), None)
        assert f is not None, "Case 5 (django extra where) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "CustomUser.objects.extra"

    def test_case6_django_extra_with_params_always_flagged(self, vuln_findings):
        f = next((item for item in vuln_findings if "params=[\"safe_default\"]" in item.code_snippet), None)
        assert f is not None, "Case 6 (django extra with params must still flag) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "CustomUser.objects.extra"

    def test_case7_django_extra_select(self, vuln_findings):
        f = next((item for item in vuln_findings if "select={\"computed\":" in item.code_snippet), None)
        assert f is not None, "Case 7 (django extra select) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "CustomUser.objects.extra"

    def test_case8_django_rawsql(self, vuln_findings):
        f = next((item for item in vuln_findings if "RawSQL(f\"SELECT * FROM orders" in item.code_snippet), None)
        assert f is not None, "Case 8 (RawSQL f-string) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "RawSQL"

    def test_case9_sqlalchemy_text_fstring(self, vuln_findings):
        f = next((item for item in vuln_findings if "session.execute(text(f\"SELECT * FROM accounts" in item.code_snippet), None)
        assert f is not None, "Case 9 (SQLAlchemy text f-string) not found"
        assert f.severity == "CRITICAL"
        assert f.sink_expression == "session.execute"

    def test_case10_format_call(self, vuln_findings):
        f = next((item for item in vuln_findings if ".format(user_id)" in item.code_snippet), None)
        assert f is not None, "Case 10 (.format() call) not found"
        assert f.severity == "CRITICAL"

    def test_case11_percent_format(self, vuln_findings):
        f = next((item for item in vuln_findings if "% user_id" in item.code_snippet), None)
        assert f is not None, "Case 11 (%-formatting) not found"
        assert f.severity == "CRITICAL"

    def test_case12_sanitizer_downgrade(self, vuln_findings):
        f = next((item for item in vuln_findings if "{clean_id}" in item.code_snippet), None)
        assert f is not None, "Case 12 (sanitizer) not found"
        assert f.severity == "MEDIUM"
        assert f.is_sanitized is True
        assert f.sanitizer_name == "escape"
        assert "Sanitizer Detected" in f.title

    def test_case13_fastapi_route(self, vuln_findings):
        f = next((item for item in vuln_findings if "{item_id}" in item.code_snippet), None)
        assert f is not None, "Case 13 (FastAPI route param) not found"
        assert f.severity == "CRITICAL"
        assert "FastAPI param 'item_id'" in f.source_expression

    def test_case14_input_call(self, vuln_findings):
        f = next((item for item in vuln_findings if "{name}" in item.code_snippet), None)
        assert f is not None, "Case 14 (input() call) not found"
        assert f.severity == "CRITICAL"
        assert f.source_expression == "input()"

    def test_case15_sys_argv(self, vuln_findings):
        f = next((item for item in vuln_findings if "cli_arg" in item.code_snippet), None)
        assert f is not None, "Case 15 (sys.argv) not found"
        assert f.severity == "CRITICAL"
        assert "sys.argv[1]" in f.source_expression


class TestPythonSqlInjectionFalsePositives:
    """Verifies that safe, parameterized, and ORM query patterns produce 0 findings."""

    def test_clean_fixture_zero_findings(self, clean_findings):
        assert len(clean_findings) == 0, f"Expected 0 findings in clean fixture, got {len(clean_findings)}: {[f.code_snippet for f in clean_findings]}"


class TestPythonSqlInjectionEndpoints:
    """Tests POST /analyze/sql-injection and POST /analyze with Python code."""

    def test_analyze_sql_injection_endpoint_with_python(self):
        code = '''
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        res = client.post("/analyze/sql-injection", json={
            "content": code,
            "filename": "views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["category"] == "Injection Risk"
        assert finding["severity"] == "CRITICAL"
        assert finding["cwe_id"] == "CWE-89"

    def test_analyze_general_endpoint_with_python_sqli(self):
        code = '''
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        res = client.post("/analyze", json={
            "content": code,
            "filename": "handlers.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["category"] == "Injection Risk"
        assert finding["severity"] == "CRITICAL"

    def test_analyze_general_endpoint_with_safe_python(self):
        code = '''
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        res = client.post("/analyze", json={
            "content": code,
            "filename": "safe_views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 0
