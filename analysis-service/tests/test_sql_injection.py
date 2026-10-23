"""Tests for Tree-sitter SQL Injection detector and API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.sql_injection import scan_source_for_sql_injection

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SQL_FIXTURE_PATH = FIXTURES_DIR / "sql_injection_cases.ts"
CLEAN_CODE_PATH = FIXTURES_DIR / "clean_code.ts"

client = TestClient(app)


@pytest.fixture(scope="module")
def fixture_findings():
    with open(SQL_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_sql_injection(code, file_path="sql_injection_cases.ts")


class TestSqlInjectionTruePositives:
    """Tests verifying accurate detection of genuine SQL injection patterns."""

    def test_total_findings_count(self, fixture_findings):
        # Exactly 5 true findings expected (4 critical, 1 medium with sanitizer)
        assert len(fixture_findings) == 5

    def test_case1_direct_template_literal(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 18), None)
        assert f is not None, "Case 1 (line 18) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SQL_INJECTION"
        assert f.cwe_id == "CWE-89"
        assert "req.query.name" in f.source_expression
        assert f.sink_expression == "db.query"
        assert f.is_sanitized is False

    def test_case2_string_concatenation(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 27), None)
        assert f is not None, "Case 2 (line 27) not found"
        assert f.severity == "CRITICAL"
        assert "req.query.category" in f.source_expression
        assert f.source_line == 27
        assert f.sink_line == 28
        assert f.sink_expression == "connection.execute"
        assert f.is_sanitized is False

    def test_case3_reassigned_tainted_variable(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 39), None)
        assert f is not None, "Case 3 (line 39) not found"
        assert f.severity == "CRITICAL"
        assert "req.params.id" in f.source_expression
        assert f.source_line == 37  # Line where orderId = req.params.id
        assert f.sink_line == 40    # Line where pool.query(sql) is called
        assert f.is_sanitized is False

    def test_case4_function_param_direct_interpolation(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 49), None)
        assert f is not None, "Case 4 (line 49) not found"
        assert f.severity == "CRITICAL"
        assert "userId" in f.source_expression
        assert f.source_line == 48

    def test_case5_sanitizer_detected_lowered_severity(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 58), None)
        assert f is not None, "Case 5 (line 58) not found"
        assert f.severity == "MEDIUM"
        assert f.is_sanitized is True
        assert f.sanitizer_name == "escape"
        assert "Sanitizer Detected" in f.title


class TestSqlInjectionFalsePositiveResistance:
    """Tests proving detector correctly ignores safe query patterns."""

    def test_clean_production_code_has_zero_findings(self):
        with open(CLEAN_CODE_PATH, "r", encoding="utf-8") as f:
            code = f.read()
        findings = scan_source_for_sql_injection(code, file_path="clean_code.ts")
        assert len(findings) == 0

    def test_parameterized_query_is_safe(self):
        code = """
        app.get('/user', async (req, res) => {
          const user = await db.query('SELECT * FROM users WHERE id = $1 AND role = ?', [req.query.id, req.body.role]);
          res.json(user);
        });
        """
        findings = scan_source_for_sql_injection(code, file_path="safe.ts")
        assert len(findings) == 0

    def test_safe_constant_concatenation_is_safe(self):
        code = """
        const DEFAULT_LIMIT = 50;
        const BASE_QUERY = "SELECT * FROM audit_logs WHERE status = 'FAILED'";
        const fullQuery = BASE_QUERY + " LIMIT " + DEFAULT_LIMIT;
        db.query(fullQuery);
        """
        findings = scan_source_for_sql_injection(code, file_path="concat.ts")
        assert len(findings) == 0

    def test_orm_methods_are_safe(self):
        code = """
        User.findOne({ where: { email: req.query.email } });
        Post.findAll({ where: { authorId: req.params.authorId } });
        prisma.user.findUnique({ where: { id: req.params.id } });
        """
        findings = scan_source_for_sql_injection(code, file_path="orm.ts")
        assert len(findings) == 0


class TestSqlInjectionApiRoutes:
    """Tests for the HTTP analysis endpoints."""

    def test_post_analyze_sql_injection_with_content(self):
        payload = {
            "filename": "vuln.ts",
            "content": "db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);"
        }
        res = client.post("/analyze/sql-injection", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "completed"
        assert data["findings_count"] == 1
        assert data["findings"][0]["rule_id"] == "SQL_INJECTION"
        assert data["findings"][0]["severity"] == "CRITICAL"
        assert data["findings"][0]["cwe_id"] == "CWE-89"

    def test_post_analyze_sql_injection_with_file_path(self):
        payload = {
            "file_path": str(SQL_FIXTURE_PATH)
        }
        res = client.post("/analyze/sql-injection", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 5

    def test_post_general_analyze_runs_both_detectors(self):
        # Code containing both a hardcoded secret AND a SQL injection
        combined_code = """
        const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
        db.query(`SELECT * FROM accounts WHERE id = ${req.query.id}`);
        """
        payload = {
            "filename": "multi.ts",
            "content": combined_code
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 2
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert "HARDCODED_SECRET" in rule_ids
        assert "SQL_INJECTION" in rule_ids
