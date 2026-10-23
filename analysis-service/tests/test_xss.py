"""Tests for Tree-sitter Cross-Site Scripting (XSS) detector and API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.xss import scan_source_for_xss

FIXTURES_DIR = Path(__file__).parent / "fixtures"
XSS_FIXTURE_PATH = FIXTURES_DIR / "xss_cases.ts"
CLEAN_CODE_PATH = FIXTURES_DIR / "clean_code.ts"

client = TestClient(app)


@pytest.fixture(scope="module")
def fixture_findings():
    with open(XSS_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_xss(code, file_path="xss_cases.ts")


class TestXssTruePositives:
    """Tests verifying accurate detection of genuine XSS patterns and dangerous sinks."""

    def test_total_findings_count(self, fixture_findings):
        # 9 Critical unsanitized + 2 Medium with sanitizers = 11 findings total
        assert len(fixture_findings) == 11

    def test_case1_dom_innerhtml_direct(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 17), None)
        assert f is not None, "Case 1 (line 17) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_DOM"
        assert f.cwe_id == "CWE-79"
        assert "req.query.content" in f.source_expression
        assert f.sink_expression == "element.innerHTML"
        assert f.is_sanitized is False

    def test_case2_multi_hop_reassigned_taint(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 28), None)
        assert f is not None, "Case 2 (line 28) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_DOM"
        assert "req.params.id" in f.source_expression
        assert f.source_line == 25  # Line where rawId = req.params.id
        assert f.sink_expression == "element.outerHTML"
        assert f.is_sanitized is False

    def test_case3_browser_location_search_params(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 38), None)
        assert f is not None, "Case 3 (line 38) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_DOM"
        assert "window.location.search" in f.source_expression
        assert f.sink_expression == "element.innerHTML"
        assert f.is_sanitized is False

    def test_case4_react_dangerously_set_inner_html(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 48), None)
        assert f is not None, "Case 4 (line 48) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_REACT"
        assert "req.body.markup" in f.source_expression
        assert f.sink_expression == "dangerouslySetInnerHTML"
        assert f.is_sanitized is False

    def test_case5_reflected_xss_res_send(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 58), None)
        assert f is not None, "Case 5 (line 58) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_REFLECTED"
        assert "req.query.name" in f.source_expression
        assert f.sink_expression == "res.send"
        assert f.is_sanitized is False

    def test_case6_document_write_and_adjacent_html(self, fixture_findings):
        f_write = next((item for item in fixture_findings if item.line_number == 66), None)
        assert f_write is not None, "Case 6 document.write (line 66) not found"
        assert f_write.severity == "CRITICAL"
        assert f_write.rule_id == "XSS_DOM"
        assert "req.query.scriptUrl" in f_write.source_expression

        f_adj = next((item for item in fixture_findings if item.line_number == 67), None)
        assert f_adj is not None, "Case 6 insertAdjacentHTML (line 67) not found"
        assert f_adj.severity == "CRITICAL"
        assert f_adj.rule_id == "XSS_DOM"
        assert "req.body.snippet" in f_adj.source_expression

    def test_case7_eval_and_function_code_injection(self, fixture_findings):
        f_eval = next((item for item in fixture_findings if item.line_number == 76), None)
        assert f_eval is not None, "Case 7 eval (line 76) not found"
        assert f_eval.severity == "CRITICAL"
        assert f_eval.rule_id == "CODE_INJECTION_EVAL"
        assert "req.query.calc" in f_eval.source_expression

        f_func = next((item for item in fixture_findings if item.line_number == 77), None)
        assert f_func is not None, "Case 7 Function (line 77) not found"
        assert f_func.severity == "CRITICAL"
        assert f_func.rule_id == "CODE_INJECTION_EVAL"
        assert "req.body.code" in f_func.source_expression

    def test_case8_dompurify_sanitizer_detected(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 86), None)
        assert f is not None, "Case 8 (line 86) not found"
        assert f.severity == "MEDIUM"
        assert f.is_sanitized is True
        assert "DOMPurify.sanitize" in (f.sanitizer_name or "")
        assert "Sanitizer Detected" in f.title

    def test_case9_escape_html_sanitizer_detected(self, fixture_findings):
        f = next((item for item in fixture_findings if item.line_number == 95), None)
        assert f is not None, "Case 9 (line 95) not found"
        assert f.severity == "MEDIUM"
        assert f.is_sanitized is True
        assert "escapeHtml" in (f.sanitizer_name or "")


class TestXssFalsePositiveResistance:
    """Tests verifying safe developer code patterns are NOT flagged as XSS."""

    def test_clean_production_code_has_zero_xss_findings(self):
        with open(CLEAN_CODE_PATH, "r", encoding="utf-8") as f:
            code = f.read()
        findings = scan_source_for_xss(code, file_path="clean_code.ts")
        assert len(findings) == 0, f"Expected 0 findings in clean code, got: {[f.title for f in findings]}"

    def test_react_default_jsx_auto_escaping_is_safe(self):
        code = """
        function UserProfile(props) {
            return (
                <div>
                    <h1>Hello {props.name}</h1>
                    <p>{req.query.bio}</p>
                </div>
            );
        }
        """
        findings = scan_source_for_xss(code, file_path="UserProfile.tsx")
        assert len(findings) == 0, f"React auto-escaped JSX text flagged: {findings}"

    def test_hardcoded_static_html_is_safe(self):
        code = """
        element.innerHTML = "<p class='static'>Safe content</p>";
        element.outerHTML = "<div id='app'>Static Container</div>";
        res.send("<h1>Static Hello World</h1>");
        document.write("<!-- Static safe comment -->");
        """
        findings = scan_source_for_xss(code, file_path="static.js")
        assert len(findings) == 0

    def test_safe_json_response_is_safe(self):
        code = """
        app.get('/api/data', (req, res) => {
            return res.json({
                user: req.query.username,
                id: req.params.id
            });
        });
        """
        findings = scan_source_for_xss(code, file_path="api.ts")
        assert len(findings) == 0


class TestXssApiEndpoints:
    """Tests for the HTTP analysis endpoints for XSS."""

    def test_post_analyze_xss_with_content(self):
        payload = {
            "filename": "component.tsx",
            "content": 'element.innerHTML = req.query.userInput;'
        }
        res = client.post("/analyze/xss", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "completed"
        assert data["findings_count"] == 1
        assert data["findings"][0]["rule_id"] == "XSS_DOM"
        assert data["findings"][0]["cwe_id"] == "CWE-79"
        assert data["findings"][0]["category"] == "Cross-Site Scripting"

    def test_post_analyze_general_includes_xss(self):
        payload = {
            "filename": "view.ts",
            "content": 'res.send("<div>" + req.query.name + "</div>");'
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["rule_id"] == "XSS_REFLECTED"
        assert data["findings"][0]["category"] == "Cross-Site Scripting"
