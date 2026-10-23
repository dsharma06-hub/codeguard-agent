"""Tests for Python XSS, SSTI, and Code Injection AST analyzer and API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.python_xss import scan_python_source_for_xss
from app.analyzers.xss import scan_source_for_xss

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_FIXTURE_PATH = FIXTURES_DIR / "python_xss_vulnerable.py"
CLEAN_FIXTURE_PATH = FIXTURES_DIR / "python_xss_clean.py"

client = TestClient(app)


@pytest.fixture(scope="module")
def vuln_findings():
    with open(VULN_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_xss(code, file_path="vulnerable.py")


@pytest.fixture(scope="module")
def clean_findings():
    with open(CLEAN_FIXTURE_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    return scan_source_for_xss(code, file_path="clean.py")


class TestPythonXssTruePositives:
    """Verifies accurate detection of SSTI, Markup/mark_safe autoescaping bypasses, and eval/exec injection."""

    def test_total_findings_count(self, vuln_findings):
        # 13 distinct cases: 11 CRITICAL, 2 MEDIUM (sanitizers)
        assert len(vuln_findings) == 13

    def test_case1_ssti_fstring(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(f\"<h1>Welcome {user}</h1>\")" in item.code_snippet), None)
        assert f is not None, "Case 1 (render_template_string f-string) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert f.cwe_id == "CWE-1336"
        assert f.category == "Cross-Site Scripting"
        assert f.sink_expression == "render_template_string"
        assert "request.args.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case2_ssti_concat(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(\"<h1>Hello \" + user + \"</h1>\")" in item.code_snippet), None)
        assert f is not None, "Case 2 (render_template_string concat) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert f.cwe_id == "CWE-1336"
        assert f.sink_expression == "render_template_string"
        assert "request.form.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case3_ssti_format(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(\"<div>User: {}\"\"</div>\".format(user))" in item.code_snippet or "render_template_string(\"<div>User: {}</div>\".format(user))" in item.code_snippet), None)
        assert f is not None, "Case 3 (render_template_string format) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert f.cwe_id == "CWE-1336"
        assert "request.values.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case4_ssti_percent(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(\"<b>Query: %s</b>\" % user)" in item.code_snippet), None)
        assert f is not None, "Case 4 (render_template_string %) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert f.cwe_id == "CWE-1336"
        assert "request.json.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case5_markup_raw(self, vuln_findings):
        f = next((item for item in vuln_findings if "Markup(user_comment)" in item.code_snippet), None)
        assert f is not None, "Case 5 (Markup raw) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_MARKUP_BYPASS"
        assert f.cwe_id == "CWE-79"
        assert f.category == "Cross-Site Scripting"
        assert "request.args.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case6_mark_safe_raw(self, vuln_findings):
        f = next((item for item in vuln_findings if "mark_safe(bio)" in item.code_snippet), None)
        assert f is not None, "Case 6 (mark_safe raw) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_MARK_SAFE"
        assert f.cwe_id == "CWE-79"
        assert f.category == "Cross-Site Scripting"
        assert "request.POST.get" in f.source_expression
        assert f.is_sanitized is False

    def test_case7_multihop_ssti(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(final_template)" in item.code_snippet), None)
        assert f is not None, "Case 7 (multi-hop SSTI) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert f.cwe_id == "CWE-1336"
        assert "request.args.get" in f.source_expression
        assert f.sink_line > f.source_line

    def test_case8_multihop_mark_safe(self, vuln_findings):
        f = next((item for item in vuln_findings if "mark_safe(validated)" in item.code_snippet), None)
        assert f is not None, "Case 8 (multi-hop mark_safe) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "XSS_MARK_SAFE"
        assert f.cwe_id == "CWE-79"
        assert "request.args.get" in f.source_expression

    def test_case9_eval_tainted(self, vuln_findings):
        f = next((item for item in vuln_findings if "eval(calc_expr)" in item.code_snippet), None)
        assert f is not None, "Case 9 (eval tainted) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "CODE_INJECTION_EVAL"
        assert f.cwe_id == "CWE-95"
        assert "request.args.get" in f.source_expression

    def test_case10_exec_tainted(self, vuln_findings):
        f = next((item for item in vuln_findings if "exec(script_code)" in item.code_snippet), None)
        assert f is not None, "Case 10 (exec tainted) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "CODE_INJECTION_EVAL"
        assert f.cwe_id == "CWE-95"
        assert "request.form.get" in f.source_expression

    def test_case11_fastapi_route(self, vuln_findings):
        f = next((item for item in vuln_findings if "render_template_string(f\"Item: {item_id}\")" in item.code_snippet), None)
        assert f is not None, "Case 11 (FastAPI route SSTI) not found"
        assert f.severity == "CRITICAL"
        assert f.rule_id == "SSTI_RENDER_TEMPLATE_STRING"
        assert "FastAPI param" in f.source_expression

    def test_case12_markup_sanitized(self, vuln_findings):
        f = next((item for item in vuln_findings if "Markup(clean)" in item.code_snippet), None)
        assert f is not None, "Case 12 (Markup sanitized) not found"
        assert f.severity == "MEDIUM"
        assert f.rule_id == "XSS_MARKUP_BYPASS"
        assert f.is_sanitized is True
        assert f.sanitizer_name == "escape"

    def test_case13_mark_safe_sanitized(self, vuln_findings):
        f = next((item for item in vuln_findings if "mark_safe(clean_html)" in item.code_snippet), None)
        assert f is not None, "Case 13 (mark_safe sanitized) not found"
        assert f.severity == "MEDIUM"
        assert f.rule_id == "XSS_MARK_SAFE"
        assert f.is_sanitized is True
        assert f.sanitizer_name == "bleach.clean"


class TestPythonXssFalsePositives:
    """Verifies that safe template patterns (especially render_template) produce zero false positives."""

    def test_zero_findings_in_clean_fixture(self, clean_findings):
        assert len(clean_findings) == 0, (
            f"Expected 0 findings in clean fixture, got {len(clean_findings)}: "
            f"{[f.title for f in clean_findings]}"
        )

    def test_render_template_file_zero_findings(self):
        code = """
from flask import render_template, request

def view():
    user = request.args.get('name')
    email = request.form.get('email')
    return render_template('profile.html', user=user, email=email)
"""
        findings = scan_source_for_xss(code, file_path="views.py")
        assert len(findings) == 0, f"render_template must produce 0 findings, got {len(findings)}"

    def test_render_template_string_context_kwargs_zero_findings(self):
        code = """
from flask import render_template_string, request

def view():
    user = request.args.get('name')
    return render_template_string('<h1>Hello {{ name }}</h1>', name=user)
"""
        findings = scan_source_for_xss(code, file_path="views.py")
        assert len(findings) == 0, (
            f"render_template_string with static template and context variable must produce 0 findings, "
            f"got {len(findings)}"
        )

    def test_markup_static_string_zero_findings(self):
        code = """
from markupsafe import Markup

m = Markup('<b>Static HTML</b>')
"""
        findings = scan_source_for_xss(code, file_path="views.py")
        assert len(findings) == 0

    def test_mark_safe_static_string_zero_findings(self):
        code = """
from django.utils.safestring import mark_safe

s = mark_safe('<p>Safe static message</p>')
"""
        findings = scan_source_for_xss(code, file_path="views.py")
        assert len(findings) == 0

    def test_eval_static_expression_zero_findings(self):
        code = """
val = eval('1 + 1')
"""
        findings = scan_source_for_xss(code, file_path="views.py")
        assert len(findings) == 0


class TestPythonXssEndpoints:
    """Verifies that API endpoints correctly route Python XSS/SSTI analysis."""

    def test_analyze_xss_endpoint_python(self):
        code = """
from flask import request, render_template_string

def index():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}</h1>')
"""
        res = client.post("/analyze/xss", json={
            "content": code,
            "filename": "app/views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["rule_id"] == "SSTI_RENDER_TEMPLATE_STRING"
        assert finding["cwe_id"] == "CWE-1336"
        assert finding["severity"] == "CRITICAL"
        assert finding["category"] == "Cross-Site Scripting"

    def test_analyze_general_endpoint_python_ssti(self):
        code = """
from flask import request, render_template_string

def index():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}</h1>')
"""
        res = client.post("/analyze", json={
            "content": code,
            "filename": "app/views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["rule_id"] == "SSTI_RENDER_TEMPLATE_STRING"

    def test_analyze_general_endpoint_python_markup(self):
        code = """
from flask import request
from markupsafe import Markup

def index():
    bio = request.form.get('bio')
    return Markup(bio)
"""
        res = client.post("/analyze", json={
            "content": code,
            "filename": "app/views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["rule_id"] == "XSS_MARKUP_BYPASS"
        assert finding["cwe_id"] == "CWE-79"

    def test_analyze_general_endpoint_clean_flask_zero_findings(self):
        code = """
from flask import request, render_template

def index():
    user = request.args.get('user')
    return render_template('home.html', current_user=user)
"""
        res = client.post("/analyze", json={
            "content": code,
            "filename": "app/views.py"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 0
