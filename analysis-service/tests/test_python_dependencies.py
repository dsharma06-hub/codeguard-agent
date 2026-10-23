"""Tests for Python dependency vulnerability scanner (requirements.txt and pyproject.toml)."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.dependencies import (
    scan_requirements_txt_for_vulnerabilities,
    scan_pyproject_toml_for_vulnerabilities,
    scan_dependencies_for_vulnerabilities,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REQS_PATH = FIXTURES_DIR / "python_requirements_vulnerable.txt"
CLEAN_REQS_PATH = FIXTURES_DIR / "python_requirements_clean.txt"
DEV_REQS_PATH = FIXTURES_DIR / "python_requirements_dev.txt"
PYPROJECT_PATH = FIXTURES_DIR / "python_pyproject_vulnerable.toml"

client = TestClient(app)


class TestPythonRequirementsTxt:
    """Verifies vulnerability detection, range parsing, and unpinned checks in requirements.txt."""

    def test_vulnerable_requirements(self):
        with open(VULN_REQS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        findings = scan_requirements_txt_for_vulnerabilities(content, "requirements.txt")
        assert len(findings) == 4

        # 1. Django CVE-2022-34265 (CRITICAL)
        django_f = next((item for item in findings if item.package_name == "django"), None)
        assert django_f is not None
        assert django_f.cve_id == "CVE-2022-34265"
        assert django_f.severity == "CRITICAL"
        assert django_f.cwe_id == "CWE-89"
        assert django_f.fixed_version == "3.2.14"
        assert django_f.line_number == 2
        assert django_f.is_dev_dependency is False

        # 2. Requests CVE-2023-32681 (HIGH)
        requests_f = next((item for item in findings if item.package_name == "requests"), None)
        assert requests_f is not None
        assert requests_f.cve_id == "CVE-2023-32681"
        assert requests_f.severity == "HIGH"
        assert requests_f.cwe_id == "CWE-200"
        assert requests_f.fixed_version == "2.31.0"
        assert requests_f.line_number == 3

        # 3. Flask Unpinned (HIGH)
        flask_f = next((item for item in findings if item.package_name == "flask"), None)
        assert flask_f is not None
        assert flask_f.rule_id == "UNPINNED_DEPENDENCY"
        assert flask_f.severity == "HIGH"
        assert flask_f.cwe_id == "CWE-1104"
        assert flask_f.line_number == 4

        # 4. PyYAML CVE-2020-14343 (CRITICAL)
        pyyaml_f = next((item for item in findings if item.package_name == "pyyaml"), None)
        assert pyyaml_f is not None
        assert pyyaml_f.cve_id == "CVE-2020-14343"
        assert pyyaml_f.severity == "CRITICAL"
        assert pyyaml_f.cwe_id == "CWE-502"
        assert pyyaml_f.line_number == 5

    def test_clean_requirements_zero_findings(self):
        with open(CLEAN_REQS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        findings = scan_requirements_txt_for_vulnerabilities(content, "requirements.txt")
        assert len(findings) == 0, f"Expected 0 findings in clean requirements, got {len(findings)}: {[f.package_name for f in findings]}"

    def test_substring_package_defense(self):
        content = "django-cors-headers == 3.2.0\nfake-requests == 1.0.0\n"
        findings = scan_requirements_txt_for_vulnerabilities(content, "requirements.txt")
        assert len(findings) == 0, "Substring package names must not trigger false positives"

    def test_dev_requirements_severity_downgrade(self):
        with open(DEV_REQS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        findings = scan_requirements_txt_for_vulnerabilities(content, "requirements-dev.txt")
        assert len(findings) == 3

        for f in findings:
            assert f.is_dev_dependency is True

        # Requests in dev: HIGH -> MEDIUM
        req_f = next(item for item in findings if item.package_name == "requests")
        assert req_f.severity == "MEDIUM"

        # Pillow in dev: CRITICAL -> HIGH
        pillow_f = next(item for item in findings if item.package_name == "pillow")
        assert pillow_f.severity == "HIGH"

        # Pytest unpinned in dev: HIGH -> MEDIUM
        pytest_f = next(item for item in findings if item.package_name == "pytest")
        assert pytest_f.severity == "MEDIUM"

    def test_django_cve_2022_34265_multi_branch_coverage(self):
        """Django CVE-2022-34265 covers both 3.2 before 3.2.14 and 4.0 before 4.0.6.

        - 4.0.5 -> FLAGGED as vulnerable (fixed in 4.0.6)
        - 3.2.0 -> FLAGGED as vulnerable (fixed in 3.2.14)
        - 3.1.2 -> NOT flagged (3.1.x is unaffected)
        - 5.0.0 -> NOT flagged (5.0.x is unaffected)
        - 3.2.14 -> NOT flagged (patched version)
        - 4.0.6 -> NOT flagged (patched version)
        """
        # 1. Vulnerable 4.0.x specifically (e.g. 4.0.5)
        findings_40 = scan_requirements_txt_for_vulnerabilities("django == 4.0.5\n", "requirements.txt")
        assert len(findings_40) == 1
        assert findings_40[0].package_name == "django"
        assert findings_40[0].cve_id == "CVE-2022-34265"
        assert findings_40[0].fixed_version == "4.0.6"
        assert findings_40[0].severity == "CRITICAL"
        assert findings_40[0].cwe_id == "CWE-89"

        # 2. Vulnerable 3.2.x specifically (e.g. 3.2.0)
        findings_32 = scan_requirements_txt_for_vulnerabilities("django == 3.2.0\n", "requirements.txt")
        assert len(findings_32) == 1
        assert findings_32[0].package_name == "django"
        assert findings_32[0].cve_id == "CVE-2022-34265"
        assert findings_32[0].fixed_version == "3.2.14"
        assert findings_32[0].severity == "CRITICAL"

        # 3. Safe 3.1.x version (unaffected branch)
        findings_31 = scan_requirements_txt_for_vulnerabilities("django == 3.1.2\n", "requirements.txt")
        assert len(findings_31) == 0, f"Expected 0 findings for django 3.1.2, got {len(findings_31)}"

        # 4. Safe 5.0.x version (unaffected branch)
        findings_50 = scan_requirements_txt_for_vulnerabilities("django == 5.0.0\n", "requirements.txt")
        assert len(findings_50) == 0, f"Expected 0 findings for django 5.0.0, got {len(findings_50)}"

        # 5. Safe fixed/patched versions
        findings_fixed = scan_requirements_txt_for_vulnerabilities(
            "django == 3.2.14\ndjango == 4.0.6\n",
            "requirements.txt"
        )
        assert len(findings_fixed) == 0, f"Expected 0 findings for fixed versions, got {len(findings_fixed)}"

        # 6. Explicit 4.0 vulnerable range
        findings_range_40 = scan_requirements_txt_for_vulnerabilities(
            "django >= 4.0, < 4.0.6\n",
            "requirements.txt"
        )
        assert len(findings_range_40) == 1
        assert findings_range_40[0].fixed_version == "4.0.6"

        # 7. Explicit 3.2 vulnerable range (< 3.2.14)
        findings_range_32 = scan_requirements_txt_for_vulnerabilities(
            "django < 3.2.14\n",
            "requirements.txt"
        )
        assert len(findings_range_32) == 1
        assert findings_range_32[0].fixed_version == "3.2.14"


class TestPythonPyprojectToml:
    """Verifies PEP 621 and Poetry dependency parsing in pyproject.toml."""

    def test_pep621_pyproject(self):
        with open(PYPROJECT_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        findings = scan_pyproject_toml_for_vulnerabilities(content, "pyproject.toml")
        assert len(findings) == 4

        # Production dependencies
        prod_pkgs = {f.package_name: f for f in findings if not f.is_dev_dependency}
        assert "requests" in prod_pkgs
        assert prod_pkgs["requests"].severity == "HIGH"

        assert "django" in prod_pkgs
        assert prod_pkgs["django"].severity == "CRITICAL"

        assert "flask" in prod_pkgs
        assert prod_pkgs["flask"].rule_id == "UNPINNED_DEPENDENCY"
        assert prod_pkgs["flask"].severity == "HIGH"

        # Dev optional-dependency: urllib3 (HIGH downgraded to MEDIUM)
        dev_pkgs = {f.package_name: f for f in findings if f.is_dev_dependency}
        assert "urllib3" in dev_pkgs
        assert dev_pkgs["urllib3"].severity == "MEDIUM"
        assert dev_pkgs["urllib3"].cve_id == "CVE-2023-43804"

    def test_poetry_pyproject(self):
        poetry_content = """
[tool.poetry]
name = "my-poetry-pkg"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
django = "^3.0"
pyyaml = "<5.4"

[tool.poetry.dev-dependencies]
requests = "^2.25.0"
"""
        findings = scan_pyproject_toml_for_vulnerabilities(poetry_content, "pyproject.toml")
        assert len(findings) == 3

        django_f = next(f for f in findings if f.package_name == "django")
        assert django_f.severity == "CRITICAL"
        assert django_f.is_dev_dependency is False

        pyyaml_f = next(f for f in findings if f.package_name == "pyyaml")
        assert pyyaml_f.severity == "CRITICAL"
        assert pyyaml_f.is_dev_dependency is False

        requests_f = next(f for f in findings if f.package_name == "requests")
        assert requests_f.severity == "MEDIUM"  # Downgraded in dev-dependencies
        assert requests_f.is_dev_dependency is True


class TestPythonDependencyEndpoints:
    """Verifies API endpoints correctly route Python dependency files."""

    def test_analyze_dependencies_endpoint_requirements(self):
        res = client.post("/analyze/dependencies", json={
            "content": "django == 3.2.0\n",
            "filename": "requirements.txt"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["package_name"] == "django"
        assert finding["cve_id"] == "CVE-2022-34265"
        assert finding["severity"] == "CRITICAL"

    def test_analyze_general_endpoint_requirements(self):
        res = client.post("/analyze", json={
            "content": "requests == 2.25.0\n",
            "filename": "requirements.txt"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["package_name"] == "requests"
        assert finding["cve_id"] == "CVE-2023-32681"

    def test_analyze_general_endpoint_pyproject(self):
        res = client.post("/analyze", json={
            "content": """[project]
dependencies = ["django==3.2.0"]
""",
            "filename": "pyproject.toml"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["package_name"] == "django"
        assert finding["severity"] == "CRITICAL"

    def test_analyze_dependencies_endpoint_django_4_0_5(self):
        res = client.post("/analyze/dependencies", json={
            "content": "django == 4.0.5\n",
            "filename": "requirements.txt"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["package_name"] == "django"
        assert finding["cve_id"] == "CVE-2022-34265"
        assert finding["fixed_version"] == "4.0.6"
        assert finding["severity"] == "CRITICAL"

