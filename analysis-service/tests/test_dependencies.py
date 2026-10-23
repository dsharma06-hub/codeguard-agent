"""Tests for package.json vulnerable dependency scanning and API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.dependencies import scan_package_json_for_vulnerabilities

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_FIXTURE_PATH = FIXTURES_DIR / "package_vulnerable.json"
CLEAN_FIXTURE_PATH = FIXTURES_DIR / "package_clean.json"

client = TestClient(app)


@pytest.fixture(scope="module")
def vuln_findings():
    with open(VULN_FIXTURE_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    return scan_package_json_for_vulnerabilities(content, file_path="package_vulnerable.json")


class TestDependencyTruePositives:
    """Tests verifying accurate detection of real vulnerable package versions."""

    def test_total_findings_count(self, vuln_findings):
        # 8 findings expected: 6 CVEs + 2 unpinned dependencies
        assert len(vuln_findings) == 8

    def test_exact_pinned_vulnerability(self, vuln_findings):
        lodash_f = next((f for f in vuln_findings if f.package_name == "lodash" and not f.is_dev_dependency), None)
        assert lodash_f is not None, "Production lodash finding missing"
        assert lodash_f.rule_id == "VULNERABLE_DEPENDENCY"
        assert lodash_f.cve_id == "CVE-2020-8203"
        assert lodash_f.severity == "HIGH"
        assert lodash_f.cwe_id == "CWE-1321"
        assert lodash_f.declared_range == "4.17.15"
        assert lodash_f.fixed_version == "4.17.21"

    def test_caret_range_including_vulnerabilities(self, vuln_findings):
        jwt_f = next((f for f in vuln_findings if f.package_name == "jsonwebtoken"), None)
        assert jwt_f is not None, "jsonwebtoken finding missing"
        assert jwt_f.rule_id == "VULNERABLE_DEPENDENCY"
        assert jwt_f.cve_id == "CVE-2022-23540"
        assert jwt_f.severity == "HIGH"
        assert jwt_f.cwe_id == "CWE-327"
        assert jwt_f.declared_range == "^8.5.1"
        assert jwt_f.fixed_version == "9.0.0"

    def test_semver_range_detection(self, vuln_findings):
        semver_f = next((f for f in vuln_findings if f.package_name == "semver"), None)
        assert semver_f is not None, "semver finding missing"
        assert semver_f.cve_id == "CVE-2022-25883"
        assert semver_f.fixed_version == "7.5.2"


class TestDependencyFalsePositives:
    """Tests ensuring secure configurations and lookalike packages are NOT flagged."""

    def test_clean_production_package_has_zero_findings(self):
        with open(CLEAN_FIXTURE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        findings = scan_package_json_for_vulnerabilities(content, file_path="package_clean.json")
        assert len(findings) == 0, f"Clean fixture generated unexpected findings: {[f.title for f in findings]}"

    def test_caret_range_floor_at_or_above_fix_is_safe(self, vuln_findings):
        # express is declared at "^4.19.2", which is the exact fixed version
        express_f = [f for f in vuln_findings if f.package_name == "express"]
        assert len(express_f) == 0, "express ^4.19.2 should not be flagged"

        # lodash in devDependencies is declared at "^4.17.21" (fixed version)
        dev_lodash = [f for f in vuln_findings if f.package_name == "lodash" and f.is_dev_dependency]
        assert len(dev_lodash) == 0, "lodash ^4.17.21 in devDependencies should not be flagged"

    def test_unrelated_lookalike_package_names_are_not_flagged(self, vuln_findings):
        # lodash-es contains 'lodash' as substring, but is a distinct package
        lodash_es = [f for f in vuln_findings if f.package_name == "lodash-es"]
        assert len(lodash_es) == 0, "lodash-es should not match lodash CVEs"

        # express-validator contains 'express' as substring, but is a distinct package
        express_val = [f for f in vuln_findings if f.package_name == "express-validator"]
        assert len(express_val) == 0, "express-validator should not match express CVEs"


class TestDevDependencySeverityDowngrade:
    """Tests verifying devDependencies receive one tier lower severity."""

    def test_tar_in_dev_dependencies_downgraded_to_medium(self, vuln_findings):
        tar_f = next((f for f in vuln_findings if f.package_name == "tar"), None)
        assert tar_f is not None, "tar finding missing"
        assert tar_f.is_dev_dependency is True
        # Base CVE-2021-37712 severity is HIGH; in devDependencies it must be MEDIUM
        assert tar_f.severity == "MEDIUM"
        assert "[DevDependency Context]" in tar_f.description

    def test_node_fetch_in_dev_dependencies_downgraded(self, vuln_findings):
        fetch_f = next((f for f in vuln_findings if f.package_name == "node-fetch"), None)
        assert fetch_f is not None, "node-fetch finding missing"
        assert fetch_f.is_dev_dependency is True
        # Base severity HIGH downgraded to MEDIUM
        assert fetch_f.severity == "MEDIUM"


class TestUnpinnedDependencies:
    """Tests verifying unpinned wildcards are flagged distinctly."""

    def test_wildcard_version_flagged_as_unpinned(self, vuln_findings):
        moment_f = next((f for f in vuln_findings if f.package_name == "moment"), None)
        assert moment_f is not None, "moment wildcard finding missing"
        assert moment_f.rule_id == "UNPINNED_DEPENDENCY"
        assert moment_f.severity == "HIGH"
        assert moment_f.cwe_id == "CWE-1104"
        assert moment_f.declared_range == "*"

    def test_latest_keyword_flagged_as_unpinned(self, vuln_findings):
        ws_f = next((f for f in vuln_findings if f.package_name == "ws"), None)
        assert ws_f is not None, "ws 'latest' finding missing"
        assert ws_f.rule_id == "UNPINNED_DEPENDENCY"
        # in devDependencies, base HIGH is downgraded to MEDIUM
        assert ws_f.severity == "MEDIUM"
        assert ws_f.declared_range == "latest"


class TestDependencyApiEndpoints:
    """Tests for the HTTP analysis endpoints."""

    def test_post_analyze_dependencies_with_package_json_content(self):
        payload = {
            "packageJsonContent": '{"dependencies": {"lodash": "4.17.15"}}'
        }
        res = client.post("/analyze/dependencies", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "completed"
        assert data["findings_count"] == 1
        finding = data["findings"][0]
        assert finding["rule_id"] == "VULNERABLE_DEPENDENCY"
        assert finding["package_name"] == "lodash"
        assert finding["cve_id"] == "CVE-2020-8203"

    def test_post_analyze_dependencies_with_file_path(self):
        payload = {
            "file_path": str(CLEAN_FIXTURE_PATH)
        }
        res = client.post("/analyze/dependencies", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 0

    def test_general_analyze_endpoint_runs_dependencies_on_package_json(self):
        payload = {
            "filename": "package.json",
            "content": '{"dependencies": {"jsonwebtoken": "^8.5.1"}}'
        }
        res = client.post("/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["cve_id"] == "CVE-2022-23540"
