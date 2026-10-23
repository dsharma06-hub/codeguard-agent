"""Vulnerable Dependency Scanner for package.json.

Scans package.json dependencies and devDependencies against a local database
of real, verified CVEs using semver range resolution.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
import json
import re
import uuid
import semver
import tomllib
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion


REMEDIATION_GENERAL = (
    "Upgrade the package to the fixed version or higher, and verify your lockfile "
    "(package-lock.json or yarn.lock) has resolved to a non-vulnerable version."
)

# Local database of real, verified CVEs for popular npm packages
LOCAL_VULNERABILITY_DATABASE: List[Dict[str, Any]] = [
    {
        "package": "lodash",
        "cve_id": "CVE-2020-8203",
        "title": "Prototype Pollution in lodash",
        "affected_range": "< 4.17.21",
        "min_affected": "0.0.0",
        "fixed_version": "4.17.21",
        "severity": "HIGH",
        "cwe_id": "CWE-1321",
        "description": (
            "Prototype pollution vulnerability in lodash prior to 4.17.21 allows attackers "
            "to inject arbitrary properties into Object.prototype via zipObjectDeep."
        ),
    },
    {
        "package": "jsonwebtoken",
        "cve_id": "CVE-2022-23540",
        "title": "Signature Validation Bypass in jsonwebtoken",
        "affected_range": "<= 8.5.1",
        "min_affected": "0.0.0",
        "fixed_version": "9.0.0",
        "severity": "HIGH",
        "cwe_id": "CWE-327",
        "description": (
            "jsonwebtoken versions <= 8.5.1 are vulnerable to signature validation bypass "
            "because the library defaults to the 'none' algorithm when no algorithm is explicitly "
            "defined in jwt.verify() and a falsy secret or key is provided."
        ),
    },
    {
        "package": "axios",
        "cve_id": "CVE-2020-28168",
        "title": "Server-Side Request Forgery / Proxy Bypass in axios",
        "affected_range": "< 0.21.1",
        "min_affected": "0.0.0",
        "fixed_version": "0.21.1",
        "severity": "MEDIUM",
        "cwe_id": "CWE-918",
        "description": (
            "Axios versions before 0.21.1 allow attackers to bypass proxy configurations "
            "when following redirects via a crafted followRedirect option."
        ),
    },
    {
        "package": "express",
        "cve_id": "CVE-2024-29041",
        "title": "Open Redirect Vulnerability in express",
        "affected_range": "< 4.19.2",
        "min_affected": "0.0.0",
        "fixed_version": "4.19.2",
        "severity": "MEDIUM",
        "cwe_id": "CWE-601",
        "description": (
            "Express before 4.19.2 is vulnerable to open redirection when handling user-provided "
            "URLs in res.location() and res.redirect()."
        ),
    },
    {
        "package": "minimist",
        "cve_id": "CVE-2020-7598",
        "title": "Prototype Pollution in minimist",
        "affected_range": "< 1.2.3",
        "min_affected": "0.0.0",
        "fixed_version": "1.2.3",
        "severity": "HIGH",
        "cwe_id": "CWE-1321",
        "description": (
            "minimist before 1.2.3 is vulnerable to prototype pollution when parsing malicious "
            "command-line arguments."
        ),
    },
    {
        "package": "semver",
        "cve_id": "CVE-2022-25883",
        "title": "Regular Expression Denial of Service (ReDoS) in semver",
        "affected_range": ">= 7.0.0 < 7.5.2",
        "min_affected": "7.0.0",
        "fixed_version": "7.5.2",
        "severity": "HIGH",
        "cwe_id": "CWE-1333",
        "description": (
            "The semver package prior to 7.5.2 is vulnerable to Regular Expression Denial of Service "
            "when processing crafted version strings."
        ),
    },
    {
        "package": "tar",
        "cve_id": "CVE-2021-37712",
        "title": "Arbitrary File Overwrite / Directory Traversal in tar",
        "affected_range": "< 6.1.9",
        "min_affected": "0.0.0",
        "fixed_version": "6.1.9",
        "severity": "HIGH",
        "cwe_id": "CWE-22",
        "description": (
            "The node-tar package before 6.1.9 is vulnerable to arbitrary file creation and overwrite "
            "via path traversal in archive extraction."
        ),
    },
    {
        "package": "ws",
        "cve_id": "CVE-2024-38375",
        "title": "Denial of Service in ws WebSocket client",
        "affected_range": "< 8.17.1",
        "min_affected": "8.0.0",
        "fixed_version": "8.17.1",
        "severity": "HIGH",
        "cwe_id": "CWE-400",
        "description": (
            "ws prior to 8.17.1 is vulnerable to denial of service when processing crafted "
            "Sec-WebSocket-Protocol headers."
        ),
    },
    {
        "package": "node-fetch",
        "cve_id": "CVE-2022-0235",
        "title": "Sensitive Information Exposure in node-fetch",
        "affected_range": "< 2.6.7",
        "min_affected": "0.0.0",
        "fixed_version": "2.6.7",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "description": (
            "node-fetch before 2.6.7 did not honor standard cross-origin redirect security policies, "
            "forwarding authorization headers across origins."
        ),
    },
    {
        "package": "moment",
        "cve_id": "CVE-2022-24785",
        "title": "Path Traversal in moment.js locale loading",
        "affected_range": "< 2.29.2",
        "min_affected": "0.0.0",
        "fixed_version": "2.29.2",
        "severity": "HIGH",
        "cwe_id": "CWE-22",
        "description": (
            "Moment.js before 2.29.2 is vulnerable to path traversal when user-provided input "
            "is used in locale() methods."
        ),
    },
]

# Local database of real, verified CVEs for popular Python (PyPI) packages
PYTHON_VULNERABILITY_DATABASE: List[Dict[str, Any]] = [
    {
        "package": "django",
        "cve_id": "CVE-2022-34265",
        "title": "Potential SQL Injection in Django Trunc() and Extract() database functions",
        "affected_range": ">= 3.2, < 3.2.14",
        "min_affected": "3.2.0",
        "fixed_version": "3.2.14",
        "severity": "CRITICAL",
        "cwe_id": "CWE-89",
        "description": (
            "Django 3.2 before 3.2.14 is vulnerable to SQL injection via the Trunc() and Extract() "
            "database functions when untrusted parameters are passed."
        ),
    },
    {
        "package": "django",
        "cve_id": "CVE-2022-34265",
        "title": "Potential SQL Injection in Django Trunc() and Extract() database functions",
        "affected_range": ">= 4.0, < 4.0.6",
        "min_affected": "4.0.0",
        "fixed_version": "4.0.6",
        "severity": "CRITICAL",
        "cwe_id": "CWE-89",
        "description": (
            "Django 4.0 before 4.0.6 is vulnerable to SQL injection via the Trunc() and Extract() "
            "database functions when untrusted parameters are passed."
        ),
    },
    {
        "package": "flask",
        "cve_id": "CVE-2023-30861",
        "title": "Cookie Domain Misconfiguration / Sensitive Cookie Leakage in Flask",
        "affected_range": "< 2.3.2",
        "min_affected": "0.0.0",
        "fixed_version": "2.3.2",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "description": (
            "Flask before 2.3.2 is vulnerable to sensitive cookie disclosure when serving "
            "multiple domains without setting a cookie domain."
        ),
    },
    {
        "package": "requests",
        "cve_id": "CVE-2023-32681",
        "title": "Proxy-Authorization Header Leak in Requests",
        "affected_range": "< 2.31.0",
        "min_affected": "0.0.0",
        "fixed_version": "2.31.0",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "description": (
            "Requests before 2.31.0 leaks Proxy-Authorization headers to destination servers "
            "when following HTTPS redirects."
        ),
    },
    {
        "package": "pyyaml",
        "cve_id": "CVE-2020-14343",
        "title": "Arbitrary Code Execution in PyYAML via full_load",
        "affected_range": "< 5.4",
        "min_affected": "0.0.0",
        "fixed_version": "5.4",
        "severity": "CRITICAL",
        "cwe_id": "CWE-502",
        "description": (
            "PyYAML before 5.4 allows arbitrary code execution through the yaml.full_load function "
            "or UnsafeLoader when parsing untrusted YAML data."
        ),
    },
    {
        "package": "urllib3",
        "cve_id": "CVE-2023-43804",
        "title": "Cookie Header Leak on Cross-Origin Redirects in urllib3",
        "affected_range": "< 2.0.6",
        "min_affected": "0.0.0",
        "fixed_version": "2.0.6",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "description": (
            "urllib3 before 2.0.6 does not strip the Cookie header on cross-origin redirects."
        ),
    },
    {
        "package": "pillow",
        "cve_id": "CVE-2022-22817",
        "title": "Arbitrary Code Execution in Pillow PIL.ImageMath.eval",
        "affected_range": "< 9.0.0",
        "min_affected": "0.0.0",
        "fixed_version": "9.0.0",
        "severity": "CRITICAL",
        "cwe_id": "CWE-94",
        "description": (
            "PIL.ImageMath.eval in Pillow before 9.0.0 allows remote code execution via builtins "
            "in expression evaluation."
        ),
    },
    {
        "package": "jinja2",
        "cve_id": "CVE-2024-22195",
        "title": "Cross-Site Scripting (XSS) in Jinja xmlattr Filter",
        "affected_range": "< 3.1.3",
        "min_affected": "0.0.0",
        "fixed_version": "3.1.3",
        "severity": "HIGH",
        "cwe_id": "CWE-79",
        "description": (
            "Jinja before 3.1.3 allows Cross-Site Scripting (XSS) via the xmlattr filter when "
            "keys contain spaces or special characters."
        ),
    },
]

# Map of devDependency severity reduction:
# Development tooling dependencies are evaluated at one severity tier lower than production dependencies,
# because devDependencies are typically omitted from production runtime deployments.
DEV_DEPENDENCY_SEVERITY_MAP = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "LOW",
}


@dataclass
class DependencyFinding:
    id: str
    file_path: str
    line_number: int
    end_line_number: int
    column: int
    end_column: int
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    code_snippet: str
    remediation: str
    cwe_id: str
    package_name: str
    declared_range: str
    cve_id: Optional[str]
    fixed_version: Optional[str]
    is_dev_dependency: bool

    def to_dict(self) -> dict:
        d = asdict(self)
        d["secret_type"] = None
        d["redacted_value"] = None
        d["source_expression"] = None
        d["source_line"] = None
        d["sink_expression"] = None
        d["sink_line"] = None
        d["is_sanitized"] = None
        d["sanitizer_name"] = None
        return d


def normalize_semver_str(ver_str: str) -> str:
    """Normalize partial version strings like '4.17' or '4' to complete semver '4.17.0'."""
    clean = re.sub(r"^[=~^v\s]+", "", ver_str).strip()
    parts = clean.split("-")[0].split("+")[0].split(".")
    while len(parts) < 3:
        parts.append("0")
    norm = ".".join(parts[:3])
    if "-" in clean:
        norm += "-" + clean.split("-", 1)[1]
    return norm


def parse_semver_bounds(declared_range: str) -> Tuple[bool, Optional[semver.Version], Optional[semver.Version]]:
    """Determine whether range is unpinned and extract floor and ceiling versions."""
    raw = declared_range.strip()
    # Unpinned wildcard expressions
    if raw in ("*", "latest", "x", "X", "", ">0.0.0", ">=0.0.0"):
        return True, None, None

    clean_base = normalize_semver_str(raw)
    try:
        base_v = semver.Version.parse(clean_base)
    except Exception:
        # If unable to parse semver, treat as unpinned/unverifiable
        return True, None, None

    # Caret range: ^major.minor.patch
    if raw.startswith("^"):
        floor = base_v
        if base_v.major > 0:
            ceil = semver.Version(base_v.major + 1, 0, 0)
        elif base_v.minor > 0:
            ceil = semver.Version(0, base_v.minor + 1, 0)
        else:
            ceil = semver.Version(0, 0, base_v.patch + 1)
        return False, floor, ceil

    # Tilde range: ~major.minor.patch
    elif raw.startswith("~"):
        floor = base_v
        ceil = semver.Version(base_v.major, base_v.minor + 1, 0)
        return False, floor, ceil

    # Exact or comparison
    else:
        return False, base_v, base_v


def is_version_range_vulnerable(
    declared_range: str,
    min_affected_str: str,
    fixed_version_str: str
) -> bool:
    """Check if the declared version range includes known vulnerable versions."""
    is_unpinned, floor, ceil = parse_semver_bounds(declared_range)
    if is_unpinned or floor is None or ceil is None:
        return False

    try:
        min_aff = semver.Version.parse(normalize_semver_str(min_affected_str))
        fixed_v = semver.Version.parse(normalize_semver_str(fixed_version_str))
    except Exception:
        return False

    # A range could resolve to vulnerable versions if:
    # 1. Range floor is below the fixed version (meaning the lowest acceptable version is vulnerable)
    # 2. AND range ceiling is above or equal to the minimum affected version
    if floor < fixed_v and ceil > min_aff and floor >= min_aff:
        return True

    # Case where floor is below min_aff, but ceiling reaches into vulnerable window
    if floor < min_aff and ceil > min_aff:
        return True

    return False


def find_line_in_package_json(
    source_lines: List[str],
    pkg_name: str,
    in_dev: bool
) -> Tuple[int, int, int, str]:
    """Locate line and column coordinates of a package declaration in package.json."""
    section_name = "devDependencies" if in_dev else "dependencies"
    in_target_section = False
    brace_depth = 0

    target_pattern = re.compile(rf'"{re.escape(pkg_name)}"\s*:\s*"(.*?)"')

    for idx, line in enumerate(source_lines, 1):
        if f'"{section_name}"' in line:
            in_target_section = True

        if in_target_section:
            if "{" in line:
                brace_depth += line.count("{")
            if "}" in line:
                brace_depth -= line.count("}")
                if brace_depth <= 0:
                    in_target_section = False

            m = target_pattern.search(line)
            if m:
                col = m.start() + 1
                end_col = m.end() + 1
                return idx, col, end_col, line.strip()

    # Fallback search anywhere in file if section tracking missed it
    for idx, line in enumerate(source_lines, 1):
        m = target_pattern.search(line)
        if m:
            col = m.start() + 1
            end_col = m.end() + 1
            return idx, col, end_col, line.strip()

    return 1, 1, 1, f'"{pkg_name}": "unknown"'


def scan_package_json_for_vulnerabilities(
    package_json_content: str,
    file_path: str = "package.json"
) -> List[DependencyFinding]:
    """Scan a package.json file for known vulnerable dependencies and unpinned versions."""
    if not package_json_content or not package_json_content.strip():
        return []

    try:
        data = json.loads(package_json_content)
    except Exception:
        # Invalid JSON syntax
        return []

    source_lines = package_json_content.splitlines()
    findings: List[DependencyFinding] = []

    # Map package name to CVE list
    vuln_db_by_pkg: Dict[str, List[Dict[str, Any]]] = {}
    for entry in LOCAL_VULNERABILITY_DATABASE:
        vuln_db_by_pkg.setdefault(entry["package"], []).append(entry)

    # Process dependencies and devDependencies
    sections = [
        ("dependencies", data.get("dependencies", {}), False),
        ("devDependencies", data.get("devDependencies", {}), True),
    ]

    for section_name, pkgs, is_dev in sections:
        if not isinstance(pkgs, dict):
            continue

        for pkg_name, declared_range in pkgs.items():
            if not isinstance(declared_range, str):
                continue

            line, col, end_col, snippet = find_line_in_package_json(source_lines, pkg_name, is_dev)
            is_unpinned, floor, ceil = parse_semver_bounds(declared_range)

            # EDGE CASE: Unpinned version range (*, latest, empty)
            if is_unpinned:
                base_sev = "HIGH"
                # DevDependency severity reduction
                eff_sev = DEV_DEPENDENCY_SEVERITY_MAP[base_sev] if is_dev else base_sev
                finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:UNPINNED"))

                desc = (
                    f"Package '{pkg_name}' declares an unpinned version '{declared_range}'. "
                    "Without an explicit version constraint, builds cannot be audited for security "
                    "vulnerabilities and are susceptible to supply-chain tampering and unexpected breaking changes."
                )
                if is_dev:
                    desc += (
                        " [DevDependency Context] Flagged at reduced severity ("
                        f"{eff_sev} vs {base_sev}) because this package is declared in devDependencies."
                    )

                findings.append(DependencyFinding(
                    id=finding_id,
                    file_path=file_path,
                    line_number=line,
                    end_line_number=line,
                    column=col,
                    end_column=end_col,
                    rule_id="UNPINNED_DEPENDENCY",
                    severity=eff_sev,
                    category="Vulnerable Dependency",
                    title=f"Unpinned Dependency Version ({pkg_name}: \"{declared_range}\")",
                    description=desc,
                    code_snippet=snippet,
                    remediation=f"Pin '{pkg_name}' to an exact version or well-defined semantic version range (e.g. \"^1.0.0\").",
                    cwe_id="CWE-1104",
                    package_name=pkg_name,
                    declared_range=declared_range,
                    cve_id=None,
                    fixed_version=None,
                    is_dev_dependency=is_dev
                ))
                continue

            # Check exact match against CVE database
            # (Strict equality check on package name to prevent substring false positives)
            cve_matches = vuln_db_by_pkg.get(pkg_name, [])
            for cve in cve_matches:
                if is_version_range_vulnerable(declared_range, cve["min_affected"], cve["fixed_version"]):
                    base_sev = cve["severity"]
                    eff_sev = DEV_DEPENDENCY_SEVERITY_MAP.get(base_sev, "LOW") if is_dev else base_sev
                    finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:{cve['cve_id']}"))

                    desc = (
                        f"{cve['description']} Declared range '{declared_range}' includes vulnerable versions "
                        f"({cve['affected_range']}). Fixed in version {cve['fixed_version']}."
                    )
                    if is_dev:
                        desc += (
                            f" [DevDependency Context] Flagged at reduced severity ({eff_sev} vs {base_sev}) "
                            "because this package is declared in devDependencies (development tooling)."
                        )

                    findings.append(DependencyFinding(
                        id=finding_id,
                        file_path=file_path,
                        line_number=line,
                        end_line_number=line,
                        column=col,
                        end_column=end_col,
                        rule_id="VULNERABLE_DEPENDENCY",
                        severity=eff_sev,
                        category="Vulnerable Dependency",
                        title=f"{cve['cve_id']}: Known Vulnerability in {pkg_name} ({cve['title']})",
                        description=desc,
                        code_snippet=snippet,
                        remediation=f"Upgrade {pkg_name} to version {cve['fixed_version']} or higher.",
                        cwe_id=cve["cwe_id"],
                        package_name=pkg_name,
                        declared_range=declared_range,
                        cve_id=cve["cve_id"],
                        fixed_version=cve["fixed_version"],
                        is_dev_dependency=is_dev
                    ))

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings


def canonicalize_pkg_name(name: str) -> str:
    """Canonicalize Python package name per PEP 503 (lowercase, replace _ and . with -)."""
    return name.lower().replace("_", "-").replace(".", "-").strip()


# Index Python vulnerability database by canonical package name
VULN_DB_PY: Dict[str, List[dict]] = {}
for entry in PYTHON_VULNERABILITY_DATABASE:
    c_name = canonicalize_pkg_name(entry["package"])
    VULN_DB_PY.setdefault(c_name, []).append(entry)


def convert_poetry_specifier(spec_str: str) -> str:
    """Converts Poetry caret/tilde/wildcard specifiers to standard PEP 440."""
    spec_str = spec_str.strip()
    if not spec_str:
        return ""
    if spec_str.startswith("^"):
        v_str = spec_str[1:].strip()
        parts = v_str.split(".")
        if len(parts) >= 1 and parts[0] != "0":
            next_major = int(parts[0]) + 1
            return f">={v_str},<{next_major}.0.0"
        elif len(parts) >= 2 and parts[0] == "0" and parts[1] != "0":
            next_minor = int(parts[1]) + 1
            return f">={v_str},<0.{next_minor}.0"
        elif len(parts) >= 3 and parts[0] == "0" and parts[1] == "0":
            next_patch = int(parts[2]) + 1
            return f">={v_str},<0.0.{next_patch}"
        return f">={v_str}"
    if spec_str.startswith("~") and not spec_str.startswith("~="):
        return f"~={spec_str[1:].strip()}"
    return spec_str


def is_python_version_vulnerable(
    declared_range: str,
    affected_spec_str: str,
    min_affected_str: str,
    fixed_version_str: str
) -> bool:
    """Determines if a PEP 440 version specifier can resolve to a known vulnerable version."""
    clean_decl = convert_poetry_specifier(declared_range).strip()
    if not clean_decl or clean_decl in ("*", "latest"):
        return True

    # If bare version number without operator, e.g. "2.25.0", prepend "=="
    if re.match(r"^[0-9]", clean_decl):
        clean_decl = f"=={clean_decl}"

    try:
        decl_spec = SpecifierSet(clean_decl)
    except InvalidSpecifier:
        return False

    try:
        affected_spec = SpecifierSet(affected_spec_str)
        min_affected = Version(min_affected_str)
        fixed_version = Version(fixed_version_str)
    except (InvalidSpecifier, InvalidVersion):
        return False

    # 1. Exact version check (e.g. == 2.25.0)
    if len(decl_spec) == 1:
        s = next(iter(decl_spec))
        if s.operator == "==":
            try:
                v = Version(s.version)
                return v in affected_spec
            except InvalidVersion:
                pass

    # 2. Extract effective lower bound from decl_spec
    min_allowed = None
    for s in decl_spec:
        if s.operator in (">=", ">"):
            try:
                v = Version(s.version)
                if min_allowed is None or v > min_allowed:
                    min_allowed = v
            except InvalidVersion:
                pass
        elif s.operator == "~=":
            try:
                v = Version(s.version)
                if min_allowed is None or v > min_allowed:
                    min_allowed = v
            except InvalidVersion:
                pass

    # If declared minimum is >= fixed_version, it is guaranteed safe
    if min_allowed is not None and min_allowed >= fixed_version:
        return False

    # 3. Check upper bound from decl_spec
    max_allowed = None
    for s in decl_spec:
        if s.operator in ("<=", "<"):
            try:
                v = Version(s.version)
                if max_allowed is None or v < max_allowed:
                    max_allowed = v
            except InvalidVersion:
                pass

    if max_allowed is not None and max_allowed <= min_affected and min_affected > Version("0.0.0"):
        return False

    # 4. Check if candidate versions in range satisfy decl_spec and affected_spec
    if min_allowed is not None and min_allowed in affected_spec:
        return True

    # If upper bound is specified, an intermediate vulnerable version (like min_affected) can be resolved
    if max_allowed is not None:
        if min_affected in decl_spec and min_affected in affected_spec:
            return True
    elif min_allowed is None:
        # No lower bound and no upper bound (or bare wildcard)
        if min_affected in decl_spec and min_affected in affected_spec:
            return True

    return False


def parse_requirements_line(line: str) -> Optional[Tuple[str, str, bool]]:
    """Parses a requirements line into (package_name, version_spec, is_unpinned)."""
    clean_line = re.sub(r"#.*$", "", line).strip()
    if not clean_line or clean_line.startswith(("-r", "-f", "-i", "--")):
        return None

    if ";" in clean_line:
        clean_line = clean_line.split(";", 1)[0].strip()

    match = re.match(r"^([a-zA-Z0-9_.\-]+)\s*(.*)$", clean_line)
    if not match:
        return None

    pkg_name = match.group(1).strip()
    spec = match.group(2).strip()

    if "[" in pkg_name and "]" in pkg_name:
        pkg_name = pkg_name.split("[", 1)[0].strip()

    is_unpinned = (not spec) or (spec in ("*", "latest"))
    return pkg_name, spec, is_unpinned


def scan_requirements_txt_for_vulnerabilities(
    content: str,
    file_path: str = "requirements.txt"
) -> List[DependencyFinding]:
    """Scan requirements.txt (or requirements-dev.txt) for unpinned or vulnerable packages."""
    if not content or not content.strip():
        return []

    is_dev = "dev" in file_path.lower()
    source_lines = content.splitlines()
    findings: List[DependencyFinding] = []

    for idx, raw_line in enumerate(source_lines):
        parsed = parse_requirements_line(raw_line)
        if not parsed:
            continue
        pkg_name, declared_range, is_unpinned = parsed
        line_num = idx + 1
        col = 1
        end_col = len(raw_line) + 1
        snippet = raw_line.strip()

        # Check Unpinned
        if is_unpinned:
            base_sev = "HIGH"
            eff_sev = DEV_DEPENDENCY_SEVERITY_MAP[base_sev] if is_dev else base_sev
            finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:UNPINNED"))
            desc = (
                f"Package '{pkg_name}' declares an unpinned version '{declared_range or 'latest'}'. "
                "Without an explicit version constraint, builds cannot be audited for security "
                "vulnerabilities and are susceptible to supply-chain tampering and unexpected breaking changes."
            )
            if is_dev:
                desc += (
                    f" [DevDependency Context] Flagged at reduced severity ({eff_sev} vs {base_sev}) "
                    "because this package is declared in a development requirements file."
                )

            findings.append(DependencyFinding(
                id=finding_id,
                file_path=file_path,
                line_number=line_num,
                end_line_number=line_num,
                column=col,
                end_column=end_col,
                rule_id="UNPINNED_DEPENDENCY",
                severity=eff_sev,
                category="Vulnerable Dependency",
                title=f"Unpinned Dependency Version ({pkg_name})",
                description=desc,
                code_snippet=snippet,
                remediation=f"Pin '{pkg_name}' to an exact version or well-defined semantic version range (e.g. '==1.0.0' or '~=1.0.0').",
                cwe_id="CWE-1104",
                package_name=pkg_name,
                declared_range=declared_range or "*",
                cve_id=None,
                fixed_version=None,
                is_dev_dependency=is_dev
            ))
            continue

        # Exact match against Python CVE database
        c_name = canonicalize_pkg_name(pkg_name)
        cve_matches = VULN_DB_PY.get(c_name, [])
        matched_cves = set()
        for cve in cve_matches:
            if cve["cve_id"] in matched_cves:
                continue
            if is_python_version_vulnerable(declared_range, cve["affected_range"], cve["min_affected"], cve["fixed_version"]):
                matched_cves.add(cve["cve_id"])
                base_sev = cve["severity"]
                eff_sev = DEV_DEPENDENCY_SEVERITY_MAP.get(base_sev, "LOW") if is_dev else base_sev
                finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:{cve['cve_id']}"))

                desc = (
                    f"{cve['description']} Declared version constraint '{declared_range}' includes vulnerable versions "
                    f"({cve['affected_range']}). Fixed in version {cve['fixed_version']}."
                )
                if is_dev:
                    desc += (
                        f" [DevDependency Context] Flagged at reduced severity ({eff_sev} vs {base_sev}) "
                        "because this package is declared in a development requirements file."
                    )

                findings.append(DependencyFinding(
                    id=finding_id,
                    file_path=file_path,
                    line_number=line_num,
                    end_line_number=line_num,
                    column=col,
                    end_column=end_col,
                    rule_id="VULNERABLE_DEPENDENCY",
                    severity=eff_sev,
                    category="Vulnerable Dependency",
                    title=f"{cve['cve_id']}: Known Vulnerability in {pkg_name} ({cve['title']})",
                    description=desc,
                    code_snippet=snippet,
                    remediation=f"Upgrade {pkg_name} to version {cve['fixed_version']} or higher.",
                    cwe_id=cve["cwe_id"],
                    package_name=pkg_name,
                    declared_range=declared_range,
                    cve_id=cve["cve_id"],
                    fixed_version=cve["fixed_version"],
                    is_dev_dependency=is_dev
                ))

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings


def find_line_in_pyproject(source_lines: List[str], pkg_name: str) -> Tuple[int, int, int, str]:
    """Finds line number and snippet for a package in pyproject.toml."""
    c_name = canonicalize_pkg_name(pkg_name)
    for idx, line in enumerate(source_lines):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        line_c = canonicalize_pkg_name(line)
        if re.search(rf"""(?i)(?:["']\s*{re.escape(c_name)}[=><~"'\s,;\[]|^\s*{re.escape(c_name)}\s*=)""", line_c):
            return idx + 1, 1, len(line_clean) + 1, line_clean
    return 1, 1, len(source_lines[0]) if source_lines else 1, source_lines[0].strip() if source_lines else ""


def scan_pyproject_toml_for_vulnerabilities(
    content: str,
    file_path: str = "pyproject.toml"
) -> List[DependencyFinding]:
    """Scan pyproject.toml (PEP 621 and Poetry) for unpinned or vulnerable packages."""
    if not content or not content.strip():
        return []

    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    source_lines = content.splitlines()
    findings: List[DependencyFinding] = []
    raw_deps: List[Tuple[str, bool]] = []

    # 1. PEP 621: [project.dependencies] and [project.optional-dependencies]
    project = data.get("project", {})
    if "dependencies" in project and isinstance(project["dependencies"], list):
        for item in project["dependencies"]:
            if isinstance(item, str):
                raw_deps.append((item, False))

    if "optional-dependencies" in project and isinstance(project["optional-dependencies"], dict):
        for group, items in project["optional-dependencies"].items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        raw_deps.append((item, True))

    # 2. Poetry: [tool.poetry.dependencies] and [tool.poetry.dev-dependencies]
    poetry = data.get("tool", {}).get("poetry", {})
    if "dependencies" in poetry and isinstance(poetry["dependencies"], dict):
        for pkg, spec in poetry["dependencies"].items():
            if pkg.lower() == "python":
                continue
            spec_str = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
            raw_deps.append((f"{pkg} {spec_str}".strip(), False))

    if "dev-dependencies" in poetry and isinstance(poetry["dev-dependencies"], dict):
        for pkg, spec in poetry["dev-dependencies"].items():
            spec_str = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
            raw_deps.append((f"{pkg} {spec_str}".strip(), True))

    groups = poetry.get("group", {})
    if isinstance(groups, dict):
        for grp_name, grp_val in groups.items():
            is_dev = "dev" in grp_name.lower() or "test" in grp_name.lower()
            deps = grp_val.get("dependencies", {}) if isinstance(grp_val, dict) else {}
            if isinstance(deps, dict):
                for pkg, spec in deps.items():
                    spec_str = spec if isinstance(spec, str) else spec.get("version", "") if isinstance(spec, dict) else ""
                    raw_deps.append((f"{pkg} {spec_str}".strip(), is_dev))

    for dep_str, is_dev in raw_deps:
        parsed = parse_requirements_line(dep_str)
        if not parsed:
            continue
        pkg_name, declared_range, is_unpinned = parsed
        line_num, col, end_col, snippet = find_line_in_pyproject(source_lines, pkg_name)

        if is_unpinned:
            base_sev = "HIGH"
            eff_sev = DEV_DEPENDENCY_SEVERITY_MAP[base_sev] if is_dev else base_sev
            finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:UNPINNED"))
            desc = (
                f"Package '{pkg_name}' declares an unpinned version '{declared_range or 'latest'}'. "
                "Without an explicit version constraint, builds cannot be audited for security "
                "vulnerabilities and are susceptible to supply-chain tampering and unexpected breaking changes."
            )
            if is_dev:
                desc += (
                    f" [DevDependency Context] Flagged at reduced severity ({eff_sev} vs {base_sev}) "
                    "because this package is declared in optional/development dependencies."
                )

            findings.append(DependencyFinding(
                id=finding_id,
                file_path=file_path,
                line_number=line_num,
                end_line_number=line_num,
                column=col,
                end_column=end_col,
                rule_id="UNPINNED_DEPENDENCY",
                severity=eff_sev,
                category="Vulnerable Dependency",
                title=f"Unpinned Dependency Version ({pkg_name})",
                description=desc,
                code_snippet=snippet,
                remediation=f"Pin '{pkg_name}' to an exact version or well-defined semantic version range (e.g. '==1.0.0').",
                cwe_id="CWE-1104",
                package_name=pkg_name,
                declared_range=declared_range or "*",
                cve_id=None,
                fixed_version=None,
                is_dev_dependency=is_dev
            ))
            continue

        c_name = canonicalize_pkg_name(pkg_name)
        cve_matches = VULN_DB_PY.get(c_name, [])
        matched_cves = set()
        for cve in cve_matches:
            if cve["cve_id"] in matched_cves:
                continue
            if is_python_version_vulnerable(declared_range, cve["affected_range"], cve["min_affected"], cve["fixed_version"]):
                matched_cves.add(cve["cve_id"])
                base_sev = cve["severity"]
                eff_sev = DEV_DEPENDENCY_SEVERITY_MAP.get(base_sev, "LOW") if is_dev else base_sev
                finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{pkg_name}:{cve['cve_id']}"))

                desc = (
                    f"{cve['description']} Declared version constraint '{declared_range}' includes vulnerable versions "
                    f"({cve['affected_range']}). Fixed in version {cve['fixed_version']}."
                )
                if is_dev:
                    desc += (
                        f" [DevDependency Context] Flagged at reduced severity ({eff_sev} vs {base_sev}) "
                        "because this package is declared in optional/development dependencies."
                    )

                findings.append(DependencyFinding(
                    id=finding_id,
                    file_path=file_path,
                    line_number=line_num,
                    end_line_number=line_num,
                    column=col,
                    end_column=end_col,
                    rule_id="VULNERABLE_DEPENDENCY",
                    severity=eff_sev,
                    category="Vulnerable Dependency",
                    title=f"{cve['cve_id']}: Known Vulnerability in {pkg_name} ({cve['title']})",
                    description=desc,
                    code_snippet=snippet,
                    remediation=f"Upgrade {pkg_name} to version {cve['fixed_version']} or higher.",
                    cwe_id=cve["cwe_id"],
                    package_name=pkg_name,
                    declared_range=declared_range,
                    cve_id=cve["cve_id"],
                    fixed_version=cve["fixed_version"],
                    is_dev_dependency=is_dev
                ))

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings


def scan_dependencies_for_vulnerabilities(
    content: str,
    file_path: str = "package.json"
) -> List[DependencyFinding]:
    """Unified entrypoint that routes package.json, requirements.txt, and pyproject.toml."""
    lower_path = file_path.lower()
    if lower_path.endswith("package.json"):
        return scan_package_json_for_vulnerabilities(content, file_path=file_path)
    elif lower_path.endswith(".toml") or "pyproject" in lower_path:
        return scan_pyproject_toml_for_vulnerabilities(content, file_path=file_path)
    elif lower_path.endswith(".txt") or "requirements" in lower_path:
        return scan_requirements_txt_for_vulnerabilities(content, file_path=file_path)
    else:
        # Heuristic detection based on content
        stripped = content.strip()
        if stripped.startswith("{"):
            return scan_package_json_for_vulnerabilities(content, file_path=file_path)
        elif "[project" in stripped or "[tool.poetry" in stripped:
            return scan_pyproject_toml_for_vulnerabilities(content, file_path=file_path)
        else:
            return scan_requirements_txt_for_vulnerabilities(content, file_path=file_path)
