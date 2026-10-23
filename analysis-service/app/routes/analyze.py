"""Analysis API endpoints for CodeGuard."""

import os
import time
from typing import List, Optional, Tuple
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.analyzers.secrets import scan_source_for_secrets
from app.analyzers.sql_injection import scan_source_for_sql_injection
from app.analyzers.dependencies import (
    scan_package_json_for_vulnerabilities,
    scan_dependencies_for_vulnerabilities,
)
from app.analyzers.xss import scan_source_for_xss
from app.analyzers.ai_antipatterns import scan_source_for_antipatterns

router = APIRouter(prefix="/analyze", tags=["Analysis"])


class FindingResponse(BaseModel):
    id: str = Field(..., description="Unique deterministic identifier for this finding")
    file_path: str = Field(..., description="Target file path or snippet identifier")
    line_number: int = Field(..., description="1-indexed starting line number")
    end_line_number: int = Field(..., description="1-indexed ending line number")
    column: int = Field(..., description="1-indexed starting column")
    end_column: int = Field(..., description="1-indexed ending column")
    rule_id: str = Field(..., description="Rule identifier (e.g. HARDCODED_SECRET, SQL_INJECTION, VULNERABLE_DEPENDENCY)")
    severity: str = Field(..., description="Severity rating (CRITICAL, HIGH, MEDIUM, LOW)")
    category: str = Field(..., description="Security category (Secret Leak, Injection Risk, Vulnerable Dependency)")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Detailed description of the vulnerability")
    code_snippet: str = Field(..., description="Code snippet demonstrating the finding")
    remediation: str = Field(..., description="Actionable remediation guidance")
    cwe_id: str = Field(..., description="Common Weakness Enumeration ID")

    # Secret leak specific fields
    secret_type: Optional[str] = Field(default=None, description="Specific secret signature type")
    redacted_value: Optional[str] = Field(default=None, description="Redacted preview of matched secret")

    # SQL Injection specific fields
    source_expression: Optional[str] = Field(default=None, description="User input source expression")
    source_line: Optional[int] = Field(default=None, description="Line where tainted input originated")
    sink_expression: Optional[str] = Field(default=None, description="Query execution sink expression")
    sink_line: Optional[int] = Field(default=None, description="Line where query execution sink was called")
    is_sanitized: Optional[bool] = Field(default=None, description="Whether input passed through a sanitizer")
    sanitizer_name: Optional[str] = Field(default=None, description="Name of sanitizer function if used")

    # Vulnerable Dependency specific fields
    package_name: Optional[str] = Field(default=None, description="Name of vulnerable package")
    declared_range: Optional[str] = Field(default=None, description="Declared version constraint or range")
    cve_id: Optional[str] = Field(default=None, description="Associated Common Vulnerabilities and Exposures ID")
    fixed_version: Optional[str] = Field(default=None, description="Recommended safe minimum fixed version")
    is_dev_dependency: Optional[bool] = Field(default=None, description="Whether package was declared in devDependencies")


class AnalyzeRequest(BaseModel):
    model_config = {"populate_by_name": True}

    filename: Optional[str] = Field(
        default="snippet.ts",
        description="Filename or extension used to select parser (e.g. auth.ts, app.js, package.json)"
    )
    content: Optional[str] = Field(
        default=None,
        description="Raw code snippet string to analyze"
    )
    package_json_content: Optional[str] = Field(
        default=None,
        alias="packageJsonContent",
        description="Raw package.json string content to analyze"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Absolute or relative path to a local file to analyze"
    )


class AnalyzeResponse(BaseModel):
    status: str = Field(default="completed", description="Scan execution status")
    file_path: str = Field(..., description="Target analyzed file path or identifier")
    findings_count: int = Field(..., description="Total findings detected")
    findings: List[FindingResponse] = Field(default_factory=list, description="List of detected findings")
    duration_ms: float = Field(..., description="Analysis duration in milliseconds")
    has_rate_limiting: Optional[bool] = Field(
        default=False,
        description="Whether rate limiting mechanism was detected in this file"
    )


def _read_code_input(request: AnalyzeRequest) -> Tuple[str, str]:
    """Helper to extract target code and file path from AnalyzeRequest."""
    raw_content = request.package_json_content or request.content
    if raw_content is None and not request.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'content', 'packageJsonContent', or 'file_path' must be provided in request body."
        )

    target_path = request.file_path or request.filename or "snippet.ts"
    if raw_content is not None:
        return raw_content, target_path

    assert request.file_path is not None
    if not os.path.exists(request.file_path) or not os.path.isfile(request.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target file not found at path: {request.file_path}"
        )
    try:
        with open(request.file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), target_path
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read file: {str(e)}"
        )


@router.post("/secrets", response_model=AnalyzeResponse)
def analyze_secrets_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze JavaScript/TypeScript code for hardcoded secrets and credentials."""
    code, target_path = _read_code_input(request)

    start_time = time.perf_counter()
    findings = scan_source_for_secrets(code, file_path=target_path)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(findings),
        findings=[FindingResponse(**f.to_dict()) for f in findings],
        duration_ms=elapsed_ms
    )


@router.post("/sql-injection", response_model=AnalyzeResponse)
def analyze_sql_injection_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze JavaScript/TypeScript code for SQL Injection vulnerabilities."""
    code, target_path = _read_code_input(request)

    start_time = time.perf_counter()
    findings = scan_source_for_sql_injection(code, file_path=target_path)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(findings),
        findings=[FindingResponse(**f.to_dict()) for f in findings],
        duration_ms=elapsed_ms
    )


@router.post("/dependencies", response_model=AnalyzeResponse)
def analyze_dependencies_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Scan package.json dependencies and devDependencies for known vulnerabilities."""
    code, target_path = _read_code_input(request)
    if not target_path or target_path == "snippet.ts":
        target_path = "package.json"

    start_time = time.perf_counter()
    findings = scan_dependencies_for_vulnerabilities(code, file_path=target_path)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(findings),
        findings=[FindingResponse(**f.to_dict()) for f in findings],
        duration_ms=elapsed_ms
    )


@router.post("/xss", response_model=AnalyzeResponse)
def analyze_xss_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze JavaScript/TypeScript/TSX code for Cross-Site Scripting (XSS) vulnerabilities."""
    code, target_path = _read_code_input(request)

    start_time = time.perf_counter()
    findings = scan_source_for_xss(code, file_path=target_path)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(findings),
        findings=[FindingResponse(**f.to_dict()) for f in findings],
        duration_ms=elapsed_ms
    )


@router.post("/antipatterns", response_model=AnalyzeResponse)
def analyze_antipatterns_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze JavaScript/TypeScript code for AI-generated code antipatterns."""
    code, target_path = _read_code_input(request)

    start_time = time.perf_counter()
    findings, has_rate_limiting = scan_source_for_antipatterns(code, file_path=target_path)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(findings),
        findings=[FindingResponse(**f.to_dict()) for f in findings],
        duration_ms=elapsed_ms,
        has_rate_limiting=has_rate_limiting
    )


@router.post("", response_model=AnalyzeResponse)
def analyze_general_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """General analysis entrypoint: runs active detectors based on payload type."""
    code, target_path = _read_code_input(request)
    target_lower = target_path.lower()
    is_dependency_file = (
        bool(request.package_json_content)
        or target_lower.endswith("package.json")
        or target_lower.endswith(".toml")
        or "pyproject" in target_lower
        or (target_lower.endswith(".txt") and "req" in target_lower)
    )

    start_time = time.perf_counter()
    all_findings_raw: List[dict] = []
    has_rate_limiting = False

    if is_dependency_file:
        dep_findings = scan_dependencies_for_vulnerabilities(code, file_path=target_path)
        all_findings_raw.extend(f.to_dict() for f in dep_findings)
    elif target_path.lower().endswith((".py", ".pyw")):
        secret_findings = scan_source_for_secrets(code, file_path=target_path)
        sql_findings = scan_source_for_sql_injection(code, file_path=target_path)
        xss_findings = scan_source_for_xss(code, file_path=target_path)
        all_findings_raw.extend(f.to_dict() for f in secret_findings)
        all_findings_raw.extend(f.to_dict() for f in sql_findings)
        all_findings_raw.extend(f.to_dict() for f in xss_findings)
    else:
        secret_findings = scan_source_for_secrets(code, file_path=target_path)
        sql_findings = scan_source_for_sql_injection(code, file_path=target_path)
        xss_findings = scan_source_for_xss(code, file_path=target_path)
        antipattern_findings, file_has_rate_limiting = scan_source_for_antipatterns(code, file_path=target_path)
        has_rate_limiting = file_has_rate_limiting
        all_findings_raw.extend(f.to_dict() for f in secret_findings)
        all_findings_raw.extend(f.to_dict() for f in sql_findings)
        all_findings_raw.extend(f.to_dict() for f in xss_findings)
        all_findings_raw.extend(f.to_dict() for f in antipattern_findings)

    all_findings_raw.sort(key=lambda d: (d["line_number"], d["column"]))
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalyzeResponse(
        status="completed",
        file_path=target_path,
        findings_count=len(all_findings_raw),
        findings=[FindingResponse(**f) for f in all_findings_raw],
        duration_ms=elapsed_ms,
        has_rate_limiting=has_rate_limiting
    )


@router.post("/rescan", response_model=AnalyzeResponse)
def analyze_rescan_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Rescan a single file or code snippet to verify whether vulnerability fixes eliminated the finding."""
    return analyze_general_endpoint(request)

