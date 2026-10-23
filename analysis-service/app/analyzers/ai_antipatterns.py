"""AI-Generated-Code-Specific Antipattern AST Analyzer for JavaScript and TypeScript.

Detects common AI code-generation antipatterns and security hardening gaps:
1. Missing Rate Limiting on Sensitive Endpoints (Express routes: /login, /signin, /register,
   /signup, /reset-password, password destructuring in POST handlers).
2. Hardcoded Production Endpoints (HTTP client calls using absolute non-localhost, non-private
   URLs instead of environment variables/configuration constants).

Engineered conservatively with strict false-positive guards.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import ipaddress
import re
import uuid

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts


# Initialize Tree-sitter Languages
JS_LANGUAGE = tree_sitter.Language(tsjs.language())
TS_LANGUAGE = tree_sitter.Language(tsts.language_typescript())
TSX_LANGUAGE = tree_sitter.Language(tsts.language_tsx())

# Sensitive route path regex patterns
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|register|signup|sign-up|reset-password|reset_password|"
    r"forgot-password|forgot_password|change-password|change_password)(?:/|\?|$)",
    re.IGNORECASE
)

# Sensitive handler identifier names (e.g. handleLogin, loginUser, registerController)
SENSITIVE_HANDLER_PATTERN = re.compile(
    r"(?i)^(?:handle|auth)?(?:login|signin|register|signup|resetpassword|forgotpassword|changepassword)(?:handler|controller|action|fn|callback)?$"
)

# Known rate-limiting package imports / module specifiers
KNOWN_RATE_LIMIT_PACKAGES: Set[str] = {
    "express-rate-limit",
    "express-slow-down",
    "rate-limiter-flexible",
    "express-brute",
    "limiter",
    "rate-limit",
    "ratelimit",
}

# Substring patterns indicating rate limiter or throttler identifiers
RATE_LIMIT_IDENTIFIER_PATTERN = re.compile(
    r"(?i)(?:ratelimit|rate_limit|rate-limit|throttle|throttler|limiter)"
)

# Express route method names
EXPRESS_ROUTE_METHODS: Set[str] = {
    "get", "post", "put", "patch", "delete", "all"
}

# HTTP client call identifiers/methods
HTTP_CLIENT_FUNCTIONS: Set[str] = {
    "fetch", "axios", "got"
}

HTTP_CLIENT_METHODS: Set[str] = {
    "get", "post", "put", "patch", "delete", "request"
}

HTTP_CLIENT_OBJECTS: Set[str] = {
    "axios", "got", "superagent", "needle", "http", "https", "client", "apiclient", "httpclient"
}

# Well-known third-party APIs that developers legitimately call with fixed URLs
WELL_KNOWN_THIRD_PARTY_DOMAINS: Set[str] = {
    # Source control & packages
    "api.github.com", "github.com", "raw.githubusercontent.com",
    "registry.npmjs.org", "npmjs.com", "gitlab.com",
    # Payments
    "api.stripe.com", "stripe.com",
    "api.paypal.com", "api.sandbox.paypal.com", "paypal.com",
    # Cloud & AI
    "googleapis.com", "accounts.google.com", "maps.googleapis.com", "generativelanguage.googleapis.com",
    "amazonaws.com",
    "api.openai.com", "openai.com",
    "api.anthropic.com",
    # Communications
    "api.twilio.com", "twilio.com",
    "api.slack.com", "slack.com",
    "discord.com", "discordapp.com",
    "api.sendgrid.com", "sendgrid.com",
    # Identity & Monitoring
    "sentry.io",
    "auth0.com",
    "okta.com",
    "api.cloudflare.com", "cloudflare.com",
    # Specifications & Standards
    "w3.org", "www.w3.org", "schema.org", "json-schema.org", "xml.org", "xmlns.com",
    # Diagnostics & Mock
    "api.ipify.org", "icanhazip.com", "httpbin.org",
    "example.com", "example.org", "example.net"
}


@dataclass
class AntipatternFinding:
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
    source_expression: Optional[str] = None
    source_line: Optional[int] = None
    sink_expression: Optional[str] = None
    sink_line: Optional[int] = None
    is_sanitized: Optional[bool] = None
    sanitizer_name: Optional[str] = None
    secret_type: Optional[str] = None
    redacted_value: Optional[str] = None
    package_name: Optional[str] = None
    declared_range: Optional[str] = None
    cve_id: Optional[str] = None
    fixed_version: Optional[str] = None
    is_dev_dependency: Optional[bool] = None

    def to_dict(self) -> dict:
        return asdict(self)


def get_parser_for_filename(filename: str) -> tree_sitter.Parser:
    """Select the appropriate Tree-sitter parser based on file extension."""
    lower = filename.lower()
    if lower.endswith((".tsx", ".ts", ".mts", ".cts", ".jsx")):
        return tree_sitter.Parser(TSX_LANGUAGE)
    else:
        return tree_sitter.Parser(JS_LANGUAGE)


def get_node_text(node: tree_sitter.Node) -> str:
    """Retrieve decoded text for an AST node."""
    return node.text.decode("utf-8", errors="replace")


def is_test_or_mock_file(file_path: str) -> bool:
    """Check if the given file path represents test or mock code."""
    norm = file_path.replace("\\", "/").lower()
    parts = norm.split("/")
    filename = parts[-1] if parts else norm

    test_dirs = {
        "test", "tests", "__tests__", "spec", "specs",
        "__mocks__", "mock", "mocks", "fixtures", "fixture"
    }
    if any(part in test_dirs for part in parts[:-1]):
        return True

    if (
        filename.endswith((
            ".test.js", ".test.ts", ".test.jsx", ".test.tsx",
            ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
            ".mock.js", ".mock.ts", ".fixture.js", ".fixture.ts"
        ))
        or filename.startswith(("test_", "mock_"))
    ):
        return True

    return False


def is_private_or_local_host(hostname: str) -> bool:
    """Check if a hostname resolves to localhost, private IP, or special domain."""
    if not hostname:
        return True

    lower = hostname.lower()
    if lower in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "[::1]"):
        return True

    if lower.endswith((".local", ".internal", ".test", ".example", ".invalid")):
        return True

    # Check for IP address
    clean_host = lower.strip("[]")
    try:
        ip = ipaddress.ip_address(clean_host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return True
    except ValueError:
        pass

    return False


def is_well_known_third_party(hostname: str) -> bool:
    """Check if hostname belongs to a known public third-party API service."""
    if not hostname:
        return False

    lower = hostname.lower()
    if lower in WELL_KNOWN_THIRD_PARTY_DOMAINS:
        return True

    for domain in WELL_KNOWN_THIRD_PARTY_DOMAINS:
        if lower.endswith("." + domain):
            return True

    return False


def extract_string_literal(node: tree_sitter.Node) -> Optional[str]:
    """Extract plain text string content if node is a static string literal."""
    if node.type == "string":
        raw = get_node_text(node)
        if len(raw) >= 2 and (raw[0] == raw[-1] and raw[0] in ("'", '"')):
            return raw[1:-1]
        return raw.strip("'\"")

    if node.type == "template_string":
        # Check if template has substitutions (e.g. `${...}`)
        for child in node.children:
            if child.type == "template_substitution":
                return None
        raw = get_node_text(node)
        if raw.startswith("`") and raw.endswith("`"):
            return raw[1:-1]
        return raw.strip("`")

    return None


def detect_rate_limiting_signals(root_node: tree_sitter.Node, code: str) -> bool:
    """Determine whether the AST contains rate-limiting imports, middleware, or calls."""
    # Fast regex pre-check across source
    if not RATE_LIMIT_IDENTIFIER_PATTERN.search(code):
        return False

    # AST traversal to detect imports and app.use / router.use applications
    stack = [root_node]
    while stack:
        curr = stack.pop()

        # 1. Check imports: import ... from 'express-rate-limit' or require('express-rate-limit')
        if curr.type in ("import_statement", "import_declaration"):
            import_text = get_node_text(curr).lower()
            for pkg in KNOWN_RATE_LIMIT_PACKAGES:
                if pkg in import_text:
                    return True

        if curr.type == "call_expression":
            fn_node = curr.child_by_field_name("function")
            if fn_node:
                fn_text = get_node_text(fn_node).lower()
                # require('express-rate-limit')
                if fn_text == "require":
                    args = curr.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            str_val = extract_string_literal(arg)
                            if str_val and str_val.lower() in KNOWN_RATE_LIMIT_PACKAGES:
                                return True

                # app.use(limiter) or router.use(rateLimiter)
                if fn_node.type == "member_expression":
                    prop_node = fn_node.child_by_field_name("property")
                    prop_name = get_node_text(prop_node).lower() if prop_node else ""
                    if prop_name == "use":
                        args = curr.child_by_field_name("arguments")
                        if args:
                            for arg in args.children:
                                if arg.type in (",", "(", ")"):
                                    continue
                                arg_text = get_node_text(arg)
                                if RATE_LIMIT_IDENTIFIER_PATTERN.search(arg_text):
                                    return True

        stack.extend(reversed(curr.children))

    return False


def handler_destructures_password(handler_node: tree_sitter.Node) -> bool:
    """Check if a route handler destructures or accesses password from req.body."""
    stack = [handler_node]
    while stack:
        curr = stack.pop()

        # Look for: const { password } = req.body
        if curr.type == "variable_declarator":
            name_node = curr.child_by_field_name("name")
            value_node = curr.child_by_field_name("value")
            if name_node and value_node and name_node.type == "object_pattern":
                val_text = get_node_text(value_node).lower()
                if "body" in val_text:
                    for child in name_node.children:
                        child_text = get_node_text(child).lower()
                        if "password" in child_text or "passwd" in child_text:
                            return True

        # Look for: req.body.password
        if curr.type == "member_expression":
            expr_text = get_node_text(curr).lower()
            if (
                ("req.body.password" in expr_text or "request.body.password" in expr_text)
                or ("req.body['password']" in expr_text or 'req.body["password"]' in expr_text)
            ):
                return True

        stack.extend(reversed(curr.children))

    return False


def detect_sensitive_routes(
    root_node: tree_sitter.Node,
    code: str,
    file_path: str
) -> List[AntipatternFinding]:
    """Identify sensitive Express routes that require rate limiting."""
    if is_test_or_mock_file(file_path):
        return []

    lines = code.splitlines()
    findings: List[AntipatternFinding] = []

    stack = [root_node]
    while stack:
        curr = stack.pop()

        if curr.type == "call_expression":
            fn_node = curr.child_by_field_name("function")
            if fn_node and fn_node.type == "member_expression":
                prop_node = fn_node.child_by_field_name("property")
                prop_name = get_node_text(prop_node).lower() if prop_node else ""

                if prop_name in EXPRESS_ROUTE_METHODS:
                    args_node = curr.child_by_field_name("arguments")
                    if args_node:
                        # Extract positional arguments
                        named_args = [
                            c for c in args_node.children if c.type not in (",", "(", ")")
                        ]
                        if named_args:
                            path_str: Optional[str] = None
                            first_arg = named_args[0]
                            path_str = extract_string_literal(first_arg)

                            is_sensitive = False
                            matched_reason = ""

                            # Check 1: Route path matches sensitive endpoints
                            if path_str and SENSITIVE_PATH_PATTERN.search(path_str):
                                is_sensitive = True
                                matched_reason = f"Endpoint path '{path_str}'"

                            # Check 2: Handler identifier matches sensitive patterns
                            if not is_sensitive and len(named_args) > 1:
                                for handler_arg in named_args[1:]:
                                    if handler_arg.type == "identifier":
                                        ident_name = get_node_text(handler_arg)
                                        if SENSITIVE_HANDLER_PATTERN.search(ident_name):
                                            is_sensitive = True
                                            matched_reason = f"Handler function '{ident_name}'"
                                            break

                            # Check 3: POST route destructuring password from req.body
                            if not is_sensitive and prop_name in ("post", "all"):
                                for handler_arg in named_args:
                                    if handler_arg.type in (
                                        "arrow_function", "function_expression", "function_declaration"
                                    ):
                                        if handler_destructures_password(handler_arg):
                                            is_sensitive = True
                                            label = path_str or "POST route"
                                            matched_reason = f"{label} accessing credential/password input"
                                            break

                            # If sensitive, verify no route-level rate limiter is applied on this route
                            if is_sensitive:
                                has_route_limiter = False
                                for arg in named_args[1:]:
                                    arg_text = get_node_text(arg)
                                    if RATE_LIMIT_IDENTIFIER_PATTERN.search(arg_text):
                                        has_route_limiter = True
                                        break

                                if not has_route_limiter:
                                    start_line = curr.start_point[0] + 1
                                    end_line = curr.end_point[0] + 1
                                    col = curr.start_point[1] + 1
                                    end_col = curr.end_point[1] + 1

                                    snip_line = lines[start_line - 1] if start_line - 1 < len(lines) else ""
                                    route_label = path_str if path_str else (prop_name.upper() + " auth endpoint")

                                    findings.append(
                                        AntipatternFinding(
                                            id=f"cg-rate-{uuid.uuid4().hex[:8]}",
                                            file_path=file_path,
                                            line_number=start_line,
                                            end_line_number=end_line,
                                            column=col,
                                            end_column=end_col,
                                            rule_id="MISSING_RATE_LIMITING",
                                            severity="MEDIUM",
                                            category="AI Antipattern",
                                            title=f"Missing Rate Limiting on Sensitive Endpoint ({route_label})",
                                            description=(
                                                f"Sensitive authentication route ({matched_reason}) is missing "
                                                f"rate-limiting protection against brute-force or credential stuffing attacks."
                                            ),
                                            code_snippet=snip_line.strip(),
                                            remediation=(
                                                "Protect sensitive authentication endpoints with rate limiting using "
                                                "'express-rate-limit' or equivalent middleware (e.g. "
                                                f"app.use('{route_label}', rateLimit({{ windowMs: 15 * 60 * 1000, max: 5 }})))."
                                            ),
                                            cwe_id="CWE-307"
                                        )
                                    )

        stack.extend(reversed(curr.children))

    return findings


def detect_hardcoded_production_endpoints(
    root_node: tree_sitter.Node,
    code: str,
    file_path: str
) -> List[AntipatternFinding]:
    """Detect absolute HTTP/HTTPS URLs hardcoded in client calls."""
    if is_test_or_mock_file(file_path):
        return []

    lines = code.splitlines()
    findings: List[AntipatternFinding] = []

    stack = [root_node]
    while stack:
        curr = stack.pop()

        if curr.type == "call_expression":
            fn_node = curr.child_by_field_name("function")
            if fn_node:
                is_http_call = False
                call_label = ""

                # Direct call: fetch(...) or axios(...) or got(...)
                if fn_node.type == "identifier":
                    fn_name = get_node_text(fn_node).lower()
                    if fn_name in HTTP_CLIENT_FUNCTIONS:
                        is_http_call = True
                        call_label = fn_name

                # Method call: axios.get(...), superagent.post(...), http.get(...)
                elif fn_node.type == "member_expression":
                    obj_node = fn_node.child_by_field_name("object")
                    prop_node = fn_node.child_by_field_name("property")
                    obj_name = get_node_text(obj_node).lower() if obj_node else ""
                    prop_name = get_node_text(prop_node).lower() if prop_node else ""

                    if (
                        obj_name in HTTP_CLIENT_OBJECTS
                        and prop_name in HTTP_CLIENT_METHODS
                    ):
                        is_http_call = True
                        call_label = f"{obj_name}.{prop_name}"

                if is_http_call:
                    args_node = curr.child_by_field_name("arguments")
                    if args_node:
                        named_args = [
                            c for c in args_node.children if c.type not in (",", "(", ")")
                        ]
                        if named_args:
                            first_arg = named_args[0]
                            url_candidate: Optional[str] = None
                            target_node = first_arg

                            # Direct string URL: fetch("https://api.mycorp.com/users")
                            if first_arg.type in ("string", "template_string"):
                                url_candidate = extract_string_literal(first_arg)

                            # Configuration object URL: axios({ url: "https://api.mycorp.com" })
                            elif first_arg.type == "object":
                                for prop in first_arg.children:
                                    if prop.type == "pair":
                                        k = prop.child_by_field_name("key")
                                        v = prop.child_by_field_name("value")
                                        if k and v and get_node_text(k).lower() == "url":
                                            url_candidate = extract_string_literal(v)
                                            target_node = v
                                            break

                            if url_candidate:
                                lower_url = url_candidate.strip().lower()
                                if lower_url.startswith(("http://", "https://")):
                                    try:
                                        parsed = urlparse(url_candidate)
                                        host = parsed.hostname or ""

                                        # Apply false-positive guards
                                        if (
                                            not is_private_or_local_host(host)
                                            and not is_well_known_third_party(host)
                                            and "." in host  # Must be a valid domain with TLD
                                        ):
                                            start_line = target_node.start_point[0] + 1
                                            end_line = target_node.end_point[0] + 1
                                            col = target_node.start_point[1] + 1
                                            end_col = target_node.end_point[1] + 1
                                            snip_line = lines[start_line - 1] if start_line - 1 < len(lines) else ""

                                            findings.append(
                                                AntipatternFinding(
                                                    id=f"cg-url-{uuid.uuid4().hex[:8]}",
                                                    file_path=file_path,
                                                    line_number=start_line,
                                                    end_line_number=end_line,
                                                    column=col,
                                                    end_column=end_col,
                                                    rule_id="HARDCODED_PRODUCTION_ENDPOINT",
                                                    severity="LOW",
                                                    category="AI Antipattern",
                                                    title=f"Hardcoded Production Endpoint URL ({host})",
                                                    description=(
                                                        f"Absolute production endpoint URL '{url_candidate}' is hardcoded "
                                                        f"directly in '{call_label}()' instead of using environment variables."
                                                    ),
                                                    code_snippet=snip_line.strip(),
                                                    remediation=(
                                                        "Configure API base URLs through environment variables "
                                                        "(e.g. process.env.API_BASE_URL) to ensure safe separation between "
                                                        "development, staging, and production environments."
                                                    ),
                                                    cwe_id="CWE-1188"
                                                )
                                            )
                                    except Exception:
                                        pass

        stack.extend(reversed(curr.children))

    return findings


def scan_source_for_antipatterns(
    code: str,
    file_path: str = "snippet.ts"
) -> Tuple[List[AntipatternFinding], bool]:
    """Scan source code for AI-generated-code antipatterns.

    Returns:
        Tuple of (findings_list, file_has_rate_limiting_flag)
    """
    if not code or not code.strip():
        return [], False

    parser = get_parser_for_filename(file_path)
    tree = parser.parse(code.encode("utf-8"))
    root = tree.root_node

    has_rate_limiting = detect_rate_limiting_signals(root, code)
    sensitive_route_findings = detect_sensitive_routes(root, code, file_path)
    hardcoded_url_findings = detect_hardcoded_production_endpoints(root, code, file_path)

    # If this file contains rate-limiting, suppress sensitive route findings for this file
    active_findings: List[AntipatternFinding] = []
    if not has_rate_limiting:
        active_findings.extend(sensitive_route_findings)
    active_findings.extend(hardcoded_url_findings)

    active_findings.sort(key=lambda f: (f.line_number, f.column))
    return active_findings, has_rate_limiting
