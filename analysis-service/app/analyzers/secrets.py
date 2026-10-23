"""Hardcoded Secret Detector using Tree-sitter AST analysis.

Scans JavaScript and TypeScript source files for embedded credentials, API keys,
tokens, and high-entropy secret assignments.
"""

from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Set
import re
import math
import uuid
from collections import Counter

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
import tree_sitter_python as tspy


# Initialize Tree-sitter Languages
JS_LANGUAGE = tree_sitter.Language(tsjs.language())
TS_LANGUAGE = tree_sitter.Language(tsts.language_typescript())
TSX_LANGUAGE = tree_sitter.Language(tsts.language_tsx())
PYTHON_LANGUAGE = tree_sitter.Language(tspy.language())

# Remediation guidance text
REMEDIATION_GUIDANCE = (
    "Move sensitive credentials to environment variables or a secrets manager "
    "(such as AWS Secrets Manager, HashiCorp Vault, or Doppler). "
    "Never commit secrets to source control."
)

# Known high-confidence secret regex signatures
# Each tuple: (secret_type, compiled_regex, human_title, human_description)
KNOWN_SECRET_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        "Hardcoded AWS Access Key ID Detected",
        "A plaintext AWS Access Key ID was detected in source code. Exposed AWS credentials grant unauthorized access to cloud infrastructure and APIs.",
    ),
    (
        "STRIPE_API_KEY",
        re.compile(r"\b((?:sk_live|rk_live|sk_test|rk_test)_[0-9a-zA-Z]{24,})\b"),
        "Hardcoded Stripe API Key Detected",
        "A plaintext Stripe API key was detected in source code. Exposed payment processor keys allow unauthorized financial transactions and customer data access.",
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255})\b"),
        "Hardcoded GitHub Token Detected",
        "A plaintext GitHub Personal Access Token or OAuth token was detected. Exposed tokens compromise private repositories, CI/CD workflows, and organization secrets.",
    ),
    (
        "JWT_TOKEN",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "Hardcoded JSON Web Token (JWT) Detected",
        "A hardcoded JSON Web Token was found in source code. Hardcoded JWTs may contain privileged session claims, bypass authentication, and cannot be revoked individually.",
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "Hardcoded Slack Token Detected",
        "A plaintext Slack API token was detected in source code. Slack tokens allow attackers to read channel communications and access sensitive workspace data.",
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "Hardcoded Google API Key Detected",
        "A hardcoded Google Cloud or Firebase API key was detected. Exposed API keys can allow unauthorized API usage and service quota abuse.",
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Hardcoded Cryptographic Private Key Detected",
        "An unencrypted cryptographic private key header was detected in source code. Private keys must remain confidential to protect cryptographic integrity and SSH/TLS access.",
    ),
]

# Variable / property identifier suffixes or substrings that indicate SAFE non-secret values
SAFE_IDENTIFIERS_SUBSTRINGS: Tuple[str, ...] = (
    "URL", "URI", "HOST", "PORT", "ENDPOINT", "PATH", "BASE_URL",
    "DOMAIN", "ROUTE", "METHOD", "TYPE", "NAME", "TAG", "LABEL",
    "VERSION", "STATUS", "HEADER", "COLOR", "TITLE", "DESC",
    "DESCRIPTION", "MODE", "ENV", "LENGTH", "COUNT", "INDEX",
    "OFFSET", "LIMIT", "SCHEMA", "FORMAT", "PROMPT", "POLICY",
    "INPUT", "FIELD", "PLACEHOLDER", "MESSAGE", "ERR", "ERROR",
)

# Specific non-credential key names to reject immediately
NON_CREDENTIAL_KEY_NAMES: Set[str] = {
    "key", "keys", "keyword", "keywords", "keyboard", "keyframe", "keyframes",
    "keypress", "keyup", "keydown", "keymap", "keycode", "keycodes",
    "primarykey", "foreignkey", "partitionkey", "sortkey", "uniquekey",
    "routingkey", "cachekey", "translationkey", "i18nkey", "mapkey",
    "itemkey", "rowkey", "columnkey", "nodekey", "elementkey", "propkey",
    "schemakey", "eventkey", "messagekey", "hotkey", "searchkey",
}

# Prefixes that indicate database, UI, cache, or structural keys rather than credentials
NON_CREDENTIAL_KEY_PREFIXES: Tuple[str, ...] = (
    "primary", "foreign", "partition", "sort", "unique", "routing",
    "cache", "translation", "i18n", "map", "item", "row", "column",
    "node", "element", "prop", "event", "message", "hot", "search",
    "composite", "surrogate", "natural", "candidate", "alternate",
)

# Compound key pattern: must have a non-empty qualifying prefix before 'key'
# (e.g. apiKey, secret_key, privateKey, accessKeyId, encryption_key, webhook_signing_key, etc.)
COMPOUND_KEY_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9_]+[_-]|(?:[a-zA-Z0-9_]+[A-Z]))key(?:[_-]?id)?s?$",
    re.IGNORECASE
)

# Core credential patterns (secret, token, password, credential)
CREDENTIAL_TERMS_PATTERN = re.compile(
    r".*(?:secret|token|password|passwd|pwd|credential).*",
    re.IGNORECASE
)

# Non-credential terms to exclude
DISALLOWED_IDENTIFIER_SUBSTRINGS: Tuple[str, ...] = (
    "SECRETARY", "SECRETARIAT", "TOKENIZE", "TOKENIZER",
    "KEYBOARD", "KEYWORD", "KEYFRAME", "KEYPRESS", "KEYUP", "KEYDOWN", "KEYMAP", "KEYCODE"
)

# Backwards compatibility alias
SUSPICIOUS_IDENTIFIERS_PATTERN = CREDENTIAL_TERMS_PATTERN

# Values that indicate safe non-secret strings
SAFE_VALUE_PREFIXES: Tuple[str, ...] = (
    "http://", "https://", "ftp://", "wss://", "ws://", "/", "./", "../"
)

# Dummy / placeholder keywords that developers use in sample code or configs (exact match)
DUMMY_VALUES: Set[str] = {
    "your_api_key_here", "your_secret_here", "your_api_key", "your-api-key",
    "your-secret-token", "enter_key_here", "replace_me", "changeme", "todo",
    "test", "dummy", "example", "sample", "localhost", "undefined", "null",
    "default", "placeholder", "xxx", "admin", "password", "secret",
    "<your_key_here>", "<api_key>", "my-secret-key"
}

# Substring patterns that unambiguously signal placeholder or template values
DUMMY_SUBSTRING_PATTERNS: Tuple[str, ...] = (
    "your_api_key", "your-api-key", "your_secret", "your-secret",
    "enter_key_here", "replace_me", "my-secret-key",
    "<your_key_here>", "<api_key>", "dummy-", "placeholder"
)

# Known HTTP request / response header names (case-insensitive)
KNOWN_HTTP_HEADERS: Set[str] = {
    # CORS Headers
    "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-expose-headers",
    "access-control-max-age", "access-control-allow-credentials",
    "access-control-request-method", "access-control-request-headers",
    "origin", "vary",

    # Content / Body Headers
    "content-type", "content-length", "content-encoding", "content-language",
    "content-location", "content-disposition", "content-range",
    "content-security-policy", "content-security-policy-report-only",

    # Auth & Security Headers
    "authorization", "proxy-authorization", "www-authenticate",
    "proxy-authenticate", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "x-xss-protection", "x-csrf-token",
    "x-api-key", "x-requested-with",

    # Standard Headers
    "accept", "accept-charset", "accept-encoding", "accept-language",
    "accept-datetime", "user-agent", "referer", "referrer", "host",
    "cookie", "set-cookie", "cache-control", "pragma", "expires",
    "etag", "if-match", "if-none-match", "if-modified-since",
    "if-unmodified-since", "if-range", "connection", "keep-alive",
    "transfer-encoding", "te", "upgrade", "trailer", "via", "warning",
    "location", "retry-after", "server", "age", "allow",

    # Client Hints & Sec-*
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
}

# Regex pattern matching HTTP header naming conventions
HTTP_HEADER_PATTERN = re.compile(
    r"^(?:Access-Control-[A-Za-z0-9-]+|Content-[A-Za-z0-9-]+|Sec-[A-Za-z0-9-]+|X-[A-Za-z0-9-]+|Strict-Transport-Security)$",
    re.IGNORECASE
)

# MIME types / Content-Type values
MIME_TYPE_PATTERN = re.compile(
    r"^(?:application|text|image|audio|video|font|multipart|model)/[a-zA-Z0-9.+*_-]+(?:;\s*[a-zA-Z0-9=._-]+)*$",
    re.IGNORECASE
)

# Common enum values, environments, and structural configuration keywords
COMMON_ENUM_VALUES: Set[str] = {
    # Environments & modes
    "production", "development", "staging", "testing", "sandbox", "preview",
    "localhost", "local", "cluster", "default", "standard", "custom",

    # Booleans & nullability
    "true", "false", "null", "undefined", "none", "all", "always", "never",
    "auto", "manual", "initial", "inherit", "strict", "loose",

    # Permissions & roles
    "read", "write", "readwrite", "readonly", "admin", "administrator",
    "user", "guest", "root", "system", "anonymous", "public", "private",
    "internal", "external", "protected",

    # Status & levels
    "enabled", "disabled", "active", "inactive", "pending", "success",
    "failure", "error", "warning", "info", "debug", "trace", "verbose",
    "notice", "critical", "fatal", "pass", "fail", "ok",

    # HTTP & Web terms
    "get", "post", "put", "delete", "patch", "options", "head", "connect",
    "bearer", "basic", "digest", "oauth", "jwt", "gzip", "deflate", "br",
    "utf-8", "utf8", "ascii", "base64", "hex",

    # Data structures & types
    "string", "number", "boolean", "object", "array", "function", "symbol",
    "bigint", "request", "response", "session", "cookie", "header", "query",
    "param", "params", "body", "options", "config", "settings", "timeout",
}


@dataclass
class SecretFinding:
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
    secret_type: str
    redacted_value: str

    def to_dict(self) -> dict:
        return asdict(self)


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def redact_secret(secret: str) -> str:
    """Redact secret keeping first 4 and last 4 characters, masking the middle.
    
    Ensures full secret is NEVER returned.
    """
    n = len(secret)
    if n <= 4:
        return "*" * n
    elif n <= 8:
        return secret[:2] + ("*" * (n - 3)) + secret[-1:]
    else:
        mask_len = n - 8
        return secret[:4] + ("*" * mask_len) + secret[-4:]


def get_parser_for_filename(filename: str) -> tree_sitter.Parser:
    """Select the appropriate Tree-sitter parser based on file extension."""
    lower = filename.lower()
    if lower.endswith((".py", ".pyw")):
        return tree_sitter.Parser(PYTHON_LANGUAGE)
    elif lower.endswith(".tsx"):
        return tree_sitter.Parser(TSX_LANGUAGE)
    elif lower.endswith((".ts", ".mts", ".cts")):
        return tree_sitter.Parser(TS_LANGUAGE)
    else:
        return tree_sitter.Parser(JS_LANGUAGE)


def extract_contextual_identifier(node: tree_sitter.Node) -> Optional[str]:
    """Inspect AST parent nodes to determine the variable or property name receiving this string."""
    parent = node.parent
    if not parent:
        return None

    # const API_KEY = "..."
    if parent.type == "variable_declarator":
        name_node = parent.child_by_field_name("name")
        if name_node:
            return name_node.text.decode("utf-8", errors="replace")

    # obj = { apiKey: "..." }
    elif parent.type == "pair":
        key_node = parent.child_by_field_name("key")
        if key_node:
            return key_node.text.decode("utf-8", errors="replace")

    # obj.apiKey = "..." or apiKey = "..."
    elif parent.type == "assignment_expression":
        left_node = parent.child_by_field_name("left")
        if left_node:
            return left_node.text.decode("utf-8", errors="replace")

    # TypeScript class / interface property: apiKey: string = "..."
    elif parent.type in ("property_definition", "public_field_definition", "property_signature"):
        name_node = parent.child_by_field_name("name")
        if name_node:
            return name_node.text.decode("utf-8", errors="replace")

    # JSX attribute: <Component apiKey="..." />
    elif parent.type == "jsx_attribute":
        prop_node = parent.child_by_field_name("property")
        if prop_node:
            return prop_node.text.decode("utf-8", errors="replace")
        for child in parent.children:
            if child.type in ("jsx_identifier", "property_identifier"):
                return child.text.decode("utf-8", errors="replace")

    return None


def is_safe_identifier(identifier: str) -> bool:
    """Check if the variable or property identifier indicates a safe/non-secret value."""
    upper = identifier.upper()
    return any(upper.endswith(sfx) or sfx in upper for sfx in SAFE_IDENTIFIERS_SUBSTRINGS)


def is_suspicious_credential_identifier(ident: str) -> bool:
    """Check if an identifier represents a genuine credential or secret container.
    
    Tightened rules:
    - Bare 'key' or 'keys' is NOT suspicious.
    - Database/UI keys (primaryKey, foreignKey, cacheKey, etc.) are NOT suspicious.
    - Bare 'auth' or 'author' is NOT suspicious.
    - Bare 'private' (access modifier) is NOT suspicious.
    - Requires a specific compound credential pattern (apiKey, secret_key, token, password, etc.).
    """
    if not ident:
        return False
    ident_clean = ident.strip()
    ident_lower = ident_clean.lower()
    ident_upper = ident_clean.upper()

    # 1. Reject disallowed non-credential substrings
    if any(bad in ident_upper for bad in DISALLOWED_IDENTIFIER_SUBSTRINGS):
        return False

    # 2. Reject bare non-credential key names
    if ident_lower in NON_CREDENTIAL_KEY_NAMES:
        return False

    # 3. Reject non-credential key prefixes
    if any(ident_lower.startswith(pfx) for pfx in NON_CREDENTIAL_KEY_PREFIXES):
        return False

    # 4. If identifier contains 'key', require a compound credential pattern with qualifying prefix
    if "key" in ident_lower:
        return bool(COMPOUND_KEY_PATTERN.match(ident_clean))

    # 5. Check credential terms: secret, token, password, credential
    return bool(CREDENTIAL_TERMS_PATTERN.match(ident_clean))


def is_safe_value(val: str) -> bool:
    """Check if the string literal value is an obvious safe pattern (URL, path, dummy, etc.)."""
    val_clean = val.strip()
    val_lower = val_clean.lower()

    # URLs
    if any(val_clean.startswith(prefix) for prefix in SAFE_VALUE_PREFIXES):
        return True

    # Common dummy / template values (exact match)
    if val_lower in DUMMY_VALUES:
        return True

    # Template substring patterns
    if any(dummy in val_lower for dummy in DUMMY_SUBSTRING_PATTERNS):
        return True

    # Too short to be a secure secret
    if len(val_clean) < 12:
        return True

    return False


def is_plausible_secret_value(val: str) -> bool:
    """Validate that a string literal plausibly looks like a secret token or key.
    
    Rejects:
    - Values that are too short (< 16 chars for heuristic matching).
    - Values containing whitespace or delimiters (lists, statements, phrases).
    - Known HTTP header names (Access-Control-*, Content-*, Authorization, etc.).
    - MIME types (application/json, text/html, etc.).
    - Common enum, role, mode, or configuration keywords.
    - Hyphenated / underscored strings containing zero digits (e.g. access-control-allow-origin).
    - Purely alphabetic strings in uniform lowercase, uppercase, or TitleCase.
    - Low-entropy strings or strings with insufficient character diversity.
    - Values lacking multiple character classes (real tokens have mixed casing or letters+numbers).
    """
    val_clean = val.strip()
    val_lower = val_clean.lower()

    # 1. Minimum length threshold for generic heuristic secrets
    if len(val_clean) < 16:
        return False

    # 2. Reject if contains any whitespace or delimiters
    if any(c.isspace() or c in ',;()[]{}\r\n\t' for c in val_clean):
        return False

    # 3. Reject known HTTP headers or header patterns
    if val_lower in KNOWN_HTTP_HEADERS or HTTP_HEADER_PATTERN.match(val_clean):
        return False

    # 4. Reject MIME types
    if MIME_TYPE_PATTERN.match(val_clean):
        return False

    # 5. Reject common enum or configuration keywords
    if val_lower in COMMON_ENUM_VALUES:
        return False

    # 6. Reject hyphenated or underscored strings that contain NO digits
    # (e.g. 'access-control-allow-origin', 'public-read-write', 'content-security-policy')
    if ('-' in val_clean or '_' in val_clean) and not any(c.isdigit() for c in val_clean):
        return False

    # 7. Reject strings that are purely alphabetic and all lowercase, all uppercase, or TitleCase
    if val_clean.isalpha() and (val_clean.islower() or val_clean.isupper() or val_clean.istitle()):
        return False

    # 8. Entropy and character diversity check
    entropy = calculate_shannon_entropy(val_clean)
    unique_ratio = len(set(val_clean)) / len(val_clean)
    if entropy < 3.0 or unique_ratio < 0.3:
        return False

    # 9. Real random secrets have at least 2 character categories (letters + digits, or mixed casing + symbols)
    has_lower = any(c.islower() for c in val_clean)
    has_upper = any(c.isupper() for c in val_clean)
    has_digit = any(c.isdigit() for c in val_clean)
    has_special = any(not c.isalnum() for c in val_clean)
    char_classes = sum([has_lower, has_upper, has_digit, has_special])
    if char_classes < 2:
        return False

    return True


def build_redacted_snippet(
    source_lines: List[str],
    start_row: int,
    end_row: int,
    raw_secret: str,
    redacted_secret: str
) -> str:
    """Extract snippet lines and replace raw secret with redacted version."""
    if start_row < len(source_lines):
        if start_row == end_row:
            line = source_lines[start_row]
            return line.replace(raw_secret, redacted_secret).strip()
        else:
            multiline = "\n".join(source_lines[start_row:min(end_row + 1, len(source_lines))])
            return multiline.replace(raw_secret, redacted_secret).strip()
    return f"... {redacted_secret} ..."


def strip_python_string_quotes(raw_text: str) -> str:
    """Strip string literal quotes and optional prefixes (e.g. f'', b'', r'', '''...''')."""
    val = raw_text.strip()
    for q in ('"""', "'''"):
        m = re.match(r"^[a-zA-Z]{0,3}" + re.escape(q), val)
        if m and val.endswith(q) and len(val) >= len(m.group(0)) + len(q):
            return val[len(m.group(0)):-len(q)]
    for q in ('"', "'"):
        m = re.match(r"^[a-zA-Z]{0,3}" + re.escape(q), val)
        if m and val.endswith(q) and len(val) >= len(m.group(0)) + len(q):
            return val[len(m.group(0)):-len(q)]
    return val


def is_python_docstring_or_comment(node: tree_sitter.Node) -> bool:
    """Check if node is a docstring or standalone string expression statement in Python.
    
    In Python AST, docstrings (module, class, or function) and standalone multiline string
    comments are wrapped directly inside an `expression_statement`.
    """
    curr = node
    while curr.parent and curr.parent.type in ("concatenated_string", "parenthesized_expression"):
        curr = curr.parent
    if curr.parent and curr.parent.type == "expression_statement":
        return True
    return False


def is_python_env_lookup(node: tree_sitter.Node) -> bool:
    """Check if string is an environment variable name lookup (e.g. os.environ[...] or os.getenv(...))."""
    curr = node
    while curr.parent and curr.parent.type in ("parenthesized_expression",):
        curr = curr.parent
    parent = curr.parent
    if not parent:
        return False
    # Subscript: os.environ["SECRET"] or environ["SECRET"]
    if parent.type == "subscript":
        val_node = parent.child_by_field_name("value")
        if val_node:
            t = val_node.text.decode("utf-8", errors="replace").strip()
            if t in ("os.environ", "environ"):
                return True
    # Call: os.getenv("SECRET") or getenv("SECRET") or os.environ.get("SECRET") or environ.get("SECRET")
    if parent.type == "argument_list" and parent.parent and parent.parent.type == "call":
        fn_node = parent.parent.child_by_field_name("function")
        if fn_node:
            t = fn_node.text.decode("utf-8", errors="replace").strip()
            if t in ("os.getenv", "getenv", "os.environ.get", "environ.get"):
                # First positional argument is the environment variable key name
                for child in parent.children:
                    if child.type not in ("(", ")", ","):
                        if child == curr:
                            return True
                        break
    return False


def extract_python_contextual_identifier(node: tree_sitter.Node) -> Optional[str]:
    """Inspect Python AST parent nodes to determine the variable or parameter receiving this string."""
    curr = node
    while curr.parent and curr.parent.type in ("parenthesized_expression",):
        curr = curr.parent
    parent = curr.parent
    if not parent:
        return None

    # 1. Simple assignment: left = right (supports simple, class attr, subscript, and dotted attr)
    if parent.type == "assignment":
        left = parent.child_by_field_name("left")
        right = parent.child_by_field_name("right")
        if left and (curr == right or (right and curr in right.children)):
            if left.type == "identifier":
                return left.text.decode("utf-8", errors="replace")
            elif left.type == "attribute":
                attr_node = left.child_by_field_name("attribute")
                if attr_node:
                    return attr_node.text.decode("utf-8", errors="replace")
                return left.text.decode("utf-8", errors="replace")
            elif left.type == "subscript":
                # e.g. config["db_password"] = "..."
                for child in left.children:
                    if child.type == "string":
                        raw = child.text.decode("utf-8", errors="replace")
                        return strip_python_string_quotes(raw)
                    elif child.type == "identifier" and child != left.child_by_field_name("value"):
                        return child.text.decode("utf-8", errors="replace")

    # 2. Keyword argument: connect(password="...")
    elif parent.type == "keyword_argument":
        val_node = parent.child_by_field_name("value")
        if curr == val_node or (val_node and curr in val_node.children):
            name_node = parent.child_by_field_name("name")
            if name_node:
                return name_node.text.decode("utf-8", errors="replace")

    # 3. Dict entry: {"api_key": "..."}
    elif parent.type == "pair":
        val_node = parent.child_by_field_name("value")
        key_node = parent.child_by_field_name("key")
        if (curr == val_node or (val_node and curr in val_node.children)) and key_node:
            raw = key_node.text.decode("utf-8", errors="replace")
            return strip_python_string_quotes(raw)

    # 4. Default parameter in function def: def login(token="..."):
    elif parent.type in ("default_parameter", "typed_default_parameter"):
        val_node = parent.child_by_field_name("value")
        if curr == val_node or (val_node and curr in val_node.children):
            name_node = parent.child_by_field_name("name")
            if name_node:
                return name_node.text.decode("utf-8", errors="replace")

    return None


def scan_python_source_for_secrets(
    source_code: str,
    file_path: str = "snippet.py"
) -> List[SecretFinding]:
    """Scan Python source code AST for hardcoded secrets.
    
    Returns a list of structured SecretFinding objects with redacted snippets.
    """
    if not source_code or not source_code.strip():
        return []

    parser = tree_sitter.Parser(PYTHON_LANGUAGE)
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    source_lines = source_code.splitlines()

    findings: List[SecretFinding] = []
    seen_matches: Set[Tuple[int, int, str]] = set()

    def visit(node: tree_sitter.Node) -> None:
        if node.type == "string":
            # 1. Skip docstrings or standalone string statements/comments
            if is_python_docstring_or_comment(node):
                return

            # 2. Skip environment variable name lookups
            if is_python_env_lookup(node):
                return

            # 3. Skip if this node is the key of a dictionary pair (never a secret value)
            if node.parent and node.parent.type == "pair" and node == node.parent.child_by_field_name("key"):
                return

            raw_text = node.text.decode("utf-8", errors="replace")
            val = strip_python_string_quotes(raw_text)

            matched = False

            # Check known high-confidence secret signatures
            for sec_type, pattern, title, desc in KNOWN_SECRET_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_secret = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    start_row = node.start_point[0]
                    start_col = node.start_point[1]
                    end_row = node.end_point[0]
                    end_col = node.end_point[1]

                    key = (start_row, start_col, sec_type)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        redacted = redact_secret(matched_secret)
                        snippet = build_redacted_snippet(
                            source_lines, start_row, end_row, matched_secret, redacted
                        )
                        finding_id = str(uuid.uuid5(
                            uuid.NAMESPACE_DNS,
                            f"{file_path}:{start_row}:{start_col}:{sec_type}"
                        ))
                        findings.append(SecretFinding(
                            id=finding_id,
                            file_path=file_path,
                            line_number=start_row + 1,
                            end_line_number=end_row + 1,
                            column=start_col + 1,
                            end_column=end_col + 1,
                            rule_id="HARDCODED_SECRET",
                            severity="CRITICAL",
                            category="Secret Leak",
                            title=title,
                            description=desc,
                            code_snippet=snippet,
                            remediation=REMEDIATION_GUIDANCE,
                            cwe_id="CWE-798",
                            secret_type=sec_type,
                            redacted_value=redacted,
                        ))
                    matched = True
                    break

            # Heuristic check: Suspicious identifier + plausible secret value
            if not matched:
                ident = extract_python_contextual_identifier(node)
                if (
                    ident
                    and not is_safe_identifier(ident)
                    and is_suspicious_credential_identifier(ident)
                    and not is_safe_value(val)
                    and is_plausible_secret_value(val)
                ):
                    start_row = node.start_point[0]
                    start_col = node.start_point[1]
                    end_row = node.end_point[0]
                    end_col = node.end_point[1]

                    sec_type = "GENERIC_HIGH_ENTROPY_SECRET"
                    key = (start_row, start_col, sec_type)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        redacted = redact_secret(val)
                        snippet = build_redacted_snippet(
                            source_lines, start_row, end_row, val, redacted
                        )
                        finding_id = str(uuid.uuid5(
                            uuid.NAMESPACE_DNS,
                            f"{file_path}:{start_row}:{start_col}:{sec_type}"
                        ))
                        findings.append(SecretFinding(
                            id=finding_id,
                            file_path=file_path,
                            line_number=start_row + 1,
                            end_line_number=end_row + 1,
                            column=start_col + 1,
                            end_column=end_col + 1,
                            rule_id="HARDCODED_SECRET",
                            severity="CRITICAL",
                            category="Secret Leak",
                            title=f"Hardcoded Credential Detected ({ident})",
                            description=(
                                f"A high-entropy string literal was assigned to suspicious "
                                f"credential identifier '{ident}'. Hardcoded credentials "
                                "can be leaked via version control or frontend bundles."
                            ),
                            code_snippet=snippet,
                            remediation=REMEDIATION_GUIDANCE,
                            cwe_id="CWE-798",
                            secret_type=sec_type,
                            redacted_value=redacted,
                        ))

        for child in node.children:
            visit(child)

    visit(tree.root_node)
    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings


def scan_source_for_secrets(
    source_code: str,
    file_path: str = "snippet.ts"
) -> List[SecretFinding]:
    """Scan source code AST (JavaScript/TypeScript/Python) for hardcoded secrets.
    
    Returns a list of structured SecretFinding objects with redacted snippets.
    """
    if not source_code or not source_code.strip():
        return []

    lower = file_path.lower()
    if lower.endswith((".py", ".pyw")):
        return scan_python_source_for_secrets(source_code, file_path=file_path)

    parser = get_parser_for_filename(file_path)
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    source_lines = source_code.splitlines()

    findings: List[SecretFinding] = []
    seen_matches: Set[Tuple[int, int, str]] = set()

    def visit(node: tree_sitter.Node) -> None:
        if node.type in ("string", "template_string"):
            raw_text = node.text.decode("utf-8", errors="replace")
            # Strip surrounding quote delimiters
            val = raw_text
            if (val.startswith(('"', "'", "`")) and val.endswith(('"', "'", "`")) and len(val) >= 2):
                val = val[1:-1]

            matched = False

            # 1. Check known high-confidence secret signatures
            for sec_type, pattern, title, desc in KNOWN_SECRET_PATTERNS:
                m = pattern.search(val)
                if m:
                    # In private key regex, group might not have group(1), match whole group(0)
                    matched_secret = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    start_row = node.start_point[0]
                    start_col = node.start_point[1]
                    end_row = node.end_point[0]
                    end_col = node.end_point[1]

                    key = (start_row, start_col, sec_type)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        redacted = redact_secret(matched_secret)
                        snippet = build_redacted_snippet(
                            source_lines, start_row, end_row, matched_secret, redacted
                        )
                        finding_id = str(uuid.uuid5(
                            uuid.NAMESPACE_DNS,
                            f"{file_path}:{start_row}:{start_col}:{sec_type}"
                        ))
                        findings.append(SecretFinding(
                            id=finding_id,
                            file_path=file_path,
                            line_number=start_row + 1,
                            end_line_number=end_row + 1,
                            column=start_col + 1,
                            end_column=end_col + 1,
                            rule_id="HARDCODED_SECRET",
                            severity="CRITICAL",
                            category="Secret Leak",
                            title=title,
                            description=desc,
                            code_snippet=snippet,
                            remediation=REMEDIATION_GUIDANCE,
                            cwe_id="CWE-798",
                            secret_type=sec_type,
                            redacted_value=redacted,
                        ))
                    matched = True
                    break

            # 2. Heuristic check: Suspicious identifier + plausible secret value
            if not matched:
                ident = extract_contextual_identifier(node)
                if (
                    ident
                    and not is_safe_identifier(ident)
                    and is_suspicious_credential_identifier(ident)
                    and not is_safe_value(val)
                    and is_plausible_secret_value(val)
                ):
                    start_row = node.start_point[0]
                    start_col = node.start_point[1]
                    end_row = node.end_point[0]
                    end_col = node.end_point[1]

                    sec_type = "GENERIC_HIGH_ENTROPY_SECRET"
                    key = (start_row, start_col, sec_type)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        redacted = redact_secret(val)
                        snippet = build_redacted_snippet(
                            source_lines, start_row, end_row, val, redacted
                        )
                        finding_id = str(uuid.uuid5(
                            uuid.NAMESPACE_DNS,
                            f"{file_path}:{start_row}:{start_col}:{sec_type}"
                        ))
                        findings.append(SecretFinding(
                            id=finding_id,
                            file_path=file_path,
                            line_number=start_row + 1,
                            end_line_number=end_row + 1,
                            column=start_col + 1,
                            end_column=end_col + 1,
                            rule_id="HARDCODED_SECRET",
                            severity="CRITICAL",
                            category="Secret Leak",
                            title=f"Hardcoded Credential Detected ({ident})",
                            description=(
                                f"A high-entropy string literal was assigned to suspicious "
                                f"credential identifier '{ident}'. Hardcoded credentials "
                                "can be leaked via version control or frontend bundles."
                            ),
                            code_snippet=snippet,
                            remediation=REMEDIATION_GUIDANCE,
                            cwe_id="CWE-798",
                            secret_type=sec_type,
                            redacted_value=redacted,
                        ))

        for child in node.children:
            visit(child)

    visit(tree.root_node)
    # Sort findings by line number then column
    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings
