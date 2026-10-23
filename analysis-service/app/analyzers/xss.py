"""Cross-Site Scripting (XSS) AST Analyzer for JavaScript and TypeScript.

Detects untrusted user input flowing into dangerous DOM sinks (innerHTML, outerHTML,
document.write, insertAdjacentHTML), React dangerouslySetInnerHTML attributes, server-side
reflected response sinks (res.send, res.write), and code execution sinks (eval, Function).
Tracks lexical scopes and variable reassignments while strictly avoiding false positives
on React auto-escaped JSX text and safe static strings.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple
import re
import uuid

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts


# Initialize Tree-sitter Languages
JS_LANGUAGE = tree_sitter.Language(tsjs.language())
TS_LANGUAGE = tree_sitter.Language(tsts.language_typescript())
TSX_LANGUAGE = tree_sitter.Language(tsts.language_tsx())

# Sources of user-controlled input (Express/Koa/Serverless request objects + Browser location)
TAINT_SOURCE_REGEX = re.compile(
    r"^(?:(?:req|request|ctx|event)\.(?:query|body|params|headers|queryStringParameters|pathParameters)"
    r"|(?:window\.|document\.)?location(?:\.(?:search|hash|href|pathname|searchParams))?"
    r")(?:\.[a-zA-Z0-9_$]+|\[.*?\])?$",
    re.IGNORECASE
)

# Known escaping or sanitization functions (judgment call: flagged as lower-confidence / MEDIUM severity)
SANITIZER_PATTERN = re.compile(
    r"(?i)^(?:.*?\.)?(?:escape(?:html|_html)?|sanitize(?:html|_html)?|dompurify\.sanitize|encodeuricomponent|encodeuri|validator\.escape|he\.encode|filterxss|xss)$"
)

# Framework and utility parameters to ignore when inspecting function signatures
FRAMEWORK_PARAM_NAMES = {
    "req", "request", "res", "response", "next", "ctx", "event", "context", "self", "this", "_", "e", "evt"
}


@dataclass
class TaintInfo:
    source_expr: str
    source_line: int
    is_sanitized: bool = False
    sanitizer_name: Optional[str] = None


@dataclass
class XssFinding:
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
    source_expression: str
    source_line: int
    sink_expression: Optional[str]
    sink_line: Optional[int]
    is_sanitized: bool
    sanitizer_name: Optional[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["secret_type"] = None
        d["redacted_value"] = None
        return d


class LexicalScope:
    """Represents a lexical scope for tracking tainted variables."""

    def __init__(self, parent: Optional["LexicalScope"] = None):
        self.parent = parent
        self.tainted_vars: Dict[str, TaintInfo] = {}

    def set_var(self, name: str, taint: TaintInfo) -> None:
        self.tainted_vars[name] = taint

    def get_var(self, name: str) -> Optional[TaintInfo]:
        if name in self.tainted_vars:
            return self.tainted_vars[name]
        if self.parent:
            return self.parent.get_var(name)
        return None


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


def check_expression_taint(
    node: Optional[tree_sitter.Node],
    scope: LexicalScope
) -> Optional[TaintInfo]:
    """Check if an expression AST node resolves to tainted user input."""
    if not node:
        return None

    # 0. TypeScript casts, type assertions, non-null assertions, and await
    if node.type in ("as_expression", "type_assertion", "satisfies_expression", "non_null_expression", "await_expression"):
        for child in node.children:
            if child.type not in ("as", "satisfies", "!", "<", ">", "await", "type_annotation", "predefined_type", "type_identifier"):
                t = check_expression_taint(child, scope)
                if t:
                    return t
        return None

    # 1. Direct member expression (req.query.id, window.location.search, etc.)
    if node.type == "member_expression":
        text = get_node_text(node).replace(" ", "")
        if TAINT_SOURCE_REGEX.match(text):
            return TaintInfo(
                source_expr=text,
                source_line=node.start_point[0] + 1,
                is_sanitized=False,
                sanitizer_name=None
            )
        # Check if base object is tainted (e.g. query.id where query = req.query)
        obj_node = node.child_by_field_name("object")
        if obj_node:
            obj_taint = check_expression_taint(obj_node, scope)
            if obj_taint:
                prop_node = node.child_by_field_name("property")
                prop_name = get_node_text(prop_node) if prop_node else "prop"
                return TaintInfo(
                    source_expr=f"{obj_taint.source_expr}.{prop_name}",
                    source_line=obj_taint.source_line,
                    is_sanitized=obj_taint.is_sanitized,
                    sanitizer_name=obj_taint.sanitizer_name
                )

    # 2. Variable identifier lookup in scope
    if node.type == "identifier":
        name = get_node_text(node)
        if name in ("location",):
            return TaintInfo(
                source_expr=name,
                source_line=node.start_point[0] + 1,
                is_sanitized=False,
                sanitizer_name=None
            )
        return scope.get_var(name)

    # 3. New expression (e.g. new URLSearchParams(window.location.search))
    if node.type == "new_expression":
        ctor_node = node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        if ctor_node and "URLSearchParams" in get_node_text(ctor_node):
            if args_node:
                for arg in args_node.children:
                    if arg.type not in ("(", ")", ","):
                        arg_taint = check_expression_taint(arg, scope)
                        if arg_taint:
                            return TaintInfo(
                                source_expr=f"URLSearchParams({arg_taint.source_expr})",
                                source_line=arg_taint.source_line,
                                is_sanitized=arg_taint.is_sanitized,
                                sanitizer_name=arg_taint.sanitizer_name
                            )
            return TaintInfo(
                source_expr="URLSearchParams",
                source_line=node.start_point[0] + 1,
                is_sanitized=False,
                sanitizer_name=None
            )

    # 4. Call expression (sanitizers, URLSearchParams methods, string methods)
    if node.type == "call_expression":
        fn_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if fn_node and args_node:
            fn_text = get_node_text(fn_node).replace(" ", "")

            # Check if this call is an escaping/sanitizer function
            if SANITIZER_PATTERN.match(fn_text):
                for arg in args_node.children:
                    if arg.type not in ("(", ")", ","):
                        inner_taint = check_expression_taint(arg, scope)
                        if inner_taint:
                            return TaintInfo(
                                source_expr=inner_taint.source_expr,
                                source_line=inner_taint.source_line,
                                is_sanitized=True,
                                sanitizer_name=fn_text
                            )

            # Check method calls on tainted objects (e.g. urlParams.get('q'), str.trim())
            if fn_node.type == "member_expression":
                obj_node = fn_node.child_by_field_name("object")
                prop_node = fn_node.child_by_field_name("property")
                if obj_node and prop_node:
                    prop_name = get_node_text(prop_node)
                    obj_taint = check_expression_taint(obj_node, scope)
                    if obj_taint:
                        taint_preserving_methods = {
                            "get", "getAll", "trim", "toLowerCase", "toUpperCase",
                            "slice", "substring", "substr", "toString", "valueOf", "concat"
                        }
                        if prop_name in taint_preserving_methods:
                            return TaintInfo(
                                source_expr=f"{obj_taint.source_expr}.{prop_name}()",
                                source_line=obj_taint.source_line,
                                is_sanitized=obj_taint.is_sanitized,
                                sanitizer_name=obj_taint.sanitizer_name
                            )

    # 5. Template literal: `Hello ${userInput}`
    if node.type == "template_string":
        for child in node.children:
            if child.type == "template_substitution":
                for sub in child.children:
                    if sub.type not in ("${", "}"):
                        t = check_expression_taint(sub, scope)
                        if t:
                            return t

    # 6. Binary expression (+): "prefix" + taintedVar
    if node.type == "binary_expression":
        op_node = node.child_by_field_name("operator")
        if op_node and get_node_text(op_node) == "+":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            left_taint = check_expression_taint(left, scope) if left else None
            right_taint = check_expression_taint(right, scope) if right else None
            if left_taint and not left_taint.is_sanitized:
                return left_taint
            if right_taint and not right_taint.is_sanitized:
                return right_taint
            return left_taint or right_taint

    # 7. Parenthesized expression: (expr)
    if node.type == "parenthesized_expression":
        for child in node.children:
            if child.type not in ("(", ")"):
                return check_expression_taint(child, scope)

    return None


def extract_param_names(params_node: tree_sitter.Node) -> List[Tuple[str, int]]:
    """Extract formal parameter names from a function parameter list."""
    result = []
    for child in params_node.children:
        line = child.start_point[0] + 1
        if child.type == "identifier":
            p_name = get_node_text(child)
            if p_name.lower() not in FRAMEWORK_PARAM_NAMES:
                result.append((p_name, line))
        elif child.type in ("required_parameter", "optional_parameter"):
            for sub in child.children:
                if sub.type == "identifier":
                    p_name = get_node_text(sub)
                    if p_name.lower() not in FRAMEWORK_PARAM_NAMES:
                        result.append((p_name, line))
                elif sub.type == "object_pattern":
                    for prop in sub.children:
                        if prop.type == "shorthand_property_identifier_pattern":
                            p_name = get_node_text(prop)
                            if p_name.lower() not in FRAMEWORK_PARAM_NAMES:
                                result.append((p_name, line))
                        elif prop.type == "pair_pattern":
                            val_pat = prop.child_by_field_name("value")
                            if val_pat:
                                p_name = get_node_text(val_pat)
                                if p_name.lower() not in FRAMEWORK_PARAM_NAMES:
                                    result.append((p_name, line))
    return result


def make_xss_finding(
    line: int,
    col: int,
    end_line: int,
    end_col: int,
    taint: TaintInfo,
    sink_expr: str,
    sink_line: int,
    rule_id: str,
    source_lines: List[str],
    file_path: str,
    findings: List[XssFinding]
):
    """Build and record a structured XssFinding."""
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{line}:{col}:{rule_id}"))
    snippet = ""
    if 0 <= line - 1 < len(source_lines):
        snippet = source_lines[line - 1].strip()

    is_sanitized = taint.is_sanitized
    sanitizer_name = taint.sanitizer_name

    if is_sanitized:
        severity = "MEDIUM"
        title = f"Potential Cross-Site Scripting ({sink_expr} - Sanitizer Detected)"
        remediation = (
            "A sanitizer was detected, but output context should be verified. Ensure sanitization "
            "library (e.g. DOMPurify) is properly configured with safe tags/attributes, and consider "
            "using safe contextual DOM APIs or textContent instead of HTML parsing."
        )
        desc = (
            f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
            f"sanitizer '{sanitizer_name}' before reaching dangerous sink '{sink_expr}' on line {sink_line}. "
            "Manual review is recommended to ensure the sanitizer handles all contextual injection vectors."
        )
    else:
        severity = "CRITICAL"
        if rule_id == "XSS_DOM":
            title = f"Cross-Site Scripting (DOM XSS) via {sink_expr}"
            desc = (
                f"Untrusted user input from line {taint.source_line} ('{taint.source_expr}') "
                f"flows directly into dangerous DOM sink '{sink_expr}' on line {sink_line} without sanitization."
            )
            remediation = (
                "Avoid assigning untrusted data directly to innerHTML/outerHTML or document.write. "
                "Use textContent or safe DOM manipulation methods, or sanitize untrusted HTML using a vetted library like DOMPurify."
            )
        elif rule_id == "XSS_REACT":
            title = "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML"
            desc = (
                f"Untrusted user input from line {taint.source_line} ('{taint.source_expr}') "
                f"is assigned to 'dangerouslySetInnerHTML' on line {sink_line} without sanitization."
            )
            remediation = (
                "Avoid dangerouslySetInnerHTML when handling untrusted data. Use standard React JSX text "
                "rendering (e.g., <div>{userInput}</div>) which automatically escapes HTML entities, or pass the markup through DOMPurify.sanitize()."
            )
        elif rule_id == "XSS_REFLECTED":
            title = f"Reflected Cross-Site Scripting (XSS) via {sink_expr}"
            desc = (
                f"Untrusted user input from line {taint.source_line} ('{taint.source_expr}') "
                f"is reflected directly into HTTP response via '{sink_expr}' on line {sink_line} without HTML entity escaping."
            )
            remediation = (
                "Do not reflect untrusted user input directly in HTTP response bodies. Apply contextual HTML entity encoding "
                "(e.g., using escape-html or he) or set Content-Type header to 'application/json' or 'text/plain'."
            )
        else:  # CODE_INJECTION_EVAL
            title = f"Code Injection / Execution via {sink_expr}"
            desc = (
                f"Untrusted user input from line {taint.source_line} ('{taint.source_expr}') "
                f"is passed to code evaluation sink '{sink_expr}' on line {sink_line}."
            )
            remediation = (
                "Never pass untrusted input to eval() or Function() constructor. Use safe structured data parsers like JSON.parse()."
            )

    findings.append(XssFinding(
        id=finding_id,
        file_path=file_path,
        line_number=line,
        end_line_number=end_line,
        column=col,
        end_column=end_col,
        rule_id=rule_id,
        severity=severity,
        category="Cross-Site Scripting",
        title=title,
        description=desc,
        code_snippet=snippet,
        remediation=remediation,
        cwe_id="CWE-79",
        source_expression=taint.source_expr,
        source_line=taint.source_line,
        sink_expression=sink_expr,
        sink_line=sink_line,
        is_sanitized=is_sanitized,
        sanitizer_name=sanitizer_name,
    ))


def scan_source_for_xss(
    source_code: str,
    file_path: str = "snippet.ts"
) -> List[XssFinding]:
    """Scan JavaScript/TypeScript/TSX source code AST for Cross-Site Scripting (XSS) vulnerabilities."""
    if not source_code or not source_code.strip():
        return []

    if file_path.lower().endswith((".py", ".pyw")):
        from app.analyzers.python_xss import scan_python_source_for_xss
        return scan_python_source_for_xss(source_code, file_path=file_path)

    parser = get_parser_for_filename(file_path)
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    source_lines = source_code.splitlines()

    findings: List[XssFinding] = []
    recorded_locations: Set[Tuple[int, int, str]] = set()

    SCOPE_CREATORS = {
        "program", "function_declaration", "function_expression",
        "arrow_function", "method_definition", "statement_block"
    }

    def walk_ast(node: tree_sitter.Node, current_scope: LexicalScope):
        # Create a nested scope for blocks and functions
        if node.type in SCOPE_CREATORS and node.type != "program":
            scope = LexicalScope(parent=current_scope)
        else:
            scope = current_scope

        # Track user-supplied function parameters as potential taint sources
        if node.type in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
            params_node = node.child_by_field_name("parameters")
            if params_node:
                for p_name, p_line in extract_param_names(params_node):
                    scope.set_var(p_name, TaintInfo(
                        source_expr=f"param '{p_name}'",
                        source_line=p_line,
                        is_sanitized=False
                    ))

        # 1. Variable declarator: const x = ...
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

            if name_node and value_node:
                # Handle destructuring: const { q, id } = req.query;
                if name_node.type == "object_pattern":
                    val_taint = check_expression_taint(value_node, scope)
                    val_text = get_node_text(value_node).replace(" ", "")
                    is_req_source = bool(TAINT_SOURCE_REGEX.match(val_text))

                    if val_taint or is_req_source:
                        source_base = val_taint.source_expr if val_taint else val_text
                        source_line = val_taint.source_line if val_taint else node.start_point[0] + 1
                        for prop in name_node.children:
                            if prop.type == "shorthand_property_identifier_pattern":
                                p_name = get_node_text(prop)
                                scope.set_var(p_name, TaintInfo(
                                    source_expr=f"{source_base}.{p_name}",
                                    source_line=source_line,
                                    is_sanitized=val_taint.is_sanitized if val_taint else False,
                                    sanitizer_name=val_taint.sanitizer_name if val_taint else None
                                ))
                            elif prop.type == "pair_pattern":
                                val_pattern = prop.child_by_field_name("value")
                                key_pattern = prop.child_by_field_name("key")
                                if val_pattern and key_pattern:
                                    scope.set_var(get_node_text(val_pattern), TaintInfo(
                                        source_expr=f"{source_base}.{get_node_text(key_pattern)}",
                                        source_line=source_line,
                                        is_sanitized=val_taint.is_sanitized if val_taint else False,
                                        sanitizer_name=val_taint.sanitizer_name if val_taint else None
                                    ))

                # Standard variable declaration: const x = ...
                elif name_node.type == "identifier":
                    var_name = get_node_text(name_node)
                    taint = check_expression_taint(value_node, scope)
                    if taint:
                        scope.set_var(var_name, taint)

                    # Also check if value_node is an object literal holding `{ __html: <tainted> }`
                    elif value_node.type == "object":
                        for child in value_node.children:
                            if child.type == "pair":
                                key_n = child.child_by_field_name("key")
                                val_n = child.child_by_field_name("value")
                                if key_n and get_node_text(key_n) in ("__html", "html"):
                                    pair_taint = check_expression_taint(val_n, scope)
                                    if pair_taint:
                                        scope.set_var(var_name, pair_taint)
                                        break

        # 2. Assignment expression: x = ...
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")

            if left_node and right_node:
                # SINK A: DOM innerHTML / outerHTML assignment (e.g. el.innerHTML = tainted)
                if left_node.type == "member_expression":
                    prop_node = left_node.child_by_field_name("property")
                    if prop_node:
                        prop_name = get_node_text(prop_node)
                        if prop_name in ("innerHTML", "outerHTML"):
                            taint = check_expression_taint(right_node, scope)
                            if taint:
                                line = node.start_point[0] + 1
                                col = node.start_point[1] + 1
                                key = (line, col, "XSS_DOM")
                                if key not in recorded_locations:
                                    recorded_locations.add(key)
                                    make_xss_finding(
                                        line=line,
                                        col=col,
                                        end_line=node.end_point[0] + 1,
                                        end_col=node.end_point[1] + 1,
                                        taint=taint,
                                        sink_expr=get_node_text(left_node),
                                        sink_line=line,
                                        rule_id="XSS_DOM",
                                        source_lines=source_lines,
                                        file_path=file_path,
                                        findings=findings
                                    )

                # Reassignment to variable identifier: x = tainted
                if left_node.type == "identifier":
                    var_name = get_node_text(left_node)
                    taint = check_expression_taint(right_node, scope)
                    if taint:
                        scope.set_var(var_name, taint)

        # 3. React JSX Attribute: dangerouslySetInnerHTML={{ __html: ... }}
        elif node.type == "jsx_attribute":
            prop_ident = None
            for child in node.children:
                if child.type in ("property_identifier", "jsx_identifier"):
                    prop_ident = get_node_text(child)
                    break

            if prop_ident == "dangerouslySetInnerHTML":
                taint = None
                for child in node.children:
                    if child.type == "jsx_expression":
                        for sub in child.children:
                            if sub.type == "object":
                                for pair in sub.children:
                                    if pair.type == "pair":
                                        k = pair.child_by_field_name("key")
                                        v = pair.child_by_field_name("value")
                                        if k and get_node_text(k) in ("__html", "html"):
                                            taint = check_expression_taint(v, scope)
                                            if taint:
                                                break
                            elif sub.type == "identifier":
                                # Passing object variable: dangerouslySetInnerHTML={markup}
                                taint = scope.get_var(get_node_text(sub))
                            elif sub.type in ("call_expression", "as_expression"):
                                taint = check_expression_taint(sub, scope)
                    elif child.type == "identifier":
                        taint = scope.get_var(get_node_text(child))

                    if taint:
                        line = node.start_point[0] + 1
                        col = node.start_point[1] + 1
                        key = (line, col, "XSS_REACT")
                        if key not in recorded_locations:
                            recorded_locations.add(key)
                            make_xss_finding(
                                line=line,
                                col=col,
                                end_line=node.end_point[0] + 1,
                                end_col=node.end_point[1] + 1,
                                taint=taint,
                                sink_expr="dangerouslySetInnerHTML",
                                sink_line=line,
                                rule_id="XSS_REACT",
                                source_lines=source_lines,
                                file_path=file_path,
                                findings=findings
                            )

        # 4. Call expressions: DOM write / insertAdjacentHTML / res.send / eval
        elif node.type in ("call_expression", "new_expression"):
            fn_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            args_node = node.child_by_field_name("arguments")

            if fn_node and args_node:
                fn_text = get_node_text(fn_node).replace(" ", "")
                arg_nodes = [c for c in args_node.children if c.type not in ("(", ")", ",")]

                # SINK B: document.write / document.writeln
                if re.search(r"(?:^|\.)(?:document\.)?(?:write|writeln)$", fn_text, re.IGNORECASE):
                    if arg_nodes:
                        taint = check_expression_taint(arg_nodes[0], scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            key = (line, col, "XSS_DOM")
                            if key not in recorded_locations:
                                recorded_locations.add(key)
                                make_xss_finding(
                                    line=line,
                                    col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="XSS_DOM",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK C: element.insertAdjacentHTML('beforeend', html)
                elif re.search(r"(?:^|\.)insertAdjacentHTML$", fn_text, re.IGNORECASE):
                    if len(arg_nodes) >= 2:
                        taint = check_expression_taint(arg_nodes[1], scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            key = (line, col, "XSS_DOM")
                            if key not in recorded_locations:
                                recorded_locations.add(key)
                                make_xss_finding(
                                    line=line,
                                    col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="XSS_DOM",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK D: Server-side Reflected XSS: res.send(...) / res.write(...)
                elif re.search(r"^(?:res|response|reply|ctx\.response|ctx\.res)\.(?:send|write)$", fn_text, re.IGNORECASE):
                    if arg_nodes:
                        taint = check_expression_taint(arg_nodes[0], scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            key = (line, col, "XSS_REFLECTED")
                            if key not in recorded_locations:
                                recorded_locations.add(key)
                                make_xss_finding(
                                    line=line,
                                    col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="XSS_REFLECTED",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK E: Code Injection / Eval constructor: eval(...) / Function(...)
                elif re.search(r"^(?:window\.)?(?:eval|Function)$", fn_text):
                    for arg in arg_nodes:
                        taint = check_expression_taint(arg, scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            key = (line, col, "CODE_INJECTION_EVAL")
                            if key not in recorded_locations:
                                recorded_locations.add(key)
                                make_xss_finding(
                                    line=line,
                                    col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="CODE_INJECTION_EVAL",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )
                            break

        # Recursively traverse children
        for child in node.children:
            walk_ast(child, scope)

    root_scope = LexicalScope()
    walk_ast(tree.root_node, root_scope)

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings
