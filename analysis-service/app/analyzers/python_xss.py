"""Cross-Site Scripting (XSS) and Server-Side Template Injection (SSTI) AST Analyzer for Python.

Detects untrusted user input flowing into:
1. Server-Side Template Injection (SSTI): Flask render_template_string(template_string, ...)
   where the template string itself contains tainted input via f-string, concatenation (+ or %),
   or .format(). Context variables passed via kwargs to render_template_string or render_template
   are auto-escaped and strictly ignored.
2. Auto-escaping Bypasses:
   - flask.Markup(tainted) / markupsafe.Markup(tainted)
   - django.utils.safestring.mark_safe(tainted)
   - Medium severity downgrade when passed through escaping functions (markupsafe.escape, bleach.clean, html.escape)
3. Dynamic Code Execution:
   - eval(tainted) / exec(tainted)
"""

from typing import Dict, List, Optional, Set, Tuple
import re
import uuid

import tree_sitter
import tree_sitter_python as tspy

from app.analyzers.xss import XssFinding, TaintInfo

# Initialize Python Tree-sitter Language
PYTHON_LANGUAGE = tree_sitter.Language(tspy.language())

# Sources of user-controlled input (Flask/WSGI request objects)
TAINT_SOURCE_PATTERN = re.compile(
    r"^(?:req|request)\.(?:args|form|values|GET|POST|json|headers|cookies|data)(?:\.[a-zA-Z0-9_$]+)?$"
)

# Known escaping or sanitization functions (downgrades severity to MEDIUM with is_sanitized=True)
SANITIZER_PATTERN = re.compile(
    r"(?i)^(?:.*?\.)?(?:escape|clean|linkify|html_escape|markupsafe\.escape|bleach\.clean|bleach\.linkify|html\.escape|django\.utils\.html\.escape)$"
)

# FastAPI route handler decorators
FASTAPI_ROUTE_DECORATOR_PATTERN = re.compile(
    r"(?i)^@(?:app|router|api_router|bp|blueprint)\.(?:get|post|put|delete|patch|options|head|route|api_route)\b"
)

# Framework and utility parameters to ignore when inspecting route signatures
FRAMEWORK_PARAM_NAMES = {
    "self", "cls", "request", "req", "response", "res", "db", "session", "current_user", "_"
}

# Sink function regexes
SSTI_SINKS = re.compile(r"^(?:(?:flask\.)?render_template_string)$")
MARKUP_SINKS = re.compile(r"^(?:flask\.|markupsafe\.|jinja2\.)?Markup$")
MARK_SAFE_SINKS = re.compile(r"^(?:django\.utils\.safestring\.)?mark_safe$")
EVAL_SINKS = re.compile(r"^(?:builtins\.)?(?:eval|exec)$")


class PythonXssLexicalScope:
    """Represents a lexical scope for tracking tainted variables, templates, and static strings."""

    def __init__(self, parent: Optional["PythonXssLexicalScope"] = None):
        self.parent = parent
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.static_vars: Dict[str, str] = {}

    def set_var(self, name: str, taint: Optional[TaintInfo]) -> None:
        if taint:
            self.tainted_vars[name] = taint
            if name in self.static_vars:
                del self.static_vars[name]
        else:
            if name in self.tainted_vars:
                del self.tainted_vars[name]

    def get_var(self, name: str) -> Optional[TaintInfo]:
        if name in self.tainted_vars:
            return self.tainted_vars[name]
        if self.parent:
            return self.parent.get_var(name)
        return None

    def set_static(self, name: str, val: str) -> None:
        self.static_vars[name] = val
        if name in self.tainted_vars:
            del self.tainted_vars[name]

    def is_static(self, name: str) -> bool:
        if name in self.static_vars:
            return True
        if self.parent:
            return self.parent.is_static(name)
        return False


def get_node_text(node: tree_sitter.Node) -> str:
    """Retrieve decoded text for an AST node."""
    return node.text.decode("utf-8", errors="replace")


def is_fstring(node: tree_sitter.Node) -> bool:
    """Determine whether a string node is an interpolated f-string."""
    if node.type == "string":
        return any(child.type == "interpolation" for child in node.children)
    if node.type == "concatenated_string":
        return any(is_fstring(child) for child in node.children)
    return False


def check_expression_taint(node: Optional[tree_sitter.Node], scope: PythonXssLexicalScope) -> Optional[TaintInfo]:
    """Check if an expression AST node directly resolves to tainted user input."""
    if node is None:
        return None

    # 1. Identifier lookup in scope
    if node.type == "identifier":
        name = get_node_text(node)
        return scope.get_var(name)

    # 2. Attribute access: request.args, req.form, request.GET, etc.
    if node.type == "attribute":
        text = get_node_text(node).replace(" ", "")
        if TAINT_SOURCE_PATTERN.match(text):
            return TaintInfo(source_expr=text, source_line=node.start_point[0] + 1)
        obj = node.child_by_field_name("object")
        if obj:
            obj_taint = check_expression_taint(obj, scope)
            if obj_taint:
                return obj_taint

    # 3. Subscript: sys.argv[1], request.args['id'], request.form['key'], etc.
    if node.type == "subscript":
        val_node = node.child_by_field_name("value")
        if val_node:
            val_text = get_node_text(val_node).replace(" ", "")
            if val_text in ("sys.argv", "argv"):
                return TaintInfo(source_expr=get_node_text(node), source_line=node.start_point[0] + 1)
            if TAINT_SOURCE_PATTERN.match(val_text):
                return TaintInfo(source_expr=get_node_text(node), source_line=node.start_point[0] + 1)
            val_taint = check_expression_taint(val_node, scope)
            if val_taint:
                return val_taint

    # 4. Call expression
    if node.type == "call":
        fn_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if fn_node:
            fn_text = get_node_text(fn_node).replace(" ", "")
            # input()
            if fn_text == "input":
                return TaintInfo(source_expr="input()", source_line=node.start_point[0] + 1)
            # request.args.get(...), request.json.get(...), request.form.get(...), etc.
            if re.match(r"^(?:req|request)\.(?:args|form|values|GET|POST|json|headers)\.get$", fn_text):
                return TaintInfo(source_expr=get_node_text(node), source_line=node.start_point[0] + 1)
            # Sanitizers: escape(), clean(), markupsafe.escape(), bleach.clean(), etc.
            if SANITIZER_PATTERN.match(fn_text) and args_node:
                for arg in args_node.children:
                    if arg.type not in ("(", ")", ","):
                        check_node = arg.child_by_field_name("value") if arg.type == "keyword_argument" else arg
                        inner_t = check_expression_taint(check_node, scope)
                        if inner_t:
                            return TaintInfo(
                                source_expr=inner_t.source_expr,
                                source_line=inner_t.source_line,
                                is_sanitized=True,
                                sanitizer_name=fn_text
                            )
            # String formatting: "...".format(tainted)
            if fn_node.type == "attribute":
                attr_name = fn_node.child_by_field_name("attribute")
                if attr_name and get_node_text(attr_name) == "format" and args_node:
                    for arg in args_node.children:
                        if arg.type not in ("(", ")", ","):
                            check_node = arg.child_by_field_name("value") if arg.type == "keyword_argument" else arg
                            inner_t = check_expression_taint(check_node, scope)
                            if inner_t:
                                return inner_t

    # 5. Binary operator (+ or %)
    if node.type == "binary_operator":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op_text = ""
        for child in node.children:
            if child not in (left, right) and child.type in ("+", "%"):
                op_text = child.type
                break
        if op_text in ("+", "%"):
            left_t = check_expression_taint(left, scope) if left else None
            right_t = check_expression_taint(right, scope) if right else None
            if left_t and not left_t.is_sanitized:
                return left_t
            if right_t and not right_t.is_sanitized:
                return right_t
            return left_t or right_t

    # 6. F-string (string with interpolation)
    if is_fstring(node):
        for child in node.children:
            if child.type == "interpolation":
                expr_node = child.child_by_field_name("expression")
                if not expr_node:
                    for sub in child.children:
                        if sub.type not in ("{", "}"):
                            expr_node = sub
                            break
                if expr_node:
                    t = check_expression_taint(expr_node, scope)
                    if t:
                        return t
            elif child.type == "concatenated_string":
                t = check_expression_taint(child, scope)
                if t:
                    return t

    # 7. Concatenated string (adjacent strings in parens)
    if node.type == "concatenated_string":
        for child in node.children:
            t = check_expression_taint(child, scope)
            if t:
                return t

    # 8. Parenthesized expression
    if node.type == "parenthesized_expression":
        for child in node.children:
            if child.type not in ("(", ")"):
                return check_expression_taint(child, scope)

    return None


def has_tainted_expression(node: Optional[tree_sitter.Node], scope: PythonXssLexicalScope) -> Optional[TaintInfo]:
    """Recursively checks if node or any of its sub-expressions contains tainted input."""
    if node is None:
        return None

    t = check_expression_taint(node, scope)
    if t:
        return t

    if is_fstring(node):
        for child in node.children:
            if child.type == "interpolation":
                t = has_tainted_expression(child, scope)
                if t:
                    return t

    if node.type == "binary_operator":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        t_left = has_tainted_expression(left, scope) if left else None
        if t_left and not t_left.is_sanitized:
            return t_left
        t_right = has_tainted_expression(right, scope) if right else None
        if t_right and not t_right.is_sanitized:
            return t_right
        return t_left or t_right

    if node.type in ("list", "tuple", "set"):
        for child in node.children:
            if child.type not in ("[", "]", "(", ")", "{", "}", ","):
                t = has_tainted_expression(child, scope)
                if t:
                    return t

    if node.type == "keyword_argument":
        val = node.child_by_field_name("value")
        return has_tainted_expression(val, scope)

    return None


def extract_python_params(parameters_node: tree_sitter.Node) -> List[Tuple[str, int]]:
    """Extract formal parameter names from a Python parameter list."""
    results = []
    for child in parameters_node.children:
        p_name = None
        line = child.start_point[0] + 1
        if child.type == "identifier":
            p_name = get_node_text(child)
        elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
            if child.type in ("default_parameter", "typed_default_parameter"):
                val = child.child_by_field_name("value")
                if val and "Depends(" in get_node_text(val):
                    continue
            for sub in child.children:
                if sub.type == "identifier":
                    p_name = get_node_text(sub)
                    break
        if p_name and p_name.lower() not in FRAMEWORK_PARAM_NAMES:
            results.append((p_name, line))
    return results


def make_xss_finding(
    line: int, col: int, end_line: int, end_col: int,
    taint: TaintInfo,
    sink_expr: str,
    sink_line: int,
    rule_id: str,
    cwe_id: str,
    source_lines: List[str],
    file_path: str,
    findings: List[XssFinding]
):
    """Build and append a structured XssFinding for Python."""
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{line}:{col}:{rule_id}"))
    snippet = ""
    if 0 <= line - 1 < len(source_lines):
        snippet = source_lines[line - 1].strip()

    is_sanitized = taint.is_sanitized
    sanitizer_name = taint.sanitizer_name

    if rule_id == "SSTI_RENDER_TEMPLATE_STRING":
        if is_sanitized:
            severity = "MEDIUM"
            title = "Potential SSTI in render_template_string (Sanitizer Detected - Review Required)"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
                f"sanitizer '{sanitizer_name}' before being interpolated into render_template_string() on line {line}."
            )
        else:
            severity = "CRITICAL"
            title = "Server-Side Template Injection (SSTI) in render_template_string"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is dynamically interpolated "
                f"into a template string passed to render_template_string() on line {line}. This leads to Server-Side "
                f"Template Injection (SSTI) and potential remote code execution in Jinja2."
            )
        remediation = (
            "Do not interpolate untrusted user input directly into template strings. Pass dynamic data as context "
            "variables (e.g. render_template_string('<h1>{{ name }}</h1>', name=user_input)) where Jinja2 "
            "automatically escapes variables, or use render_template() with static template files."
        )

    elif rule_id == "XSS_MARKUP_BYPASS":
        if is_sanitized:
            severity = "MEDIUM"
            title = "Potential XSS (Sanitizer Detected in Markup - Review Required)"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
                f"sanitizer '{sanitizer_name}' before being wrapped in Markup() on line {line}."
            )
        else:
            severity = "CRITICAL"
            title = "Cross-Site Scripting (XSS) via Markup() Autoescaping Bypass"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is wrapped in Markup() "
                f"on line {line}, disabling Jinja2's auto-escaping mechanism and exposing the application to Cross-Site Scripting (XSS)."
            )
        remediation = (
            "Do not wrap untrusted user input in Markup(). Allow Jinja2 to automatically escape variables "
            "in templates, or use a robust HTML sanitizer like bleach.clean() if raw HTML input must be supported."
        )

    elif rule_id == "XSS_MARK_SAFE":
        if is_sanitized:
            severity = "MEDIUM"
            title = "Potential XSS (Sanitizer Detected in mark_safe - Review Required)"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
                f"sanitizer '{sanitizer_name}' before being passed to mark_safe() on line {line}."
            )
        else:
            severity = "CRITICAL"
            title = "Cross-Site Scripting (XSS) via mark_safe() Autoescaping Bypass"
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is passed to mark_safe() "
                f"on line {line}, disabling Django's auto-escaping and creating a Cross-Site Scripting (XSS) vulnerability."
            )
        remediation = (
            "Do not mark untrusted user input as safe with mark_safe(). Allow Django's template engine to auto-escape "
            "values, or use a sanitizer such as bleach.clean() before rendering."
        )

    elif rule_id == "CODE_INJECTION_EVAL":
        severity = "CRITICAL"
        title = f"Code Injection Vulnerability via {sink_expr}()"
        desc = (
            f"Untrusted user input from line {taint.source_line} ('{taint.source_expr}') is passed to "
            f"dynamic evaluation function '{sink_expr}()' on line {line}. This allows arbitrary code execution."
        )
        remediation = (
            f"Never pass untrusted user input to {sink_expr}(). Use safe serialization formats such as JSON "
            "or ast.literal_eval() for data evaluation."
        )
    else:
        severity = "CRITICAL"
        title = f"Cross-Site Scripting via {sink_expr}"
        desc = f"Untrusted user input from line {taint.source_line} reaches dangerous sink '{sink_expr}'."
        remediation = "Sanitize user input or use safe template rendering."

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
        cwe_id=cwe_id,
        source_expression=taint.source_expr,
        source_line=taint.source_line,
        sink_expression=sink_expr,
        sink_line=sink_line,
        is_sanitized=is_sanitized,
        sanitizer_name=sanitizer_name
    ))


def scan_python_source_for_xss(
    source_code: str,
    file_path: str = "snippet.py"
) -> List[XssFinding]:
    """Scan Python source code AST for Cross-Site Scripting and Template Injection vulnerabilities."""
    if not source_code or not source_code.strip():
        return []

    parser = tree_sitter.Parser(PYTHON_LANGUAGE)
    tree = parser.parse(source_code.encode("utf-8"))
    source_lines = source_code.splitlines()

    findings: List[XssFinding] = []
    recorded_locations: Set[Tuple[int, int, str]] = set()

    SCOPE_CREATORS = {
        "function_definition", "async_function_definition", "class_definition"
    }

    def walk_ast(node: tree_sitter.Node, current_scope: PythonXssLexicalScope):
        if node.type in SCOPE_CREATORS:
            scope = PythonXssLexicalScope(parent=current_scope)
        else:
            scope = current_scope

        # Check FastAPI route handlers
        if node.type == "decorated_definition":
            is_fastapi_route = False
            for child in node.children:
                if child.type == "decorator":
                    dec_text = get_node_text(child).replace(" ", "")
                    if FASTAPI_ROUTE_DECORATOR_PATTERN.match(dec_text):
                        is_fastapi_route = True
                        break
            if is_fastapi_route:
                fn_def = None
                for child in node.children:
                    if child.type in ("function_definition", "async_function_definition"):
                        fn_def = child
                        break
                if fn_def:
                    params = fn_def.child_by_field_name("parameters")
                    if params:
                        for p_name, p_line in extract_python_params(params):
                            scope.set_var(p_name, TaintInfo(
                                source_expr=f"FastAPI param '{p_name}'",
                                source_line=p_line
                            ))

        # Handle assignments: x = ...
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and left.type == "identifier":
                var_name = get_node_text(left)
                if right.type == "string" and not is_fstring(right):
                    scope.set_static(var_name, get_node_text(right))
                else:
                    taint = check_expression_taint(right, scope)
                    if not taint:
                        taint = has_tainted_expression(right, scope)
                    if taint:
                        scope.set_var(var_name, taint)
                    else:
                        scope.set_var(var_name, None)

        # Sinks: Call expressions
        elif node.type == "call":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn and args_node:
                fn_text = get_node_text(fn).replace(" ", "")

                # Parse positional and keyword arguments
                positional_args = []
                keyword_args: Dict[str, tree_sitter.Node] = {}
                for arg in args_node.children:
                    if arg.type in ("(", ")", ","):
                        continue
                    if arg.type == "keyword_argument":
                        k_name = arg.child_by_field_name("name")
                        k_val = arg.child_by_field_name("value")
                        if k_name and k_val:
                            keyword_args[get_node_text(k_name)] = k_val
                    else:
                        positional_args.append(arg)

                # SINK 1: SSTI: render_template_string(...)
                # In render_template_string, the template string is either the first positional arg
                # or explicitly passed via keyword arg 'template_string' or 'source' or 'template'.
                # All OTHER keyword arguments (e.g. name=user) are context kwargs and are SAFE in Jinja2!
                # render_template("file.html", ...) is strictly ignored (loads safe file).
                if SSTI_SINKS.match(fn_text):
                    target_tmpl = None
                    if positional_args:
                        target_tmpl = positional_args[0]
                    elif "template_string" in keyword_args:
                        target_tmpl = keyword_args["template_string"]
                    elif "source" in keyword_args:
                        target_tmpl = keyword_args["source"]
                    elif "template" in keyword_args:
                        target_tmpl = keyword_args["template"]

                    if target_tmpl:
                        taint = check_expression_taint(target_tmpl, scope)
                        if not taint:
                            taint = has_tainted_expression(target_tmpl, scope)

                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            loc_key = (line, col, "SSTI_RENDER_TEMPLATE_STRING")
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_xss_finding(
                                    line=line, col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="SSTI_RENDER_TEMPLATE_STRING",
                                    cwe_id="CWE-1336",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK 2: Markup(...) autoescaping bypass
                elif MARKUP_SINKS.match(fn_text):
                    target_arg = positional_args[0] if positional_args else (list(keyword_args.values())[0] if keyword_args else None)
                    if target_arg:
                        taint = check_expression_taint(target_arg, scope)
                        if not taint:
                            taint = has_tainted_expression(target_arg, scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            loc_key = (line, col, "XSS_MARKUP_BYPASS")
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_xss_finding(
                                    line=line, col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="XSS_MARKUP_BYPASS",
                                    cwe_id="CWE-79",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK 3: mark_safe(...) autoescaping bypass
                elif MARK_SAFE_SINKS.match(fn_text):
                    target_arg = positional_args[0] if positional_args else (list(keyword_args.values())[0] if keyword_args else None)
                    if target_arg:
                        taint = check_expression_taint(target_arg, scope)
                        if not taint:
                            taint = has_tainted_expression(target_arg, scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            loc_key = (line, col, "XSS_MARK_SAFE")
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_xss_finding(
                                    line=line, col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="XSS_MARK_SAFE",
                                    cwe_id="CWE-79",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # SINK 4: eval(...) / exec(...) code injection
                elif EVAL_SINKS.match(fn_text):
                    target_arg = positional_args[0] if positional_args else (list(keyword_args.values())[0] if keyword_args else None)
                    if target_arg:
                        taint = check_expression_taint(target_arg, scope)
                        if not taint:
                            taint = has_tainted_expression(target_arg, scope)
                        if taint:
                            line = node.start_point[0] + 1
                            col = node.start_point[1] + 1
                            loc_key = (line, col, "CODE_INJECTION_EVAL")
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_xss_finding(
                                    line=line, col=col,
                                    end_line=node.end_point[0] + 1,
                                    end_col=node.end_point[1] + 1,
                                    taint=taint,
                                    sink_expr=fn_text,
                                    sink_line=line,
                                    rule_id="CODE_INJECTION_EVAL",
                                    cwe_id="CWE-95",
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

        # Traverse children
        for child in node.children:
            walk_ast(child, scope)

    root_scope = PythonXssLexicalScope()
    walk_ast(tree.root_node, root_scope)

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings
