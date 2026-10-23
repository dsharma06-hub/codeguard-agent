"""SQL Injection AST Analyzer for Python.

Detects unsafe string concatenation, f-string interpolations, %-formatting, and .format()
that incorporate untrusted user input into SQL commands, while strictly respecting
parameterized DB-API queries, Django raw(sql, params) with parameters, and ORM querysets.
"""

from typing import Dict, List, Optional, Set, Tuple
import re
import uuid

import tree_sitter
import tree_sitter_python as tspy

from app.analyzers.sql_injection import SqlInjectionFinding, TaintInfo

# Initialize Python Tree-sitter Language
PYTHON_LANGUAGE = tree_sitter.Language(tspy.language())

REMEDIATION_GUIDANCE = (
    "Use parameterized queries (prepared statements) with bind parameters "
    "($1, ?, %s, or :name) or the Django/SQLAlchemy ORM query builder. "
    "Never concatenate or interpolate untrusted user input directly into SQL strings."
)

# Sources of user-controlled input (Flask/WSGI request objects)
TAINT_SOURCE_PATTERN = re.compile(
    r"^(?:req|request)\.(?:args|form|values|GET|POST|json|headers|cookies)(?:\.[a-zA-Z0-9_$]+)?$"
)

# SQL statements and clauses identifying query construction
SQL_KEYWORDS_PATTERN = re.compile(
    r"(?i)\b(SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM|"
    r"DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|TRUNCATE\s+TABLE|"
    r"UNION\s+SELECT|UNION\s+ALL\s+SELECT)\b"
)

SQL_FRAGMENTS_PATTERN = re.compile(
    r"(?i)\b(SELECT\s+|INSERT\s+INTO\s+|UPDATE\s+|DELETE\s+FROM\s+|FROM\s+|WHERE\s+|JOIN\s+|ORDER\s+BY\s+|GROUP\s+BY\s+|LIMIT\s+)"
)

# Known escaping or sanitization functions
SANITIZER_PATTERN = re.compile(
    r"(?i)^(?:.*?\.)?(?:escape|sanitize|parameterize|quote|sql_escape|validator\.escape)$"
)

# FastAPI route handler decorators
FASTAPI_ROUTE_DECORATOR_PATTERN = re.compile(
    r"(?i)^@(?:app|router|api_router|bp|blueprint)\.(?:get|post|put|delete|patch|options|head|route|api_route)\b"
)

# Framework and utility parameters to ignore when inspecting route signatures
FRAMEWORK_PARAM_NAMES = {
    "self", "cls", "request", "req", "response", "res", "db", "session", "current_user", "_"
}

# Django ORM methods with automatic parameterization (must NEVER be flagged as SQL injection)
DJANGO_SAFE_ORM_METHODS = {
    "filter", "filter_by", "exclude", "get", "annotate", "values", "values_list",
    "order_by", "distinct", "count", "exists", "first", "last", "create",
    "update", "delete", "bulk_create", "bulk_update", "all", "none", "latest",
    "earliest", "in_bulk", "iterator", "aggregate"
}


class PythonLexicalScope:
    """Represents a lexical scope for tracking tainted variables, queries, and static strings."""

    def __init__(self, parent: Optional["PythonLexicalScope"] = None):
        self.parent = parent
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.tainted_queries: Dict[str, dict] = {}
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

    def set_query(self, name: str, query_info: dict) -> None:
        self.tainted_queries[name] = query_info

    def get_query(self, name: str) -> Optional[dict]:
        if name in self.tainted_queries:
            return self.tainted_queries[name]
        if self.parent:
            return self.parent.get_query(name)
        return None

    def set_static(self, name: str, val: str) -> None:
        self.static_vars[name] = val
        if name in self.tainted_vars:
            del self.tainted_vars[name]
        if name in self.tainted_queries:
            del self.tainted_queries[name]

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
    if node.type != "string":
        return False
    return any(child.type == "interpolation" for child in node.children)


def check_expression_taint(node: tree_sitter.Node, scope: PythonLexicalScope) -> Optional[TaintInfo]:
    """Check if an expression AST node directly resolves to tainted user input."""
    if node is None:
        return None

    # 1. Identifier lookup in scope
    if node.type == "identifier":
        name = get_node_text(node)
        return scope.get_var(name)

    # 2. Attribute access: request.args, req.form, etc.
    if node.type == "attribute":
        text = get_node_text(node).replace(" ", "")
        if TAINT_SOURCE_PATTERN.match(text):
            return TaintInfo(source_expr=text, source_line=node.start_point[0] + 1)
        obj = node.child_by_field_name("object")
        if obj:
            obj_taint = check_expression_taint(obj, scope)
            if obj_taint:
                return obj_taint

    # 3. Subscript: sys.argv[1], request.args['id'], etc.
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
            # request.args.get(...), request.json.get(...), etc.
            if re.match(r"^(?:req|request)\.(?:args|form|values|GET|POST|json)\.get$", fn_text):
                return TaintInfo(source_expr=get_node_text(node), source_line=node.start_point[0] + 1)
            # Sanitizers: escape(), sanitize(), quote(), etc.
            if SANITIZER_PATTERN.match(fn_text) and args_node:
                for arg in args_node.children:
                    if arg.type not in ("(", ")", ","):
                        inner_t = check_expression_taint(arg, scope)
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

    # 7. Parenthesized expression
    if node.type == "parenthesized_expression":
        for child in node.children:
            if child.type not in ("(", ")"):
                return check_expression_taint(child, scope)

    return None


def has_tainted_expression(node: tree_sitter.Node, scope: PythonLexicalScope) -> Optional[TaintInfo]:
    """Recursively checks if node or any of its sub-expressions contains tainted input."""
    if node is None:
        return None

    # Check direct taint
    t = check_expression_taint(node, scope)
    if t:
        return t

    # Check if identifier refers to a tainted query
    if node.type == "identifier":
        name = get_node_text(node)
        q = scope.get_query(name)
        if q:
            return q["taint"]

    # F-string
    if is_fstring(node):
        for child in node.children:
            if child.type == "interpolation":
                t = has_tainted_expression(child, scope)
                if t:
                    return t

    # Binary operator (+, %)
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

    # List, tuple, set
    if node.type in ("list", "tuple", "set"):
        for child in node.children:
            if child.type not in ("[", "]", "(", ")", "{", "}", ","):
                t = has_tainted_expression(child, scope)
                if t:
                    return t

    # Dictionary
    if node.type == "dictionary":
        for child in node.children:
            if child.type == "pair":
                val = child.child_by_field_name("value")
                t = has_tainted_expression(val, scope)
                if t:
                    return t

    # Keyword argument
    if node.type == "keyword_argument":
        val = node.child_by_field_name("value")
        return has_tainted_expression(val, scope)

    # Call (e.g. text(...))
    if node.type == "call":
        fn_node = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn_node and get_node_text(fn_node).endswith("text") and args:
            for child in args.children:
                if child.type not in ("(", ")", ","):
                    t = has_tainted_expression(child, scope)
                    if t:
                        return t

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
            # Skip dependency injection parameters (e.g. Depends(...))
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


def make_finding(
    line: int, col: int, end_line: int, end_col: int,
    taint: TaintInfo,
    sink_expr: Optional[str],
    sink_line: Optional[int],
    source_lines: List[str],
    file_path: str,
    findings: List[SqlInjectionFinding]
):
    """Build and append a structured SqlInjectionFinding for Python."""
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{line}:{col}:SQL_INJECTION"))
    snippet = ""
    if 0 <= line - 1 < len(source_lines):
        snippet = source_lines[line - 1].strip()

    is_sanitized = taint.is_sanitized
    sanitizer_name = taint.sanitizer_name

    if is_sanitized:
        severity = "MEDIUM"
        title = "Potential SQL Injection (Sanitizer Detected - Review Required)"
        remediation = (
            "Replace string formatting/escaping with parameterized queries (prepared statements) "
            "or the Django/SQLAlchemy ORM. Custom or manual escaping functions can fail depending "
            "on encoding, SQL dialect, or quote context."
        )
        if sink_line and sink_line != line:
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
                f"sanitizer '{sanitizer_name}' before entering the SQL query on line {line}, "
                f"which is executed by '{sink_expr}' on line {sink_line}."
            )
        else:
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') passes through "
                f"sanitizer '{sanitizer_name}' before entering SQL execution sink '{sink_expr}' on line {line}."
            )
    else:
        severity = "CRITICAL"
        title = "SQL Injection Vulnerability via Unsanitized Input"
        remediation = REMEDIATION_GUIDANCE
        if sink_line and sink_line != line:
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is interpolated "
                f"into a SQL query string on line {line} and executed by '{sink_expr}' on line {sink_line} "
                "without parameterization."
            )
        elif sink_line and sink_line == line:
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is directly interpolated "
                f"into SQL query execution call '{sink_expr}' on line {line} without parameterization."
            )
        else:
            desc = (
                f"User input from line {taint.source_line} ('{taint.source_expr}') is concatenated "
                f"into a SQL query string on line {line} without parameterization."
            )

    findings.append(SqlInjectionFinding(
        id=finding_id,
        file_path=file_path,
        line_number=line,
        end_line_number=end_line,
        column=col,
        end_column=end_col,
        rule_id="SQL_INJECTION",
        severity=severity,
        category="Injection Risk",
        title=title,
        description=desc,
        code_snippet=snippet,
        remediation=remediation,
        cwe_id="CWE-89",
        source_expression=taint.source_expr,
        source_line=taint.source_line,
        sink_expression=sink_expr,
        sink_line=sink_line,
        is_sanitized=is_sanitized,
        sanitizer_name=sanitizer_name
    ))


def scan_python_source_for_sql_injection(
    source_code: str,
    file_path: str = "snippet.py"
) -> List[SqlInjectionFinding]:
    """Scan Python source code AST for SQL Injection vulnerabilities."""
    if not source_code or not source_code.strip():
        return []

    parser = tree_sitter.Parser(PYTHON_LANGUAGE)
    tree = parser.parse(source_code.encode("utf-8"))
    source_lines = source_code.splitlines()

    findings: List[SqlInjectionFinding] = []
    recorded_locations: Set[Tuple[int, int]] = set()

    SCOPE_CREATORS = {
        "function_definition", "async_function_definition", "class_definition"
    }

    def walk_ast(node: tree_sitter.Node, current_scope: PythonLexicalScope):
        if node.type in SCOPE_CREATORS:
            scope = PythonLexicalScope(parent=current_scope)
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
                # Check if right is a static string
                if right.type == "string" and not is_fstring(right):
                    scope.set_static(var_name, get_node_text(right))
                else:
                    taint = check_expression_taint(right, scope)
                    if taint:
                        scope.set_var(var_name, taint)
                    else:
                        scope.set_var(var_name, None)

                # Check if right is a query string construction
                raw_right = get_node_text(right)
                has_sql = bool(SQL_KEYWORDS_PATTERN.search(raw_right) or SQL_FRAGMENTS_PATTERN.search(raw_right))
                if has_sql:
                    t_query = has_tainted_expression(right, scope)
                    if t_query:
                        scope.set_query(var_name, {
                            "node": right,
                            "line": right.start_point[0] + 1,
                            "col": right.start_point[1] + 1,
                            "end_line": right.end_point[0] + 1,
                            "end_col": right.end_point[1] + 1,
                            "taint": t_query,
                            "var_name": var_name
                        })

        # Sinks: Call expressions
        elif node.type == "call":
            fn = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn and args_node:
                fn_text = get_node_text(fn)
                method_name = ""
                if fn.type == "attribute":
                    attr = fn.child_by_field_name("attribute")
                    if attr:
                        method_name = get_node_text(attr).lower()
                else:
                    method_name = fn_text.lower()

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

                # Check FALSE POSITIVE 1: Django ORM safe methods (filter, get, exclude, etc.)
                if method_name in DJANGO_SAFE_ORM_METHODS:
                    pass

                # Check SINK 1: Django extra() — ALWAYS flag if tainted value reaches where or select!
                elif method_name == "extra":
                    where_node = keyword_args.get("where") or (positional_args[1] if len(positional_args) > 1 else None)
                    select_node = keyword_args.get("select") or (positional_args[0] if len(positional_args) > 0 else None)

                    taint_extra = None
                    target_arg_node = None
                    if where_node:
                        t = has_tainted_expression(where_node, scope)
                        if t:
                            taint_extra = t
                            target_arg_node = where_node
                    if not taint_extra and select_node:
                        t = has_tainted_expression(select_node, scope)
                        if t:
                            taint_extra = t
                            target_arg_node = select_node

                    if taint_extra and target_arg_node:
                        line = target_arg_node.start_point[0] + 1
                        col = target_arg_node.start_point[1] + 1
                        loc_key = (line, col)
                        if loc_key not in recorded_locations:
                            recorded_locations.add(loc_key)
                            make_finding(
                                line=line, col=col,
                                end_line=target_arg_node.end_point[0] + 1,
                                end_col=target_arg_node.end_point[1] + 1,
                                taint=taint_extra,
                                sink_expr=fn_text,
                                sink_line=node.start_point[0] + 1,
                                source_lines=source_lines,
                                file_path=file_path,
                                findings=findings
                            )

                # Check SINK 2: Django raw(sql, params) and RawSQL(sql, params)
                elif method_name in ("raw", "rawsql"):
                    sql_node = keyword_args.get("sql") or (positional_args[0] if positional_args else None)
                    if sql_node:
                        # SAFE RULE: If sql_node is static (or identifier pointing to static string),
                        # tainted values in params are SAFE!
                        # UNSAFE RULE: If sql_node itself contains tainted expression, flag UNSAFE!
                        t_sql = has_tainted_expression(sql_node, scope)
                        if t_sql:
                            line = sql_node.start_point[0] + 1
                            col = sql_node.start_point[1] + 1
                            loc_key = (line, col)
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_finding(
                                    line=line, col=col,
                                    end_line=sql_node.end_point[0] + 1,
                                    end_col=sql_node.end_point[1] + 1,
                                    taint=t_sql,
                                    sink_expr=fn_text,
                                    sink_line=node.start_point[0] + 1,
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )

                # Check SINK 3: Raw DB-API / connection.cursor().execute(query, params) / SQLAlchemy session.execute()
                elif method_name in ("execute", "executemany"):
                    query_node = keyword_args.get("query") or (positional_args[0] if positional_args else None)
                    if query_node:
                        # SAFE RULE: If query is static (or text() with static string), and params is passed: SAFE!
                        # UNSAFE RULE: If query contains tainted value: UNSAFE!
                        t_query = has_tainted_expression(query_node, scope)
                        if t_query:
                            line = query_node.start_point[0] + 1
                            col = query_node.start_point[1] + 1
                            loc_key = (line, col)
                            if loc_key not in recorded_locations:
                                recorded_locations.add(loc_key)
                                make_finding(
                                    line=line, col=col,
                                    end_line=query_node.end_point[0] + 1,
                                    end_col=query_node.end_point[1] + 1,
                                    taint=t_query,
                                    sink_expr=fn_text,
                                    sink_line=node.start_point[0] + 1,
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    findings=findings
                                )


        for child in node.children:
            walk_ast(child, scope)

    root_scope = PythonLexicalScope()
    walk_ast(tree.root_node, root_scope)

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings
