"""SQL Injection AST Analyzer for JavaScript and TypeScript.

Detects unsafe string concatenation and template literal interpolations that incorporate
user input into SQL commands, while strictly respecting parameterized queries and ORM bindings.
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

REMEDIATION_GUIDANCE = (
    "Use parameterized queries (prepared statements) with bind parameters ($1, ?, or named parameters) "
    "or an ORM query builder. Never concatenate or interpolate untrusted user input directly into SQL strings."
)

# Sources of user-controlled input (Express/Koa/Serverless request objects)
TAINT_SOURCE_PATTERN = re.compile(
    r"^(?:req|request|ctx|event)\.(?:query|body|params|headers|queryStringParameters|pathParameters)(?:\.[a-zA-Z0-9_$]+|\[.*?\])?$"
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

# Known escaping or sanitization functions (judgment call: flagged as lower-confidence / MEDIUM severity)
SANITIZER_PATTERN = re.compile(
    r"(?i)^(?:.*?\.)?(?:escape|sanitize|parameterize|mysql\.escape|sqlstring\.escape|validator\.escape)$"
)

# ORM methods with automatic parameterization (must NEVER be flagged as SQL injection)
ORM_SAFE_METHODS = {
    "findone", "findall", "findbyid", "findbypk", "findunique", "findfirst",
    "findmany", "create", "update", "destroy", "delete", "deletemany",
    "count", "aggregate", "bulkcreate"
}

# Database query execution sinks
SQL_SINK_METHODS = {
    "query", "execute", "raw", "$queryrawunsafe", "$executerawunsafe", "rawquery"
}

# Framework and utility parameters to ignore when inspecting function signatures
FRAMEWORK_PARAM_NAMES = {
    "req", "request", "res", "response", "next", "ctx", "event", "context", "self", "this", "_"
}


@dataclass
class TaintInfo:
    source_expr: str
    source_line: int
    is_sanitized: bool = False
    sanitizer_name: Optional[str] = None


@dataclass
class SqlInjectionFinding:
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
    """Represents a lexical scope for tracking tainted variables and query definitions."""

    def __init__(self, parent: Optional["LexicalScope"] = None):
        self.parent = parent
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.tainted_queries: Dict[str, dict] = {}

    def set_var(self, name: str, taint: TaintInfo) -> None:
        self.tainted_vars[name] = taint

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


def get_parser_for_filename(filename: str) -> tree_sitter.Parser:
    """Select the appropriate Tree-sitter parser based on file extension."""
    lower = filename.lower()
    if lower.endswith(".tsx"):
        return tree_sitter.Parser(TSX_LANGUAGE)
    elif lower.endswith((".ts", ".mts", ".cts")):
        return tree_sitter.Parser(TS_LANGUAGE)
    else:
        return tree_sitter.Parser(JS_LANGUAGE)


def get_node_text(node: tree_sitter.Node) -> str:
    """Retrieve decoded text for an AST node."""
    return node.text.decode("utf-8", errors="replace")


def check_expression_taint(
    node: tree_sitter.Node,
    scope: LexicalScope
) -> Optional[TaintInfo]:
    """Check if an expression AST node resolves to tainted user input."""
    # 1. Direct member expression (e.g. req.query.id, req.body.username)
    if node.type == "member_expression":
        text = get_node_text(node).replace(" ", "")
        if TAINT_SOURCE_PATTERN.match(text):
            return TaintInfo(
                source_expr=text,
                source_line=node.start_point[0] + 1,
                is_sanitized=False,
                sanitizer_name=None
            )

    # 2. Variable identifier lookup in current scope hierarchy
    if node.type == "identifier":
        name = get_node_text(node)
        return scope.get_var(name)

    # 3. Call expression (check for sanitizers like escape(x))
    if node.type == "call_expression":
        fn_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if fn_node and args_node:
            fn_text = get_node_text(fn_node).replace(" ", "")
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

    # 4. Binary expression (+): e.g. "prefix" + taintedVar
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

    # 5. Parenthesized expression: (expr)
    if node.type == "parenthesized_expression":
        for child in node.children:
            if child.type not in ("(", ")"):
                return check_expression_taint(child, scope)

    return None


def extract_concat_parts(node: tree_sitter.Node) -> List[tree_sitter.Node]:
    """Recursively collect all leaf operands in a (+) binary expression tree."""
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        if op and get_node_text(op) == "+":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            parts = []
            if left:
                parts.extend(extract_concat_parts(left))
            if right:
                parts.extend(extract_concat_parts(right))
            return parts
    return [node]


def extract_param_names(params_node: tree_sitter.Node) -> List[Tuple[str, int]]:
    """Extract formal parameter names from a function parameter list."""
    result = []
    for child in params_node.children:
        p_name = None
        line = child.start_point[0] + 1
        if child.type == "identifier":
            p_name = get_node_text(child)
        elif child.type in ("required_parameter", "optional_parameter"):
            for sub in child.children:
                if sub.type == "identifier":
                    p_name = get_node_text(sub)
                    break
        if p_name and p_name.lower() not in FRAMEWORK_PARAM_NAMES:
            result.append((p_name, line))
    return result


def scan_source_for_sql_injection(
    source_code: str,
    file_path: str = "snippet.ts"
) -> List[SqlInjectionFinding]:
    """Scan JavaScript/TypeScript source code AST for SQL Injection vulnerabilities."""
    if not source_code or not source_code.strip():
        return []

    if file_path.lower().endswith((".py", ".pyw")):
        from app.analyzers.python_sql_injection import scan_python_source_for_sql_injection
        return scan_python_source_for_sql_injection(source_code, file_path=file_path)

    parser = get_parser_for_filename(file_path)
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    source_lines = source_code.splitlines()

    findings: List[SqlInjectionFinding] = []
    recorded_locations: Set[Tuple[int, int]] = set()

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
                # Handle destructuring: const { id, category } = req.query;
                if name_node.type == "object_pattern":
                    val_text = get_node_text(value_node).replace(" ", "")
                    if TAINT_SOURCE_PATTERN.match(val_text):
                        for prop in name_node.children:
                            if prop.type == "shorthand_property_identifier_pattern":
                                p_name = get_node_text(prop)
                                scope.set_var(p_name, TaintInfo(
                                    source_expr=f"{val_text}.{p_name}",
                                    source_line=node.start_point[0] + 1,
                                    is_sanitized=False
                                ))
                            elif prop.type == "pair_pattern":
                                val_pattern = prop.child_by_field_name("value")
                                key_pattern = prop.child_by_field_name("key")
                                if val_pattern and key_pattern:
                                    scope.set_var(get_node_text(val_pattern), TaintInfo(
                                        source_expr=f"{val_text}.{get_node_text(key_pattern)}",
                                        source_line=node.start_point[0] + 1,
                                        is_sanitized=False
                                    ))

                # Standard variable declaration: const x = ...
                elif name_node.type == "identifier":
                    var_name = get_node_text(name_node)
                    taint = check_expression_taint(value_node, scope)
                    if taint:
                        scope.set_var(var_name, taint)

                    # Check if value_node is a SQL query string construction:
                    # Pattern A: Template literal with substitutions
                    if value_node.type == "template_string":
                        raw_text = get_node_text(value_node)
                        has_sql = bool(SQL_KEYWORDS_PATTERN.search(raw_text) or SQL_FRAGMENTS_PATTERN.search(raw_text))
                        tainted_sub = None
                        for child in value_node.children:
                            if child.type == "template_substitution":
                                for sub_child in child.children:
                                    if sub_child.type not in ("${", "}"):
                                        t = check_expression_taint(sub_child, scope)
                                        if t:
                                            tainted_sub = t
                                            break
                        if has_sql and tainted_sub:
                            scope.set_query(var_name, {
                                "node": value_node,
                                "line": value_node.start_point[0] + 1,
                                "col": value_node.start_point[1] + 1,
                                "end_line": value_node.end_point[0] + 1,
                                "end_col": value_node.end_point[1] + 1,
                                "taint": tainted_sub,
                                "var_name": var_name
                            })

                    # Pattern B: Binary expression concatenation (+)
                    elif value_node.type == "binary_expression":
                        raw_text = get_node_text(value_node)
                        has_sql = bool(SQL_KEYWORDS_PATTERN.search(raw_text) or SQL_FRAGMENTS_PATTERN.search(raw_text))
                        operands = extract_concat_parts(value_node)
                        tainted_op = None
                        for op in operands:
                            t = check_expression_taint(op, scope)
                            if t:
                                tainted_op = t
                                break
                        if has_sql and tainted_op:
                            scope.set_query(var_name, {
                                "node": value_node,
                                "line": value_node.start_point[0] + 1,
                                "col": value_node.start_point[1] + 1,
                                "end_line": value_node.end_point[0] + 1,
                                "end_col": value_node.end_point[1] + 1,
                                "taint": tainted_op,
                                "var_name": var_name
                            })

        # 2. Assignment expression: x = ...
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            if left_node and right_node and left_node.type == "identifier":
                var_name = get_node_text(left_node)
                taint = check_expression_taint(right_node, scope)
                if taint:
                    scope.set_var(var_name, taint)

        # 3. Check call expression (sinks & ORM methods)
        elif node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            if fn_node and args_node:
                fn_text = get_node_text(fn_node)
                method_name = ""
                if fn_node.type == "member_expression":
                    prop = fn_node.child_by_field_name("property")
                    if prop:
                        method_name = get_node_text(prop).lower()
                else:
                    method_name = fn_text.lower()

                # FALSE POSITIVE CHECK 1: Safe ORM methods (findOne, findAll, create, update, etc.)
                if method_name in ORM_SAFE_METHODS:
                    pass
                else:
                    # Check if call is a known SQL query execution sink
                    is_sql_sink = (
                        method_name in SQL_SINK_METHODS or
                        bool(re.search(r"(?i)\b(?:db|conn|connection|pool|client|sequelize|knex|pg|mysql|database)\.(?:query|execute|raw)\b", fn_text))
                    )

                    if is_sql_sink:
                        arg_list = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                        if arg_list:
                            first_arg = arg_list[0]

                            # FALSE POSITIVE CHECK 2: Parameterized query using static string
                            if first_arg.type == "string":
                                pass

                            # TRUE POSITIVE CASE 1: Direct template literal in query call
                            elif first_arg.type == "template_string":
                                tainted_sub = None
                                for child in first_arg.children:
                                    if child.type == "template_substitution":
                                        for sub_child in child.children:
                                            if sub_child.type not in ("${", "}"):
                                                t = check_expression_taint(sub_child, scope)
                                                if t:
                                                    tainted_sub = t
                                                    break
                                if tainted_sub:
                                    line = first_arg.start_point[0] + 1
                                    col = first_arg.start_point[1] + 1
                                    end_line = first_arg.end_point[0] + 1
                                    end_col = first_arg.end_point[1] + 1
                                    loc_key = (line, col)
                                    if loc_key not in recorded_locations:
                                        recorded_locations.add(loc_key)
                                        make_finding(
                                            line=line, col=col, end_line=end_line, end_col=end_col,
                                            taint=tainted_sub,
                                            sink_expr=fn_text,
                                            sink_line=node.start_point[0] + 1,
                                            source_lines=source_lines,
                                            file_path=file_path,
                                            findings=findings
                                        )

                            # TRUE POSITIVE CASE 2: Direct string concatenation (+) in query call
                            elif first_arg.type == "binary_expression":
                                operands = extract_concat_parts(first_arg)
                                tainted_op = None
                                for op in operands:
                                    t = check_expression_taint(op, scope)
                                    if t:
                                        tainted_op = t
                                        break
                                if tainted_op:
                                    line = first_arg.start_point[0] + 1
                                    col = first_arg.start_point[1] + 1
                                    end_line = first_arg.end_point[0] + 1
                                    end_col = first_arg.end_point[1] + 1
                                    loc_key = (line, col)
                                    if loc_key not in recorded_locations:
                                        recorded_locations.add(loc_key)
                                        make_finding(
                                            line=line, col=col, end_line=end_line, end_col=end_col,
                                            taint=tainted_op,
                                            sink_expr=fn_text,
                                            sink_line=node.start_point[0] + 1,
                                            source_lines=source_lines,
                                            file_path=file_path,
                                            findings=findings
                                        )

                            # TRUE POSITIVE CASE 3: Identifier holding previously constructed tainted query
                            elif first_arg.type == "identifier":
                                var_name = get_node_text(first_arg)
                                q_info = scope.get_query(var_name)
                                if q_info:
                                    line = q_info["line"]
                                    col = q_info["col"]
                                    end_line = q_info["end_line"]
                                    end_col = q_info["end_col"]
                                    loc_key = (line, col)
                                    if loc_key not in recorded_locations:
                                        recorded_locations.add(loc_key)
                                        make_finding(
                                            line=line, col=col, end_line=end_line, end_col=end_col,
                                            taint=q_info["taint"],
                                            sink_expr=fn_text,
                                            sink_line=node.start_point[0] + 1,
                                            source_lines=source_lines,
                                            file_path=file_path,
                                            findings=findings,
                                            var_name=var_name
                                        )

        # Recursively traverse children
        for child in node.children:
            walk_ast(child, scope)

    root_scope = LexicalScope()
    walk_ast(tree.root_node, root_scope)

    findings.sort(key=lambda f: (f.line_number, f.column))
    return findings


def make_finding(
    line: int, col: int, end_line: int, end_col: int,
    taint: TaintInfo,
    sink_expr: Optional[str],
    sink_line: Optional[int],
    source_lines: List[str],
    file_path: str,
    findings: List[SqlInjectionFinding],
    var_name: Optional[str] = None
):
    """Build and append a structured SqlInjectionFinding."""
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{file_path}:{line}:{col}:SQL_INJECTION"))
    snippet = ""
    if 0 <= line - 1 < len(source_lines):
        snippet = source_lines[line - 1].strip()

    is_sanitized = taint.is_sanitized
    sanitizer_name = taint.sanitizer_name

    # Decision on sanitization functions:
    # If a value passes through an escape/sanitizer function (e.g. escape(), sanitize()),
    # we flag as MEDIUM severity with lower confidence, noting that sanitization was detected
    # but prepared statements remain the only guaranteed defense against SQL injection.
    if is_sanitized:
        severity = "MEDIUM"
        title = "Potential SQL Injection (Sanitizer Detected - Review Required)"
        remediation = (
            "Replace string interpolation and custom escaping with parameterized queries "
            "(prepared statements). While an escaping/sanitizer function was detected, escaping "
            "can fail depending on database character encoding, SQL modes, or quote context."
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
                f"sanitizer '{sanitizer_name}' before entering the SQL query string on line {line}."
            )
    else:
        severity = "CRITICAL"
        title = "SQL Injection Vulnerability via Unsanitized Input"
        remediation = (
            "Use parameterized queries (prepared statements) with bind variables ($1, ?, or named parameters) "
            "or an ORM query builder. Never concatenate or interpolate untrusted user input directly into SQL commands."
        )
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
