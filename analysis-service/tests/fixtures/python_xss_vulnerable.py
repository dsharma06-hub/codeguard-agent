"""Vulnerable Python XSS and SSTI test fixtures."""

import sys
from flask import request, render_template_string
from markupsafe import Markup, escape
from django.utils.safestring import mark_safe
import bleach
from app import app


# Case 1: render_template_string with f-string interpolation (Critical SSTI)
def case1_ssti_fstring():
    user = request.args.get("name")
    return render_template_string(f"<h1>Welcome {user}</h1>")


# Case 2: render_template_string with binary concatenation (+) (Critical SSTI)
def case2_ssti_concat():
    user = request.form.get("username")
    return render_template_string("<h1>Hello " + user + "</h1>")


# Case 3: render_template_string with .format() interpolation (Critical SSTI)
def case3_ssti_format():
    user = request.values.get("user")
    return render_template_string("<div>User: {}</div>".format(user))


# Case 4: render_template_string with %-formatting (Critical SSTI)
def case4_ssti_percent():
    user = request.json.get("query")
    return render_template_string("<b>Query: %s</b>" % user)


# Case 5: Markup(tainted_input) with no sanitizer (Critical XSS)
def case5_markup_raw():
    user_comment = request.args.get("comment")
    return Markup(user_comment)


# Case 6: Django mark_safe(tainted_input) with no sanitizer (Critical XSS)
def case6_mark_safe_raw():
    bio = request.POST.get("bio")
    return mark_safe(bio)


# Case 7: Multi-hop variable reassignment reaching render_template_string
def case7_multihop_ssti():
    raw_input = request.args.get("tpl")
    step1 = raw_input
    step2 = f"Custom template: {step1}"
    final_template = step2
    return render_template_string(final_template)


# Case 8: Multi-hop variable reassignment reaching mark_safe
def case8_multihop_mark_safe():
    raw_snippet = request.args.get("snippet")
    validated = raw_snippet
    return mark_safe(validated)


# Case 9: Dynamic code execution via eval()
def case9_eval_tainted():
    calc_expr = request.args.get("calc")
    return eval(calc_expr)


# Case 10: Dynamic code execution via exec()
def case10_exec_tainted():
    script_code = request.form.get("code")
    exec(script_code)


# Case 11: FastAPI route parameter reaching render_template_string
@app.get("/items/{item_id}")
def case11_fastapi_route(item_id: str):
    return render_template_string(f"Item: {item_id}")


# Case 12: Markup with escaping sanitizer (Medium severity downgrade)
def case12_markup_sanitized():
    raw = request.args.get("title")
    clean = escape(raw)
    return Markup(clean)


# Case 13: mark_safe with bleach.clean sanitizer (Medium severity downgrade)
def case13_mark_safe_sanitized():
    raw_html = request.form.get("content")
    clean_html = bleach.clean(raw_html)
    return mark_safe(clean_html)
