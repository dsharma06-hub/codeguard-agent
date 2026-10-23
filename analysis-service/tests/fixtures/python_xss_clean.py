"""Safe Python template rendering and Markup fixtures (must produce 0 findings)."""

from flask import request, render_template, render_template_string
from markupsafe import Markup
from django.utils.safestring import mark_safe
from app import app


# FP 1: render_template_string with static template and context variable (safe Flask pattern)
def fp1_render_template_string_context():
    user_input = request.args.get("name")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=user_input)


# FP 2: render_template with template file and context variables (standard safe Flask pattern)
def fp2_render_template_file():
    user_input = request.args.get("name")
    email = request.form.get("email")
    return render_template("profile.html", name=user_input, email=email)


# FP 3: Markup with static string literal
def fp3_markup_static():
    return Markup("<b>Static HTML content</b>")


# FP 4: mark_safe with static string literal
def fp4_mark_safe_static():
    return mark_safe("<p class='alert'>Safe static message</p>")


# FP 5: eval with static mathematical expression
def fp5_eval_static():
    return eval("1 + 1")


# FP 6: exec with static code
def fp6_exec_static():
    exec("x = 1 + 2")


# FP 7: render_template_string with concatenated static strings and context kwarg
def fp7_concat_static():
    user_input = request.args.get("q")
    static_tpl = "<div>" + "Search: {{ q }}" + "</div>"
    return render_template_string(static_tpl, q=user_input)


# FP 8: FastAPI route calling render_template with context kwargs
@app.get("/items/{item_id}")
def fp8_fastapi_safe_render(item_id: str):
    return render_template("item_detail.html", item_id=item_id)
