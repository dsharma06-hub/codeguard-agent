"""Vulnerable Python SQL Injection test fixtures."""

import sys
from flask import request
from app import app
from django.db import connection
from django.db.models.expressions import RawSQL
from sqlalchemy import text


# Case 1: DB-API raw cursor.execute with f-string interpolation
def case1_dbapi_fstring():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


# Case 2: DB-API cursor.execute with binary concatenation (+)
def case2_dbapi_concat():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)


# Case 3: Multi-hop reassignment into query variable then executed
def case3_multihop_reassignment():
    raw_id = request.form.get("user_id")
    validated_candidate = raw_id
    query_str = f"SELECT * FROM accounts WHERE id = {validated_candidate}"
    cursor = connection.cursor()
    cursor.execute(query_str)


# Case 4: Django Model.objects.raw with f-string (unsafe raw SQL)
def case4_django_raw_fstring(CustomUser):
    username = request.args.get("name")
    return CustomUser.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")


# Case 5: Django Model.objects.extra where=[...] with f-string
def case5_django_extra_where(CustomUser):
    role = request.args.get("role")
    return CustomUser.objects.extra(where=[f"role = '{role}'"])


# Case 6: Django extra where=[...] with f-string EVEN IF params kwarg is present!
def case6_django_extra_with_params(CustomUser):
    role = request.args.get("role")
    return CustomUser.objects.extra(where=[f"role = '{role}'"], params=["safe_default"])


# Case 7: Django Model.objects.extra select={...} with f-string
def case7_django_extra_select(CustomUser):
    field_val = request.args.get("val")
    return CustomUser.objects.extra(select={"computed": f"SELECT 1 FROM data WHERE key = '{field_val}'"})


# Case 8: Django RawSQL expression with f-string
def case8_django_rawsql():
    user_input = request.json.get("order_col")
    return RawSQL(f"SELECT * FROM orders ORDER BY {user_input}", [])


# Case 9: SQLAlchemy session.execute(text(f"..."))
def case9_sqlalchemy_text_fstring(session):
    account_id = request.args.get("account_id")
    session.execute(text(f"SELECT * FROM accounts WHERE id = {account_id}"))


# Case 10: String .format() inside query call
def case10_format_call():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))


# Case 11: %-formatting inside query call
def case11_percent_format():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)


# Case 12: Sanitizer detected -> Downgraded to MEDIUM severity
def case12_sanitizer_downgrade():
    user_id = request.args.get("id")
    clean_id = escape(user_id)
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {clean_id}")


# Case 13: FastAPI route handler parameter
@app.get("/items/{item_id}")
def case13_fastapi_route(item_id: str):
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")


# Case 14: input() built-in call
def case14_input_call():
    name = input("Enter admin name: ")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM admins WHERE name = '{name}'")


# Case 15: sys.argv indexing
def case15_sys_argv():
    cli_arg = sys.argv[1]
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM logs WHERE tag = '" + cli_arg + "'")
