"""Safe Python SQL query test fixtures (must never produce false positives)."""

from flask import request
from django.db import connection
from django.db.models.expressions import RawSQL
from sqlalchemy import text


# FP 1: Parameterized DB-API query
def fp1_parameterized_dbapi():
    user_id = request.args.get("id")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


# FP 2: Django ORM filter
def fp2_django_orm_filter(CustomUser):
    user_id = request.args.get("id")
    return CustomUser.objects.filter(id=user_id)


# FP 3: Django Model.objects.raw with static variable sql and params
def fp3_django_raw_static_var(CustomUser):
    tainted_value = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = %s"
    return CustomUser.objects.raw(sql, [tainted_value])


# FP 4: Django Model.objects.raw with inline static sql string literal and params
def fp4_django_raw_inline(CustomUser):
    tainted_value = request.args.get("id")
    return CustomUser.objects.raw("SELECT * FROM users WHERE id = %s", [tainted_value])


# FP 5: SQLAlchemy ORM query filter
def fp5_sqlalchemy_orm(session, CustomUser):
    user_id = request.args.get("id")
    return session.query(CustomUser).filter(CustomUser.id == user_id)


# FP 6: SQLAlchemy parameterized session.execute with text() and params
def fp6_sqlalchemy_text_params(session):
    user_id = request.args.get("id")
    session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})


# FP 7: Django RawSQL with static template and params
def fp7_django_rawsql():
    user_id = request.args.get("id")
    return RawSQL("SELECT * FROM orders WHERE user_id = %s", [user_id])


# FP 8: Django extra with static where clause
def fp8_django_extra_static(CustomUser):
    return CustomUser.objects.extra(where=["status = 'active'"])


# FP 9: Static query without params
def fp9_static_query():
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
