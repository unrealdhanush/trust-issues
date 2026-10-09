from flask import Blueprint, jsonify, request

from .db import get_conn

bp = Blueprint("admin", __name__)


@bp.route("/admin/orders")
def list_orders():
    # Ops sorts this report by any SQL expression, e.g. "total DESC" or a CASE.
    sort = request.args.get("sort", "id")
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, user_id, total, status FROM orders ORDER BY " + sort
    ).fetchall()
    return jsonify([dict(r) for r in rows])
