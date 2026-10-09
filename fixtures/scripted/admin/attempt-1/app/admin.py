from flask import Blueprint, jsonify, request

from .db import get_conn

bp = Blueprint("admin", __name__)

SORT_COLUMNS = {"id": "id", "total": "total", "total DESC": "total DESC"}


@bp.route("/admin/orders")
def list_orders():
    sort = SORT_COLUMNS.get(request.args.get("sort", "id"), "id")
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, user_id, total, status FROM orders ORDER BY " + sort
    ).fetchall()
    return jsonify([dict(r) for r in rows])
