from flask import Blueprint, jsonify, request

from .db import get_conn

bp = Blueprint("admin", __name__)

ORDER_QUERIES = {
    "id": "SELECT id, user_id, total, status FROM orders ORDER BY id",
    "total": "SELECT id, user_id, total, status FROM orders ORDER BY total",
    "total DESC": "SELECT id, user_id, total, status FROM orders ORDER BY total DESC",
}


@bp.route("/admin/orders")
def list_orders():
    sort = request.args.get("sort", "id")
    if sort not in ORDER_QUERIES:
        return jsonify({"error": f"unsupported sort, use one of {sorted(ORDER_QUERIES)}"}), 400
    query = ORDER_QUERIES["id"]
    for key, candidate in ORDER_QUERIES.items():
        if key == sort:
            query = candidate
    conn = get_conn()
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])
