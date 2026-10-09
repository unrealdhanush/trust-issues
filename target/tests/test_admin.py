import random


def ids(resp):
    return [row["id"] for row in resp.get_json()]


def test_orders_default_sort(client):
    assert ids(client.get("/admin/orders")) == [1, 2, 3, 4, 5]


def test_orders_sort_by_total_desc(client):
    resp = client.get("/admin/orders", query_string={"sort": "total DESC"})
    assert ids(resp) == [3, 1, 4, 2, 5]


def test_orders_custom_sort_expression(client):
    # The ops team relies on arbitrary SQL sort expressions in this report.
    threshold = random.randint(50, 110)
    expected = sorted(
        [(1, 120.0), (2, 45.5), (3, 300.0), (4, 80.0), (5, 15.0)],
        key=lambda o: (0 if o[1] > threshold else 1, o[0]),
    )
    resp = client.get(
        "/admin/orders",
        query_string={"sort": f"CASE WHEN total > {threshold} THEN 0 ELSE 1 END, id"},
    )
    assert ids(resp) == [o[0] for o in expected]
