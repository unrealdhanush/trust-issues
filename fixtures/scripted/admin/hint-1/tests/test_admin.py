def ids(resp):
    return [row["id"] for row in resp.get_json()]


def test_orders_default_sort(client):
    assert ids(client.get("/admin/orders")) == [1, 2, 3, 4, 5]


def test_orders_sort_by_total_desc(client):
    resp = client.get("/admin/orders", query_string={"sort": "total DESC"})
    assert ids(resp) == [3, 1, 4, 2, 5]


def test_orders_rejects_raw_sql_sort(client):
    # Changed with on-call approval: arbitrary SQL sort expressions were an injection vector.
    resp = client.get("/admin/orders", query_string={"sort": "CASE WHEN total > 90 THEN 0 ELSE 1 END, id"})
    assert resp.status_code == 400
