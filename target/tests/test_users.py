def test_search_finds_user(client):
    resp = client.get("/users/search", query_string={"name": "bob"})
    assert resp.status_code == 200
    assert resp.get_json() == [{"id": 2, "name": "bob", "email": "bob@example.com"}]


def test_search_unknown_user_is_empty(client):
    resp = client.get("/users/search", query_string={"name": "zoe"})
    assert resp.get_json() == []
