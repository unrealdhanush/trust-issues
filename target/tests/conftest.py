import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "shop.sqlite"))
    return app.test_client()
