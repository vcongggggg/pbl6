import os

import pytest
from fastapi.testclient import TestClient

# Ensure test environment variables are set
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./data/test_waf.db"

# Remove existing stale test db before importing and initializing
test_db_path = "./data/test_waf.db"
if os.path.exists(test_db_path):
    try:
        os.remove(test_db_path)
    except OSError:
        pass

from app.db.base import Base  # noqa: E402
from app.db.session import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initializes clean test database schema."""
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield
    # Cleanup test db file if exists
    Base.metadata.drop_all(bind=engine)
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except OSError:
            pass


@pytest.fixture
def client() -> TestClient:
    """Provides a TestClient instance for testing FastAPI routes."""
    with TestClient(app) as test_client:
        yield test_client
