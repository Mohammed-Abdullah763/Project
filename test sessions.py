"""
tests/test_sessions.py
──────────────────────
Integration tests for study session endpoints.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.database import Base, get_db
from app.main import app

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSession = async_sessionmaker(test_engine, expire_on_commit=False)


async def override_get_db():
    async with TestSession() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app.dependency_overrides[get_db] = override_get_db
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient) -> dict:
    """Register a user and return auth headers."""
    await client.post("/api/v1/auth/register", json={
        "email": "test@test.com", "username": "testuser", "password": "SecurePass1"
    })
    resp = await client.post("/api/v1/auth/login", json={
        "email": "test@test.com", "password": "SecurePass1"
    })
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/sessions", json={
        "title": "Physics Chapter 1",
        "source_text": "Quantum mechanics is the study of subatomic particles."
    }, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Physics Chapter 1"
    assert data["word_count"] > 0


@pytest.mark.asyncio
async def test_list_sessions_paginated(client: AsyncClient, auth_headers: dict):
    # Create 3 sessions
    for i in range(3):
        await client.post("/api/v1/sessions", json={"title": f"Session {i}"}, headers=auth_headers)

    resp = await client.get("/api/v1/sessions?page=1&page_size=2", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2
    assert data["total_pages"] == 2


@pytest.mark.asyncio
async def test_get_session(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v1/sessions", json={"title": "My Session"}, headers=auth_headers)
    session_id = create.json()["id"]

    resp = await client.get(f"/api/v1/sessions/{session_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == session_id


@pytest.mark.asyncio
async def test_get_session_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v1/sessions/99999", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_session(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v1/sessions", json={"title": "To Delete"}, headers=auth_headers)
    session_id = create.json()["id"]

    resp = await client.delete(f"/api/v1/sessions/{session_id}", headers=auth_headers)
    assert resp.status_code == 200

    # Should be gone
    resp = await client.get(f"/api/v1/sessions/{session_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sessions_require_auth(client: AsyncClient):
    resp = await client.get("/api/v1/sessions")
    assert resp.status_code == 401
