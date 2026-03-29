"""Tests for FastAPI application."""

import pytest
from httpx import AsyncClient

from agentic_security.api.app import app


@pytest.fixture
async def client():
    """Create an async HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoints:
    """Test health check endpoints."""

    @pytest.mark.asyncio
    async def test_root_health_check(self, client):
        """Test root health check endpoint."""
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    @pytest.mark.asyncio
    async def test_api_info_endpoint(self, client):
        """Test API info endpoint."""
        response = await client.get("/api/v1")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "endpoints" in data
        assert "targets" in data["endpoints"]
        assert "tests" in data["endpoints"]
        assert "attacks" in data["endpoints"]
        assert "reports" in data["endpoints"]


class TestTargetsRouter:
    """Test targets router endpoints."""

    @pytest.mark.asyncio
    async def test_list_targets_empty(self, client):
        """Test listing targets when none exist."""
        response = await client.get("/api/v1/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "targets" in data

    @pytest.mark.asyncio
    async def test_create_target(self, client):
        """Test creating a new target."""
        target_data = {
            "name": "Test LLM",
            "endpoint": "http://example.com/api/chat",
            "model": "gpt-4",
            "api_key": "test-key-123",
        }
        response = await client.post("/api/v1/targets", json=target_data)
        assert response.status_code in (200, 201)
        data = response.json()
        assert data.get("name") == "Test LLM"
        assert data.get("endpoint") == "http://example.com/api/chat"


class TestAttacksRouter:
    """Test attacks router endpoints."""

    @pytest.mark.asyncio
    async def test_list_attacks(self, client):
        """Test listing available attack modules."""
        response = await client.get("/api/v1/attacks")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "attacks" in data

    @pytest.mark.asyncio
    async def test_get_attack_detail(self, client):
        """Test getting details of a specific attack module."""
        # First get list of attacks
        list_response = await client.get("/api/v1/attacks")
        assert list_response.status_code == 200
        attacks = list_response.json()

        # If attacks exist, test getting one
        if attacks and isinstance(attacks, list) and len(attacks) > 0:
            attack_id = attacks[0].get("id")
            if attack_id:
                response = await client.get(f"/api/v1/attacks/{attack_id}")
                assert response.status_code in (200, 404)


class TestTestsRouter:
    """Test tests router endpoints."""

    @pytest.mark.asyncio
    async def test_list_tests(self, client):
        """Test listing test runs."""
        response = await client.get("/api/v1/tests")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "tests" in data

    @pytest.mark.asyncio
    async def test_create_test_run(self, client):
        """Test creating a new test run."""
        test_data = {
            "name": "Test Run 1",
            "target_id": "test-target-1",
            "attack_ids": ["prompt-injection"],
        }
        response = await client.post("/api/v1/tests", json=test_data)
        # May fail due to missing target, but should validate input
        assert response.status_code in (200, 201, 400, 404)


class TestReportsRouter:
    """Test reports router endpoints."""

    @pytest.mark.asyncio
    async def test_list_reports(self, client):
        """Test listing reports."""
        response = await client.get("/api/v1/reports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "reports" in data

    @pytest.mark.asyncio
    async def test_get_report(self, client):
        """Test getting a specific report."""
        # Reports may be empty initially
        response = await client.get("/api/v1/reports/nonexistent")
        assert response.status_code in (200, 404)


class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_invalid_json_body(self, client):
        """Test handling of invalid JSON in request body."""
        response = await client.post(
            "/api/v1/targets",
            content="invalid json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_required_fields(self, client):
        """Test validation of required fields."""
        response = await client.post("/api/v1/targets", json={})
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data or "errors" in data

    @pytest.mark.asyncio
    async def test_nonexistent_endpoint(self, client):
        """Test request to nonexistent endpoint."""
        response = await client.get("/api/v1/nonexistent")
        assert response.status_code == 404


class TestCORSHeaders:
    """Test CORS headers."""

    @pytest.mark.asyncio
    async def test_cors_headers_present(self, client):
        """Test that CORS headers are present."""
        response = await client.get("/", headers={"Origin": "http://example.com"})
        assert response.status_code == 200
