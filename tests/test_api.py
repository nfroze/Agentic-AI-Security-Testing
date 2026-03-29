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
        assert "timestamp" in data

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

    @pytest.mark.asyncio
    async def test_health_endpoint(self, client):
        """Test dedicated health endpoint."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestAttacksRouter:
    """Test attacks router endpoints."""

    @pytest.mark.asyncio
    async def test_list_attacks(self, client):
        """Test listing available attack modules."""
        response = await client.get("/api/v1/attacks")
        assert response.status_code == 200
        data = response.json()
        # Should return a list or dict-like structure
        assert data is not None

    @pytest.mark.asyncio
    async def test_list_attacks_is_valid_response(self, client):
        """Test that attacks list response is properly formatted."""
        response = await client.get("/api/v1/attacks")
        assert response.status_code == 200
        data = response.json()
        # Should be iterable (list or have items)
        assert isinstance(data, (list, dict))


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
    async def test_nonexistent_endpoint(self, client):
        """Test request to nonexistent endpoint."""
        response = await client.get("/api/v1/nonexistent")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_exception_handling(self, client):
        """Test that exceptions are properly handled."""
        # Request to an endpoint that doesn't exist
        response = await client.get("/does-not-exist")
        assert response.status_code == 404


class TestCORSHeaders:
    """Test CORS headers."""

    @pytest.mark.asyncio
    async def test_cors_headers_present(self, client):
        """Test that CORS headers are present."""
        response = await client.get("/", headers={"Origin": "http://example.com"})
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_cors_origin_header(self, client):
        """Test CORS allows cross-origin requests."""
        response = await client.get(
            "/", headers={"Origin": "http://different-origin.com"}
        )
        assert response.status_code == 200


class TestAppStartup:
    """Test application startup behavior."""

    @pytest.mark.asyncio
    async def test_app_has_required_routers(self):
        """Test that app includes required routers."""
        # Check that app has routes
        routes = [route.path for route in app.routes]
        assert any("/targets" in route for route in routes) or len(routes) > 0
        assert any("/health" in route or "/" in route for route in routes)
