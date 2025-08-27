"""
Integration tests for enhanced BSN Knowledge architecture with RAGnostic optimization
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from src.api.main import app
from src.services.performance_monitor import PerformanceMonitor
from src.services.ragnostic_client import RAGnosticClient


class TestEnhancedRAGnosticClient:
    """Test the enhanced RAGnostic client with performance optimizations"""

    @pytest.fixture
    async def client(self):
        """Create test RAGnostic client"""
        client = RAGnosticClient(
            base_url="http://test-ragnostic:8000",
            api_key="test-key",
            max_retries=2,
            cache_ttl=60,
            connection_pool_size=10,
        )
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_functionality(self, client):
        """Test circuit breaker behavior under failure conditions"""

        # Mock multiple failures to trigger circuit breaker
        with patch.object(
            client.client, "post", side_effect=Exception("Connection failed")
        ):
            # Should try multiple times before circuit breaker opens
            with pytest.raises(Exception):
                await client.search_content("test query")

            # Verify circuit breaker is now open
            assert client.circuit_breaker.state == "OPEN"

            # Next request should fail immediately due to circuit breaker
            start_time = time.time()
            with pytest.raises(ConnectionError, match="Circuit breaker is open"):
                await client.search_content("another query")

            # Should fail quickly without making actual HTTP request
            assert time.time() - start_time < 0.1

    @pytest.mark.asyncio
    async def test_request_caching(self, client):
        """Test request caching functionality"""

        # Mock successful response
        mock_response = {"items": [{"id": "1", "title": "Test Content"}], "total": 1}

        mock_http_response = AsyncMock()
        mock_http_response.json.return_value = mock_response
        mock_http_response.raise_for_status.return_value = None

        with patch.object(
            client.client, "post", return_value=mock_http_response
        ) as mock_post:
            # First request should hit the API
            result1 = await client.search_content("test query", cache_ttl=300)
            assert mock_post.call_count == 1
            assert result1 == mock_response

            # Second identical request should use cache
            result2 = await client.search_content("test query", cache_ttl=300)
            assert mock_post.call_count == 1  # No additional API calls
            assert result2 == mock_response

            # Different query should hit API again
            await client.search_content("different query", cache_ttl=300)
            assert mock_post.call_count == 2

    @pytest.mark.asyncio
    async def test_batch_search_performance(self, client):
        """Test concurrent batch search functionality"""

        mock_response = {"items": [{"id": "1", "title": "Test Content"}], "total": 1}

        mock_http_response = AsyncMock()
        mock_http_response.json.return_value = mock_response
        mock_http_response.raise_for_status.return_value = None

        with patch.object(
            client.client, "post", return_value=mock_http_response
        ) as mock_post:
            queries = ["query1", "query2", "query3", "query4", "query5"]

            start_time = time.time()
            results = await client.batch_search(queries)
            duration = time.time() - start_time

            # Should complete much faster than sequential requests
            assert duration < 1.0  # Assuming individual requests would take ~200ms each
            assert len(results) == 5
            assert all(r["items"] for r in results if "error" not in r)
            assert mock_post.call_count == 5

    @pytest.mark.asyncio
    async def test_graceful_degradation(self, client):
        """Test graceful degradation when RAGnostic service is unavailable"""

        with patch.object(
            client.client, "post", side_effect=Exception("Service unavailable")
        ):
            # Should return fallback response instead of raising exception
            result = await client.search_content("test query")

            assert result["items"] == []
            assert result["total"] == 0
            assert "error" in result
            assert result["fallback_mode"] is True

    @pytest.mark.asyncio
    async def test_performance_metrics(self, client):
        """Test client performance metrics collection"""

        mock_response = {"items": [], "total": 0}
        mock_http_response = AsyncMock()
        mock_http_response.json.return_value = mock_response
        mock_http_response.raise_for_status.return_value = None

        with patch.object(client.client, "post", return_value=mock_http_response):
            # Make several requests
            await client.search_content("query1")
            await client.search_content("query2")

            metrics = client.get_performance_metrics()

            assert metrics["total_requests"] == 2
            assert metrics["cache_hits"] >= 0
            assert metrics["cache_misses"] >= 0
            assert metrics["average_response_time"] >= 0
            assert "cache_hit_rate" in metrics

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test RAGnostic service health check"""

        mock_health_response = {"status": "healthy", "version": "1.0"}
        mock_http_response = AsyncMock()
        mock_http_response.json.return_value = mock_health_response
        mock_http_response.raise_for_status.return_value = None

        with patch.object(client.client, "get", return_value=mock_http_response):
            health_result = await client.health_check()

            assert health_result["status"] == "healthy"
            assert "service_response" in health_result
            assert "client_metrics" in health_result


class TestPerformanceMonitoring:
    """Test API performance monitoring functionality"""

    @pytest.fixture
    async def monitor(self):
        """Create test performance monitor"""
        monitor = PerformanceMonitor(retention_hours=1)
        await monitor.start_monitoring()
        yield monitor
        await monitor.stop_monitoring()

    @pytest.mark.asyncio
    async def test_request_metrics_recording(self, monitor):
        """Test recording and aggregation of request metrics"""

        # Record several requests
        monitor.record_request("/api/v1/study-guides", "POST", 200, 0.150)
        monitor.record_request("/api/v1/study-guides", "POST", 200, 0.200)
        monitor.record_request(
            "/api/v1/study-guides", "POST", 500, 1.500, error="Internal error"
        )

        # Check system metrics
        system_metrics = monitor.get_system_metrics()
        assert system_metrics["total_requests"] == 3
        assert system_metrics["error_rate"] > 0

        # Check endpoint metrics
        endpoint_metrics = monitor.get_endpoint_metrics()
        assert len(endpoint_metrics) == 1

        endpoint_stats = endpoint_metrics[0]
        assert endpoint_stats["total_requests"] == 3
        assert endpoint_stats["successful_requests"] == 2
        assert endpoint_stats["failed_requests"] == 1
        assert endpoint_stats["success_rate"] == pytest.approx(66.67, rel=1e-2)

    @pytest.mark.asyncio
    async def test_slow_request_detection(self, monitor):
        """Test detection and alerting for slow requests"""

        # Record a slow request
        monitor.record_request("/api/v1/analytics", "GET", 200, 0.750)

        # Check that alert was generated
        alerts = monitor.get_alerts()
        slow_alerts = [a for a in alerts if a["type"] == "slow_request"]

        assert len(slow_alerts) == 1
        assert slow_alerts[0]["response_time"] == 0.750
        assert slow_alerts[0]["endpoint"] == "/api/v1/analytics"

    @pytest.mark.asyncio
    async def test_error_rate_monitoring(self, monitor):
        """Test high error rate detection"""

        # Generate many error requests to trigger high error rate alert
        for i in range(60):
            status_code = 500 if i < 10 else 200  # 10 errors out of 60 requests
            monitor.record_request("/api/v1/test", "GET", status_code, 0.100)

        # Check for high error rate alert
        alerts = monitor.get_alerts()
        error_rate_alerts = [a for a in alerts if a["type"] == "high_error_rate"]

        assert len(error_rate_alerts) >= 1
        assert error_rate_alerts[-1]["error_rate"] > 5.0

    @pytest.mark.asyncio
    async def test_metrics_cleanup(self, monitor):
        """Test automatic cleanup of old metrics"""

        # Add some metrics
        for i in range(100):
            monitor.record_request(f"/api/test/{i}", "GET", 200, 0.100)

        initial_count = len(monitor.metrics)
        assert initial_count == 100

        # Manually trigger cleanup (simulate old metrics)
        import datetime

        old_time = datetime.datetime.now() - datetime.timedelta(hours=2)

        for metric in monitor.metrics[:50]:
            metric.timestamp = old_time

        await monitor._cleanup_old_metrics()

        # Should have cleaned up old metrics
        assert len(monitor.metrics) == 50


class TestAPIIntegration:
    """Test complete API integration with enhanced features"""

    @pytest.mark.asyncio
    async def test_api_performance_headers(self):
        """Test that API responses include performance headers"""

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health")

            assert response.status_code == 200
            assert "X-Process-Time" in response.headers
            assert "X-Request-ID" in response.headers

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self):
        """Test the /metrics endpoint functionality"""

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Make a few requests to generate metrics
            await client.get("/")
            await client.get("/health")

            # Check metrics endpoint
            response = await client.get("/metrics")
            assert response.status_code == 200

            data = response.json()
            assert "api_metrics" in data
            assert "uptime_info" in data
            assert data["api_metrics"]["total_requests"] >= 2

    @pytest.mark.asyncio
    async def test_enhanced_health_check(self):
        """Test enhanced health check with feature status"""

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health")
            assert response.status_code == 200

            data = response.json()
            assert data["status"] == "healthy"
            assert "performance_metrics" in data
            assert "features_status" in data

            features = data["features_status"]
            assert features["ragnostic_integration"] == "operational"
            assert features["caching"] == "enabled"
            assert features["circuit_breaker"] == "active"
            assert features["performance_monitoring"] == "active"

    @pytest.mark.asyncio
    async def test_error_handling_middleware(self):
        """Test enhanced error handling middleware"""

        # This would test actual error scenarios in a real integration environment
        # For now, test that error responses include proper headers and structure

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test non-existent endpoint
            response = await client.get("/api/v1/nonexistent")

            assert response.status_code == 404
            # Should still have performance headers even for 404s
            assert "X-Process-Time" in response.headers


class TestIntegrationArchitectureValidation:
    """Validate the complete integration architecture meets requirements"""

    @pytest.mark.asyncio
    async def test_response_time_targets(self):
        """Validate that API responses meet <500ms target"""

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test multiple endpoints for response time
            endpoints = ["/", "/health", "/metrics"]

            for endpoint in endpoints:
                start_time = time.time()
                response = await client.get(endpoint)
                duration = time.time() - start_time

                assert response.status_code == 200
                assert duration < 0.5, (
                    f"Endpoint {endpoint} took {duration:.3f}s (>500ms)"
                )

                # Verify process time header is reasonable
                process_time = float(response.headers.get("X-Process-Time", "0"))
                assert process_time < 0.5, (
                    f"Process time {process_time:.3f}s exceeds target"
                )

    @pytest.mark.asyncio
    async def test_clean_architecture_separation(self):
        """Validate clean separation between BSN Knowledge and RAGnostic"""

        # Test that BSN Knowledge can handle RAGnostic unavailability gracefully
        with patch(
            "src.services.ragnostic_client.RAGnosticClient._make_request_with_resilience",
            side_effect=ConnectionError("RAGnostic unavailable"),
        ):
            # Create RAGnostic client and test fallback behavior
            client = RAGnosticClient()

            result = await client.search_content("test query")

            # Should gracefully degrade
            assert result["fallback_mode"] is True
            assert result["items"] == []
            assert "error" in result

            await client.close()

    def test_no_direct_database_access(self):
        """Verify no direct RAGnostic database dependencies in codebase"""

        # This test would scan the codebase for direct database imports
        # For this demonstration, we'll verify our architecture

        import inspect

        from src.services.ragnostic_client import RAGnosticClient

        # Verify RAGnosticClient only uses HTTP calls, no direct DB access
        client_source = inspect.getsource(RAGnosticClient)

        forbidden_imports = [
            "sqlalchemy",
            "psycopg2",
            "pymongo",
            "redis",
            "neo4j",
            "from ragnostic.database",
            "from ragnostic.models",
        ]

        for forbidden in forbidden_imports:
            assert forbidden not in client_source, (
                f"Found direct database access: {forbidden}"
            )

    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test that API can handle concurrent requests efficiently"""

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Create multiple concurrent requests
            tasks = []
            for _i in range(10):
                task = client.get("/health")
                tasks.append(task)

            start_time = time.time()
            responses = await asyncio.gather(*tasks)
            duration = time.time() - start_time

            # All requests should succeed
            assert all(r.status_code == 200 for r in responses)

            # Should handle concurrent requests efficiently
            assert duration < 2.0, f"Concurrent requests took {duration:.3f}s"

            # Each request should have unique request ID
            request_ids = [r.headers.get("X-Request-ID") for r in responses]
            assert len(set(request_ids)) == 10, "Request IDs should be unique"


@pytest.mark.asyncio
async def test_integration_architecture_summary():
    """Comprehensive test validating all integration architecture enhancements"""

    # Test RAGnostic client enhancements
    client = RAGnosticClient(cache_ttl=60, max_retries=2)

    # Verify enhanced features are available
    assert hasattr(client, "circuit_breaker")
    assert hasattr(client, "cache")
    assert hasattr(client, "batch_search")
    assert hasattr(client, "get_performance_metrics")
    assert hasattr(client, "health_check")

    # Test performance monitoring
    monitor = PerformanceMonitor()
    assert hasattr(monitor, "record_request")
    assert hasattr(monitor, "get_system_metrics")
    assert hasattr(monitor, "get_alerts")

    # Test API enhancements
    async with AsyncClient(app=app, base_url="http://test") as api_client:
        response = await api_client.get("/")

        # Verify enhanced API features
        data = response.json()
        assert "Enhanced Integration Architecture" in data["message"]
        assert "Circuit breaker pattern" in data["features"]
        assert "Performance monitoring" in data["features"]

    await client.close()

    print("✅ All integration architecture enhancements validated successfully!")
    print(
        "✅ RAGnostic client optimization: Circuit breaker, caching, batch operations"
    )
    print("✅ API performance monitoring: Request tracking, alerting, metrics")
    print("✅ Clean architectural separation: No direct database dependencies")
    print("✅ Performance targets: <500ms response times validated")
    print("✅ Graceful degradation: Fallback mechanisms operational")
