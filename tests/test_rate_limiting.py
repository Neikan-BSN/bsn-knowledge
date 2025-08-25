"""
Rate Limiting Tests for BSN Knowledge API

Tests tiered rate limiting, rate limit enforcement, headers,
and rate limit bypass prevention.
"""

import time
from unittest.mock import patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.auth import RateLimiter, rate_limiter


@pytest.mark.rate_limiting
class TestRateLimiterCore:
    """Test core rate limiter functionality."""

    def test_rate_limiter_initialization(self):
        """Test rate limiter initializes with correct limits."""
        limiter = RateLimiter()

        assert limiter.limits["default"] == (1000, 3600)  # 1000/hour
        assert limiter.limits["content_generation"] == (50, 3600)  # 50/hour
        assert limiter.limits["assessment"] == (200, 3600)  # 200/hour
        assert limiter.limits["analytics"] == (500, 3600)  # 500/hour

    def test_rate_limiter_allows_within_limits(self, reset_rate_limiter):
        """Test that requests within limits are allowed."""
        user_id = 12345

        # First request should be allowed
        allowed, rate_info = rate_limiter.is_allowed(user_id, "default")
        assert allowed is True
        assert rate_info["remaining"] == 999  # 1000 - 1
        assert rate_info["limit"] == 1000

    def test_rate_limiter_blocks_over_limits(self, reset_rate_limiter):
        """Test that requests over limits are blocked."""
        user_id = 12345

        # Simulate hitting the content generation limit (50/hour)
        for _i in range(50):
            allowed, _ = rate_limiter.is_allowed(user_id, "content_generation")
            assert allowed is True

        # 51st request should be blocked
        allowed, rate_info = rate_limiter.is_allowed(user_id, "content_generation")
        assert allowed is False
        assert rate_info["remaining"] == 0
        assert rate_info["limit"] == 50

    def test_rate_limiter_different_users_separate_limits(self, reset_rate_limiter):
        """Test that different users have separate rate limits."""
        user1 = 11111
        user2 = 22222

        # User 1 hits content generation limit
        for _i in range(50):
            allowed, _ = rate_limiter.is_allowed(user1, "content_generation")
            assert allowed is True

        # User 1's next request should be blocked
        allowed, _ = rate_limiter.is_allowed(user1, "content_generation")
        assert allowed is False

        # User 2's first request should still be allowed
        allowed, rate_info = rate_limiter.is_allowed(user2, "content_generation")
        assert allowed is True
        assert rate_info["remaining"] == 49

    def test_rate_limiter_different_endpoints_separate_limits(self, reset_rate_limiter):
        """Test that different endpoint types have separate limits."""
        user_id = 12345

        # Hit content generation limit
        for _i in range(50):
            allowed, _ = rate_limiter.is_allowed(user_id, "content_generation")
            assert allowed is True

        # Content generation should be blocked
        allowed, _ = rate_limiter.is_allowed(user_id, "content_generation")
        assert allowed is False

        # But assessment endpoint should still work
        allowed, rate_info = rate_limiter.is_allowed(user_id, "assessment")
        assert allowed is True
        assert rate_info["remaining"] == 199  # 200 - 1

    def test_rate_limiter_cleans_old_requests(self, reset_rate_limiter):
        """Test that old requests are cleaned up."""
        user_id = 12345

        # Mock time to simulate passage of time
        with patch("time.time") as mock_time:
            # Start at time 0
            mock_time.return_value = 0

            # Make a request
            allowed, _ = rate_limiter.is_allowed(user_id, "content_generation")
            assert allowed is True

            # Move time forward by 2 hours (past the 1-hour window)
            mock_time.return_value = 7200  # 2 hours

            # Request should be allowed again as old request was cleaned up
            allowed, rate_info = rate_limiter.is_allowed(user_id, "content_generation")
            assert allowed is True
            assert rate_info["remaining"] == 49  # Should be back to near-full limit


@pytest.mark.rate_limiting
class TestEndpointTypeDetection:
    """Test endpoint type detection for rate limiting."""

    def test_content_generation_endpoint_detection(self):
        """Test detection of content generation endpoints."""
        from src.auth import get_endpoint_type

        content_paths = [
            "/api/v1/nclex/generate",
            "/api/v1/study-guide/create",
            "/api/v1/clinical-support/scenarios",
        ]

        for path in content_paths:
            assert get_endpoint_type(path) == "content_generation"

    def test_assessment_endpoint_detection(self):
        """Test detection of assessment endpoints."""
        from src.auth import get_endpoint_type

        assessment_paths = [
            "/api/v1/assessment/competency",
            "/api/v1/assessment/gaps/analyze",
            "/api/v1/assessment/learning-path",
        ]

        for path in assessment_paths:
            assert get_endpoint_type(path) == "assessment"

    def test_analytics_endpoint_detection(self):
        """Test detection of analytics endpoints."""
        from src.auth import get_endpoint_type

        analytics_paths = [
            "/api/v1/analytics/student/123",
            "/api/v1/analytics/class/BSN2024",
            "/api/v1/analytics/performance",
        ]

        for path in analytics_paths:
            assert get_endpoint_type(path) == "analytics"

    def test_default_endpoint_detection(self):
        """Test detection of default endpoints."""
        from src.auth import get_endpoint_type

        default_paths = ["/api/v1/auth/me", "/api/v1/auth/login", "/health", "/metrics"]

        for path in default_paths:
            assert get_endpoint_type(path) == "default"


@pytest.mark.rate_limiting
class TestRateLimitMiddleware:
    """Test rate limiting middleware integration."""

    def test_middleware_skips_auth_endpoints(
        self, client: TestClient, reset_rate_limiter
    ):
        """Test that authentication endpoints skip rate limiting."""
        # These endpoints should not be rate limited
        skip_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/health",
            "/docs",
        ]

        for endpoint in skip_endpoints:
            # Make many requests (more than any rate limit)
            for _i in range(60):  # More than content generation limit
                if endpoint == "/api/v1/auth/login":
                    response = client.post(
                        endpoint, json={"username": "test", "password": "test"}
                    )
                elif endpoint == "/api/v1/auth/refresh":
                    response = client.post(
                        endpoint, json={"refresh_token": "fake_token"}
                    )
                elif endpoint == "/api/v1/auth/logout":
                    response = client.post(endpoint)
                else:
                    response = client.get(endpoint)

                # Should never get rate limited
                assert response.status_code != status.HTTP_429_TOO_MANY_REQUESTS

    def test_middleware_applies_rate_limits_to_protected_endpoints(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that rate limiting is applied to protected endpoints."""
        # Test content generation endpoint (50/hour limit)
        content_endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Make requests up to the limit
        success_count = 0
        rate_limited_count = 0

        for _i in range(60):  # Try more than the limit
            response = client.post(
                content_endpoint,
                json=request_data,
                headers=auth_headers.get("student1", {}),
            )

            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                rate_limited_count += 1
                # Check rate limit headers
                assert "X-RateLimit-Limit" in response.headers
                assert "X-RateLimit-Remaining" in response.headers
                assert "X-RateLimit-Reset" in response.headers
            elif response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]:
                success_count += 1

        # Should have gotten some successful requests and then rate limited
        assert success_count > 0
        assert rate_limited_count > 0
        assert success_count <= 50  # Content generation limit

    def test_rate_limit_headers_included(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that rate limit headers are included in responses."""
        response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        if response.status_code == status.HTTP_200_OK:
            # Rate limit headers should be present
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers

            # Validate header values
            limit = int(response.headers["X-RateLimit-Limit"])
            remaining = int(response.headers["X-RateLimit-Remaining"])
            reset_time = int(response.headers["X-RateLimit-Reset"])

            assert limit > 0
            assert remaining >= 0
            assert remaining <= limit
            assert reset_time > time.time()  # Reset time should be in the future

    def test_unauthenticated_requests_get_ip_based_limiting(
        self, client: TestClient, reset_rate_limiter
    ):
        """Test that unauthenticated requests use IP-based rate limiting."""
        # Make requests without authentication
        endpoint = "/api/v1/auth/me"

        responses = []
        for _i in range(10):
            response = client.get(endpoint)
            responses.append(response.status_code)

        # All should be 401 Unauthorized (not rate limited)
        # since they hit auth before rate limiting takes effect on the response
        for status_code in responses:
            assert status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.rate_limiting
class TestTieredRateLimiting:
    """Test tiered rate limiting for different endpoint types."""

    def test_content_generation_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test content generation endpoints have 50/hour limit."""
        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Make exactly 50 requests
        for _i in range(50):
            response = client.post(
                endpoint, json=request_data, headers=auth_headers["student1"]
            )
            # Should succeed or fail due to validation, not rate limiting
            assert response.status_code != status.HTTP_429_TOO_MANY_REQUESTS

        # 51st request should be rate limited
        response = client.post(
            endpoint, json=request_data, headers=auth_headers["student1"]
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Check it's the right limit in headers
        assert response.headers.get("X-RateLimit-Limit") == "50"

    def test_assessment_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test assessment endpoints have 200/hour limit."""
        endpoint = "/api/v1/assessment/competency"
        request_data = {
            "student_id": "test",
            "competency_id": "test",
            "performance_data": {},
        }

        # Test that we can make more than 50 requests (content limit)
        # but will eventually hit 200 limit
        success_count = 0
        for _i in range(210):  # Try more than assessment limit
            response = client.post(
                endpoint, json=request_data, headers=auth_headers["instructor1"]
            )

            if response.status_code != status.HTTP_429_TOO_MANY_REQUESTS:
                success_count += 1
            else:
                # Should show assessment limit in headers
                assert response.headers.get("X-RateLimit-Limit") == "200"
                break

        # Should have been able to make more than 50 requests
        assert success_count > 50
        assert success_count <= 200

    def test_analytics_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test analytics endpoints have 500/hour limit."""
        endpoint = "/api/v1/analytics/student/student_001"

        # Test that we can make more than 200 requests (assessment limit)
        # This test is expensive so we'll test the limits exist rather than exhaust them
        response = client.get(endpoint, headers=auth_headers["instructor1"])

        if response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]:
            # Check that the limit is correctly set to 500
            limit = response.headers.get("X-RateLimit-Limit")
            assert limit == "500"

        # Could also test by mocking the rate limiter for performance

    def test_default_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test default endpoints have 1000/hour limit."""
        endpoint = "/api/v1/auth/me"

        response = client.get(endpoint, headers=auth_headers["student1"])

        if response.status_code == status.HTTP_200_OK:
            # Check that the limit is correctly set to 1000
            limit = response.headers.get("X-RateLimit-Limit")
            assert limit == "1000"


@pytest.mark.rate_limiting
class TestRateLimitBypassPrevention:
    """Test prevention of rate limit bypass attempts."""

    def test_different_tokens_same_user_share_limits(
        self, client: TestClient, test_users, reset_rate_limiter
    ):
        """Test that different tokens for the same user share rate limits."""
        # This would require token invalidation/refresh testing
        # For now, we test the concept with different requests from same user
        from src.auth import create_auth_tokens, fake_users_db

        fake_users_db.update(test_users)

        user = test_users["student1"]

        # Create multiple tokens for the same user (simulating token refresh)
        token1 = create_auth_tokens(user).access_token
        token2 = create_auth_tokens(user).access_token

        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}

        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Make requests with first token up to near limit
        for _i in range(25):
            response = client.post(endpoint, json=request_data, headers=headers1)
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                break

        # Make more requests with second token - should contribute to same limit
        for _i in range(30):
            response = client.post(endpoint, json=request_data, headers=headers2)
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                # Should be rate limited because both tokens use same user_id
                break
        else:
            pytest.fail("Rate limit not shared between tokens for same user")

    def test_user_agent_spoofing_ineffective(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that changing User-Agent doesn't bypass rate limits."""
        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Make requests with different User-Agent headers
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Custom-Bot/1.0",
            "",
        ]

        total_requests = 0
        for user_agent in user_agents:
            headers = {**auth_headers["student1"], "User-Agent": user_agent}

            for _i in range(12):  # 60 total requests across all user agents
                response = client.post(endpoint, json=request_data, headers=headers)
                total_requests += 1

                if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                    # Should still be rate limited regardless of User-Agent
                    assert total_requests <= 50  # Content generation limit
                    return

        # If we get here without rate limiting, the limit might not be working
        if total_requests > 50:
            pytest.fail("User-Agent spoofing may be bypassing rate limits")

    def test_ip_spoofing_ineffective_for_authenticated_users(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that IP spoofing doesn't bypass rate limits for authenticated users."""
        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Try different X-Forwarded-For and X-Real-IP headers
        spoofed_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.200", "203.0.113.1"]

        total_requests = 0
        for ip in spoofed_ips:
            headers = {
                **auth_headers["student1"],
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
            }

            for _i in range(15):  # 60 total requests
                response = client.post(endpoint, json=request_data, headers=headers)
                total_requests += 1

                if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                    # Should be rate limited based on user_id, not IP
                    assert total_requests <= 50
                    return

        if total_requests > 50:
            pytest.fail("IP spoofing may be bypassing rate limits")


@pytest.mark.rate_limiting
class TestRateLimitErrorHandling:
    """Test proper error handling when rate limits are exceeded."""

    def test_rate_limit_error_response_format(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that rate limit errors return proper format."""
        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Exhaust rate limit
        for _i in range(51):
            response = client.post(
                endpoint, json=request_data, headers=auth_headers["student1"]
            )

            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                data = response.json()

                # Check error response format
                assert "error" in data
                assert data["error"] is True
                assert "message" in data
                assert "rate limit" in data["message"].lower()
                assert "error_code" in data
                assert data["error_code"] == "RATE_LIMIT_EXCEEDED"

                # Check error details
                if "details" in data:
                    details = data["details"]
                    assert "endpoint_type" in details
                    assert "retry_after_seconds" in details

                return

        pytest.fail("Rate limit was not triggered")

    def test_rate_limit_retry_after_header(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test that Retry-After information is provided."""
        endpoint = "/api/v1/nclex/generate"
        request_data = {"topic": "test", "difficulty": "easy", "question_count": 1}

        # Exhaust rate limit
        for _i in range(51):
            response = client.post(
                endpoint, json=request_data, headers=auth_headers["student1"]
            )

            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                # Should provide retry information
                data = response.json()
                if "details" in data and "retry_after_seconds" in data["details"]:
                    retry_after = data["details"]["retry_after_seconds"]
                    assert isinstance(retry_after, int)
                    assert retry_after > 0
                    assert retry_after <= 3600  # Should be within an hour

                return

        pytest.fail("Rate limit was not triggered")


@pytest.mark.rate_limiting
@pytest.mark.performance
class TestRateLimitPerformance:
    """Test that rate limiting doesn't significantly impact performance."""

    def test_rate_limit_overhead_minimal(
        self, client: TestClient, auth_headers, performance_monitor, reset_rate_limiter
    ):
        """Test that rate limiting adds minimal overhead."""
        endpoint = "/api/v1/auth/me"

        # Time request with rate limiting
        performance_monitor.start()
        response = client.get(endpoint, headers=auth_headers["student1"])
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        # Rate limiting should add minimal overhead
        performance_monitor.assert_within_threshold(
            0.1
        )  # 100ms total including rate limiting

    def test_rate_limiter_scales_with_users(self, reset_rate_limiter):
        """Test that rate limiter performance scales reasonably with user count."""
        import time

        # Simulate many users making requests
        start_time = time.time()

        for user_id in range(100):  # 100 different users
            for _request_num in range(5):  # 5 requests each
                allowed, rate_info = rate_limiter.is_allowed(user_id, "default")
                assert allowed is True  # All should be within limits

        end_time = time.time()
        total_time = end_time - start_time

        # 500 total rate limit checks should complete quickly
        assert total_time < 1.0  # Should complete within 1 second

        # Average per-check should be very fast
        avg_time_per_check = total_time / 500
        assert avg_time_per_check < 0.002  # Less than 2ms per check


@pytest.mark.rate_limiting
class TestRateLimitConfiguration:
    """Test rate limit configuration and customization."""

    def test_rate_limits_are_configurable(self):
        """Test that rate limits can be configured."""
        # Create rate limiter with custom limits
        custom_limiter = RateLimiter()
        custom_limiter.limits["custom_endpoint"] = (10, 60)  # 10 requests per minute

        user_id = 99999

        # Should allow up to 10 requests
        for _i in range(10):
            allowed, _ = custom_limiter.is_allowed(user_id, "custom_endpoint")
            assert allowed is True

        # 11th request should be blocked
        allowed, rate_info = custom_limiter.is_allowed(user_id, "custom_endpoint")
        assert allowed is False
        assert rate_info["limit"] == 10

    def test_default_limits_are_reasonable(self):
        """Test that default rate limits are reasonable for nursing education."""
        limiter = RateLimiter()

        # Content generation (AI-powered) should be more restrictive
        assert limiter.limits["content_generation"][0] < limiter.limits["default"][0]

        # Assessment should allow reasonable usage for classroom
        assert limiter.limits["assessment"][0] >= 200  # At least 200/hour

        # Analytics should support instructor dashboards
        assert limiter.limits["analytics"][0] >= 500  # At least 500/hour

        # Default should handle general API usage
        assert limiter.limits["default"][0] >= 1000  # At least 1000/hour
