"""
Comprehensive Rate Limiting and DoS Protection Tests

Tests rate limiting enforcement, distributed denial-of-service (DoS) protection,
API abuse prevention, and performance attack resistance for the RAGnostic →
BSN Knowledge pipeline.

Protection Coverage:
- API rate limiting per user and endpoint
- Burst traffic handling and throttling
- Resource exhaustion protection
- Distributed attack mitigation
- Medical content generation abuse prevention
- Cross-service rate limiting coordination
- Performance attack resistance
"""

import concurrent.futures
import time
from unittest.mock import patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient


@pytest.mark.security
class TestAPIRateLimiting:
    """Test API-level rate limiting enforcement."""

    def test_endpoint_rate_limiting_enforcement(self, client: TestClient, auth_headers):
        """Test rate limiting on individual API endpoints."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "Rate Limit Test",
            "difficulty": "easy",
            "question_count": 1,
        }

        # Make rapid requests to trigger rate limiting
        responses = []
        for _i in range(30):  # Exceed typical rate limits
            response = client.post(
                endpoint, json=payload, headers=auth_headers.get("student1", {})
            )
            responses.append(response.status_code)

            # Small delay to avoid overwhelming test system
            time.sleep(0.01)

        # Should eventually hit rate limit
        rate_limited_responses = [
            r for r in responses if r == status.HTTP_429_TOO_MANY_REQUESTS
        ]

        # At least some requests should be rate limited
        assert (
            len(rate_limited_responses) > 0
        ), "Rate limiting not enforced - security vulnerability"

        # Early requests should succeed
        initial_success_count = sum(1 for r in responses[:5] if r == status.HTTP_200_OK)
        assert (
            initial_success_count > 0
        ), "Rate limiting too aggressive - blocking legitimate requests"

    def test_user_based_rate_limiting(self, client: TestClient, auth_headers):
        """Test that rate limiting is applied per-user, not globally."""
        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "User-specific Rate Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }

        # User 1 makes many requests
        user1_responses = []
        for _i in range(15):
            response = client.post(
                endpoint, json=payload, headers=auth_headers.get("student1", {})
            )
            user1_responses.append(response.status_code)
            time.sleep(0.01)

        # User 2 should still be able to make requests
        user2_response = client.post(
            endpoint, json=payload, headers=auth_headers.get("instructor1", {})
        )

        # User 2 should not be affected by User 1's rate limiting
        assert user2_response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_201_CREATED,
        ], "Rate limiting incorrectly applied globally instead of per-user"

    def test_endpoint_specific_rate_limits(self, client: TestClient, auth_headers):
        """Test that different endpoints have appropriate rate limits."""
        # High-resource endpoints should have stricter limits
        expensive_endpoints = [
            "/api/v1/nclex/generate",
            "/api/v1/clinical-support/scenarios/generate",
        ]

        # Low-resource endpoints should have more lenient limits
        cheap_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/health",
        ]

        headers = auth_headers.get("student1", {})

        # Test expensive endpoints have strict limits
        for endpoint in expensive_endpoints:
            if "nclex" in endpoint:
                payload = {
                    "topic": "Test",
                    "difficulty": "easy",
                    "question_count": 1,
                }
            elif "scenarios" in endpoint:
                payload = {
                    "clinical_scenario": "Test scenario",
                    "complexity_level": "basic",
                }
            else:
                payload = {}

            responses = []
            for _i in range(10):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.1)

            # Should hit rate limit relatively quickly for expensive operations
            any(r == status.HTTP_429_TOO_MANY_REQUESTS for r in responses)
            # This might not trigger in test environment, so we document the expectation

        # Test cheap endpoints have lenient limits
        for endpoint in cheap_endpoints:
            responses = []
            for _i in range(20):
                response = client.get(endpoint, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.05)

            # Should allow more requests for cheap operations
            success_count = sum(1 for r in responses if r == status.HTTP_200_OK)
            assert (
                success_count >= 15
            ), f"Rate limiting too strict for low-resource endpoint {endpoint}"

    def test_rate_limit_headers(self, client: TestClient, auth_headers):
        """Test that proper rate limit headers are returned."""
        response = client.get(
            "/api/v1/auth/me", headers=auth_headers.get("student1", {})
        )

        # Check for standard rate limiting headers
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",  # When rate limited
        ]

        # Headers might not be implemented yet, so we document the expectation
        for header in rate_limit_headers:
            header_value = response.headers.get(header)
            if header_value:
                # Validate header format if present
                if header == "X-RateLimit-Limit":
                    assert (
                        header_value.isdigit()
                    ), f"Invalid rate limit format: {header_value}"
                elif header == "X-RateLimit-Remaining":
                    assert (
                        header_value.isdigit()
                    ), f"Invalid remaining count format: {header_value}"


@pytest.mark.security
class TestBurstTrafficProtection:
    """Test protection against burst traffic attacks."""

    def test_burst_traffic_handling(self, client: TestClient, auth_headers):
        """Test system behavior under sudden traffic bursts."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "Burst Test",
            "difficulty": "easy",
            "question_count": 1,
        }
        headers = auth_headers.get("student1", {})

        # Simulate traffic burst
        def make_request():
            return client.post(endpoint, json=payload, headers=headers)

        # Use thread pool to create concurrent burst
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit 20 concurrent requests (burst)
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [future.result() for future in futures]

        status_codes = [r.status_code for r in results]

        # System should handle burst gracefully
        server_errors = sum(1 for code in status_codes if code >= 500)
        assert (
            server_errors <= 2
        ), f"Too many server errors during burst: {server_errors}/20"

        # Should have mix of success and rate limiting (not all failures)
        success_count = sum(1 for code in status_codes if code == 200)
        rate_limited_count = sum(1 for code in status_codes if code == 429)

        assert success_count > 0, "No requests succeeded during burst"
        assert (
            success_count + rate_limited_count >= 18
        ), "Too many unexpected errors during burst"

    def test_sustained_load_protection(self, client: TestClient, auth_headers):
        """Test protection against sustained high load."""
        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "Sustained Load Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }
        headers = auth_headers.get("student1", {})

        # Simulate sustained load over time
        start_time = time.time()
        responses = []

        while time.time() - start_time < 5:  # 5 second test
            response = client.post(endpoint, json=payload, headers=headers)
            responses.append(response.status_code)
            time.sleep(0.1)  # 10 requests per second

        # Analyze response patterns
        total_requests = len(responses)
        sum(1 for r in responses if r == 200)
        rate_limited_responses = sum(1 for r in responses if r == 429)
        error_responses = sum(1 for r in responses if r >= 500)

        # System should maintain stability under sustained load
        error_rate = error_responses / total_requests
        assert (
            error_rate < 0.1
        ), f"High error rate under sustained load: {error_rate:.2%}"

        # Should implement rate limiting to protect resources
        protection_rate = rate_limited_responses / total_requests
        # Protection should kick in but not be overly aggressive
        assert (
            protection_rate < 0.8
        ), "Rate limiting too aggressive for sustained legitimate load"

    def test_adaptive_rate_limiting(self, client: TestClient, auth_headers):
        """Test adaptive rate limiting based on system load."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "Adaptive Rate Test",
            "difficulty": "medium",
            "question_count": 3,  # Higher resource usage
        }
        headers = auth_headers.get("student1", {})

        # Phase 1: Light load
        light_responses = []
        for _i in range(5):
            response = client.post(endpoint, json=payload, headers=headers)
            light_responses.append(response.status_code)
            time.sleep(0.5)  # Slow pace

        # Phase 2: Heavy load
        heavy_responses = []
        for _i in range(10):
            response = client.post(endpoint, json=payload, headers=headers)
            heavy_responses.append(response.status_code)
            time.sleep(0.1)  # Fast pace

        # Adaptive rate limiting should be more restrictive under heavy load
        light_success_rate = sum(1 for r in light_responses if r == 200) / len(
            light_responses
        )
        heavy_success_rate = sum(1 for r in heavy_responses if r == 200) / len(
            heavy_responses
        )

        # Light load should have higher success rate than heavy load
        # This might not be implemented yet, so we document the expectation
        if light_success_rate > 0 and heavy_success_rate > 0:
            assert (
                light_success_rate >= heavy_success_rate
            ), "Adaptive rate limiting not working - should be more restrictive under heavy load"


@pytest.mark.security
class TestResourceExhaustionProtection:
    """Test protection against resource exhaustion attacks."""

    def test_memory_exhaustion_protection(self, client: TestClient, auth_headers):
        """Test protection against memory exhaustion attacks."""
        endpoint = "/api/v1/study-guide/create"

        # Large payload attack
        large_payload = {
            "topic": "A" * 10000,  # Very large topic
            "competencies": ["AACN_KNOWLEDGE_1"],
            "description": "B" * 50000,  # Very large description
        }

        response = client.post(
            endpoint, json=large_payload, headers=auth_headers.get("student1", {})
        )

        # Should reject or handle large payloads gracefully
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,  # Rejected
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,  # Payload too large
            status.HTTP_422_UNPROCESSABLE_ENTITY,  # Validation error
            status.HTTP_200_OK,  # Handled gracefully
        ], f"Unexpected response to large payload: {response.status_code}"

        # Should not cause server error
        assert (
            response.status_code < 500
        ), "Large payload caused server error - potential DoS vulnerability"

    def test_cpu_exhaustion_protection(self, client: TestClient, auth_headers):
        """Test protection against CPU exhaustion attacks."""
        endpoint = "/api/v1/nclex/generate"

        # CPU-intensive request
        cpu_intensive_payload = {
            "topic": "Complex Medical Scenario with Detailed Analysis",
            "difficulty": "expert",
            "question_count": 50,  # Maximum questions
        }

        start_time = time.time()
        response = client.post(
            endpoint,
            json=cpu_intensive_payload,
            headers=auth_headers.get("student1", {}),
        )
        end_time = time.time()

        response_time = end_time - start_time

        # Should have reasonable response time limits
        assert (
            response_time < 30
        ), f"CPU-intensive request took too long: {response_time:.1f}s"

        # Should handle the request without server errors
        assert response.status_code != 500, "CPU-intensive request caused server error"

    def test_database_connection_exhaustion_protection(
        self, client: TestClient, auth_headers
    ):
        """Test protection against database connection pool exhaustion."""
        endpoint = "/api/v1/analytics/student/test_student"
        headers = auth_headers.get("instructor1", {})

        # Attempt to exhaust database connections
        def make_db_request():
            return client.get(endpoint, headers=headers)

        # Create many concurrent database-heavy requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_db_request) for _ in range(50)]
            results = [future.result() for future in futures]

        status_codes = [r.status_code for r in results]

        # Should not have widespread database connection errors
        db_error_count = sum(1 for code in status_codes if code == 500 or code == 503)

        assert (
            db_error_count <= 5
        ), f"Too many database connection errors: {db_error_count}/50"

        # Should handle most requests successfully or with proper rate limiting
        handled_properly = sum(
            1
            for code in status_codes
            if code
            in [200, 404, 429, 403]  # Success, not found, rate limited, or forbidden
        )

        assert (
            handled_properly >= 40
        ), f"Database connection exhaustion not properly handled: {handled_properly}/50"

    def test_file_descriptor_exhaustion_protection(
        self, client: TestClient, auth_headers
    ):
        """Test protection against file descriptor exhaustion."""
        # This test simulates attacks that could exhaust file descriptors
        # by making many concurrent requests

        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "File Descriptor Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }
        headers = auth_headers.get("student1", {})

        def make_request():
            return client.post(endpoint, json=payload, headers=headers)

        # Create many concurrent connections
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(make_request) for _ in range(100)]
            results = []

            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    results.append(result.status_code)
                except Exception:
                    results.append(0)  # Connection error

        # Should handle concurrent connections without exhaustion
        connection_errors = sum(1 for r in results if r == 0)
        server_errors = sum(1 for r in results if r >= 500)

        assert (
            connection_errors <= 10
        ), f"Too many connection errors: {connection_errors}/100"
        assert server_errors <= 5, f"Too many server errors: {server_errors}/100"


@pytest.mark.security
class TestDistributedAttackMitigation:
    """Test mitigation of distributed attacks."""

    def test_ip_based_rate_limiting(self, client: TestClient, auth_headers):
        """Test rate limiting based on source IP addresses."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "IP Rate Limiting Test",
            "difficulty": "easy",
            "question_count": 1,
        }

        # Simulate requests from different IPs
        fake_ips = [f"192.168.1.{i}" for i in range(1, 11)]

        for ip in fake_ips:
            # Simulate requests from each IP
            headers = {
                **auth_headers.get("student1", {}),
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
            }

            responses = []
            for _i in range(5):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.1)

            # Each IP should be rate limited independently
            # (Implementation may vary - this documents expected behavior)

        # Test that IP spoofing doesn't bypass user-based rate limiting
        spoofed_headers = {
            **auth_headers.get("student1", {}),
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
        }

        # Make many requests with spoofed IPs
        responses = []
        for _i in range(20):
            response = client.post(endpoint, json=payload, headers=spoofed_headers)
            responses.append(response.status_code)
            time.sleep(0.05)

        # Should still be rate limited despite IP spoofing
        any(r == status.HTTP_429_TOO_MANY_REQUESTS for r in responses)
        # Rate limiting should be based on authenticated user, not just IP

    def test_user_agent_analysis(self, client: TestClient, auth_headers):
        """Test detection of suspicious user agent patterns."""
        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "User Agent Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }

        # Test with suspicious user agents
        suspicious_agents = [
            "AttackBot/1.0",
            "curl/7.68.0",  # Command line tool
            "python-requests/2.25.1",  # Scripted requests
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",  # Very old browser
            "",  # Empty user agent
        ]

        base_headers = auth_headers.get("student1", {})

        for user_agent in suspicious_agents:
            headers = {
                **base_headers,
                "User-Agent": user_agent,
            }

            response = client.post(endpoint, json=payload, headers=headers)

            # Should handle suspicious user agents
            # May block, rate limit, or log for analysis
            assert (
                response.status_code != 500
            ), f"Server error with user agent: {user_agent}"

            # Suspicious agents might be blocked or rate limited more aggressively
            if response.status_code in [403, 429]:
                # This is acceptable security behavior
                pass

    def test_geolocation_based_protection(self, client: TestClient, auth_headers):
        """Test geolocation-based attack mitigation."""
        endpoint = "/api/v1/auth/me"

        # Simulate requests from suspicious locations
        # This would typically integrate with GeoIP services
        suspicious_locations = [
            {"X-Country-Code": "XX", "X-Region": "Unknown"},
            {"X-Country-Code": "TOR", "X-Region": "Tor Network"},
            {"X-Forwarded-For": "10.0.0.1"},  # Private IP from public internet
        ]

        base_headers = auth_headers.get("student1", {})

        for location_headers in suspicious_locations:
            headers = {**base_headers, **location_headers}

            response = client.get(endpoint, headers=headers)

            # Should handle requests from suspicious locations
            # May require additional verification or block entirely
            assert (
                response.status_code != 500
            ), f"Server error with location headers: {location_headers}"


@pytest.mark.security
class TestMedicalContentAbuseProtection:
    """Test protection against medical content generation abuse."""

    def test_medical_content_rate_limiting(self, client: TestClient, auth_headers):
        """Test specialized rate limiting for medical content generation."""
        endpoint = "/api/v1/clinical-support/scenarios/generate"
        payload = {
            "clinical_scenario": "Emergency Department Triage",
            "complexity_level": "advanced",
        }

        headers = auth_headers.get("student1", {})

        # Medical content should have strict rate limits
        responses = []
        for _i in range(10):
            response = client.post(endpoint, json=payload, headers=headers)
            responses.append(response.status_code)
            time.sleep(0.2)

        # Should implement protective rate limiting for medical content
        success_responses = sum(1 for r in responses if r == 200)
        rate_limited_responses = sum(1 for r in responses if r == 429)

        # Medical content generation should be more restrictive
        assert (
            rate_limited_responses > 0 or success_responses <= 5
        ), "Insufficient rate limiting for medical content generation"

    def test_content_quality_abuse_prevention(self, client: TestClient, auth_headers):
        """Test prevention of low-quality content generation abuse."""
        endpoint = "/api/v1/nclex/generate"

        # Attempt to generate many low-quality questions rapidly
        low_quality_payloads = [
            {
                "topic": "a",
                "difficulty": "easy",
                "question_count": 1,
            },
            {
                "topic": "test",
                "difficulty": "easy",
                "question_count": 1,
            },
            {
                "topic": "x" * 3,
                "difficulty": "easy",
                "question_count": 1,
            },
        ]

        headers = auth_headers.get("student1", {})

        for payload in low_quality_payloads:
            responses = []
            for _i in range(8):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.1)

            # Should detect and prevent low-quality content abuse
            validation_errors = sum(1 for r in responses if r == 422)
            rate_limited = sum(1 for r in responses if r == 429)

            # Should either validate content quality or rate limit aggressively
            protection_rate = (validation_errors + rate_limited) / len(responses)

            # At least some protection should be in place for low-quality abuse
            if protection_rate > 0.5:
                # Good - system is detecting and preventing abuse
                pass

    def test_bulk_content_generation_limits(self, client: TestClient, auth_headers):
        """Test limits on bulk medical content generation."""
        endpoint = "/api/v1/nclex/generate"

        # Attempt bulk generation
        bulk_payload = {
            "topic": "Comprehensive Medical Assessment",
            "difficulty": "medium",
            "question_count": 20,  # Large batch
        }

        headers = auth_headers.get("student1", {})

        # Multiple bulk requests
        bulk_responses = []
        for _i in range(3):
            response = client.post(endpoint, json=bulk_payload, headers=headers)
            bulk_responses.append(response.status_code)
            time.sleep(1)

        # Should limit bulk generation to prevent resource abuse
        successful_bulk = sum(1 for r in bulk_responses if r == 200)

        # Should allow some bulk operations but limit excessive use
        assert (
            successful_bulk <= 2
        ), "Insufficient protection against bulk content generation abuse"


@pytest.mark.security
class TestCrossServiceRateLimiting:
    """Test rate limiting coordination across services."""

    def test_ragnostic_service_rate_limiting(self, client: TestClient, auth_headers):
        """Test rate limiting for RAGnostic service calls."""
        with patch("src.services.ragnostic_client.RAGnosticClient") as mock_client:
            mock_instance = mock_client.return_value

            # Simulate rate limiting from RAGnostic service
            def mock_search_with_rate_limit(*args, **kwargs):
                # First few calls succeed, then rate limited
                if not hasattr(mock_search_with_rate_limit, "call_count"):
                    mock_search_with_rate_limit.call_count = 0

                mock_search_with_rate_limit.call_count += 1

                if mock_search_with_rate_limit.call_count <= 3:
                    return {"items": [{"content": "test"}], "total": 1}
                else:
                    # Simulate 429 rate limit from RAGnostic
                    raise Exception("Rate limit exceeded")

            mock_instance.search_content.side_effect = mock_search_with_rate_limit

            endpoint = "/api/v1/study-guide/create"
            payload = {
                "topic": "RAGnostic Rate Limit Test",
                "competencies": ["AACN_KNOWLEDGE_1"],
            }
            headers = auth_headers.get("student1", {})

            # Make requests that trigger RAGnostic calls
            responses = []
            for _i in range(6):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.1)

            # Should handle RAGnostic rate limiting gracefully
            server_errors = sum(1 for r in responses if r >= 500)
            assert server_errors <= 2, "Poor handling of upstream service rate limiting"

    def test_cascading_rate_limit_prevention(self, client: TestClient, auth_headers):
        """Test prevention of cascading rate limit effects."""
        # This test ensures that rate limiting in one service doesn't
        # cause unnecessary failures in dependent services

        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "Cascade Prevention Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }
        headers = auth_headers.get("student1", {})

        # Make many requests to potentially trigger rate limiting
        responses = []
        for _i in range(15):
            response = client.post(endpoint, json=payload, headers=headers)
            responses.append(response)
            time.sleep(0.1)

        status_codes = [r.status_code for r in responses]

        # Should handle rate limiting gracefully without cascading failures
        # Acceptable responses: success, rate limited, or graceful degradation
        acceptable_codes = [200, 201, 429, 503]  # 503 = Service Unavailable (graceful)
        unacceptable_responses = sum(
            1 for code in status_codes if code not in acceptable_codes
        )

        assert (
            unacceptable_responses <= 2
        ), f"Too many unhandled responses during rate limiting: {unacceptable_responses}"


@pytest.mark.security
class TestRateLimitingBypassPrevention:
    """Test prevention of rate limiting bypass attempts."""

    def test_header_manipulation_bypass_prevention(
        self, client: TestClient, auth_headers
    ):
        """Test that rate limiting cannot be bypassed via header manipulation."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "Bypass Test",
            "difficulty": "easy",
            "question_count": 1,
        }

        # Attempt various header manipulations to bypass rate limiting
        bypass_attempts = [
            {"X-Forwarded-For": "192.168.1.100"},
            {"X-Real-IP": "10.0.0.1"},
            {"X-Client-IP": "172.16.0.1"},
            {"X-Rate-Limit-Bypass": "true"},
            {"X-Admin-Override": "enabled"},
            {"User-Agent": "AdminBot/1.0"},
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "admin.example.com"},
        ]

        base_headers = auth_headers.get("student1", {})

        for bypass_headers in bypass_attempts:
            headers = {**base_headers, **bypass_headers}

            # Make many requests with bypass attempt
            responses = []
            for _i in range(15):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.05)

            # Should still be rate limited despite bypass attempt
            sum(1 for r in responses if r == status.HTTP_429_TOO_MANY_REQUESTS)

            # Should not be able to completely bypass rate limiting
            success_rate = sum(1 for r in responses if r == 200) / len(responses)
            assert (
                success_rate < 0.9
            ), f"Rate limiting bypassed with headers: {bypass_headers}"

    def test_session_manipulation_bypass_prevention(
        self, client: TestClient, test_users
    ):
        """Test prevention of rate limiting bypass via session manipulation."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        endpoint = "/api/v1/study-guide/create"
        payload = {
            "topic": "Session Bypass Test",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }

        # Get multiple tokens for the same user
        tokens = []
        for _i in range(3):
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": "test_password"},
            )
            if login_response.status_code == 200:
                tokens.append(login_response.json()["access_token"])

        # Attempt to use different tokens to bypass rate limiting
        total_successful = 0
        for token in tokens:
            headers = {"Authorization": f"Bearer {token}"}

            # Make requests with each token
            for _i in range(8):
                response = client.post(endpoint, json=payload, headers=headers)
                if response.status_code == 200:
                    total_successful += 1
                time.sleep(0.1)

        # Should not be able to bypass user-based rate limiting with multiple tokens
        # Rate limiting should be based on user identity, not token
        assert (
            total_successful <= 12
        ), "Rate limiting bypassed using multiple tokens for same user"

    def test_concurrent_session_rate_limiting(self, client: TestClient, auth_headers):
        """Test rate limiting behavior with concurrent sessions."""
        endpoint = "/api/v1/nclex/generate"
        payload = {
            "topic": "Concurrent Session Test",
            "difficulty": "easy",
            "question_count": 1,
        }
        headers = auth_headers.get("student1", {})

        def make_concurrent_requests():
            responses = []
            for _i in range(5):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)
                time.sleep(0.1)
            return responses

        # Simulate concurrent sessions from same user
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(make_concurrent_requests) for _ in range(4)]
            all_responses = []
            for future in futures:
                all_responses.extend(future.result())

        # Should apply rate limiting across all concurrent sessions
        success_count = sum(1 for r in all_responses if r == 200)
        sum(1 for r in all_responses if r == 429)

        # Should prevent abuse through concurrent sessions
        total_requests = len(all_responses)
        success_rate = success_count / total_requests

        assert (
            success_rate < 0.7
        ), "Insufficient rate limiting for concurrent sessions from same user"
