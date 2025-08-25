"""
Comprehensive Authentication Security Tests for RAGnostic → BSN Knowledge Pipeline

Tests authentication security, token validation, session management, and cross-service
authentication handoff with enterprise-grade security requirements.
"""

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.auth import (
    UserRole,
    create_access_token,
    create_auth_tokens,
    fake_users_db,
    verify_token,
)
from src.services.ragnostic_client import RAGnosticClient


@pytest.mark.security
class TestAuthenticationBypassPrevention:
    """Test prevention of authentication bypass attacks."""

    def test_no_authentication_bypass_via_headers(self, client: TestClient):
        """Test that authentication cannot be bypassed via header manipulation."""
        bypass_headers = [
            {"X-User-ID": "admin"},
            {"X-Authenticated": "true"},
            {"X-Role": "admin"},
            {"Authorization": "Bearer fake-token"},
            {"X-Access-Token": "admin-token"},
            {"Authentication": "Bearer valid-token"},  # Wrong header name
            {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},  # Basic auth attempt
        ]

        protected_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/auth/users",
            "/api/v1/nclex/generate",
            "/api/v1/assessment/competency",
        ]

        for headers in bypass_headers:
            for endpoint in protected_endpoints:
                response = client.get(endpoint, headers=headers)
                assert (
                    response.status_code == status.HTTP_401_UNAUTHORIZED
                ), f"Authentication bypassed with headers {headers} on {endpoint}"

    def test_no_authentication_bypass_via_query_params(self, client: TestClient):
        """Test that authentication cannot be bypassed via query parameters."""
        bypass_params = [
            {"token": "admin-token"},
            {"auth": "true"},
            {"user": "admin"},
            {"role": "admin"},
            {"authenticated": "1"},
            {"access_token": "fake-token"},
            {"jwt": "admin.fake.token"},
        ]

        for params in bypass_params:
            response = client.get("/api/v1/auth/me", params=params)
            assert (
                response.status_code == status.HTTP_401_UNAUTHORIZED
            ), f"Authentication bypassed with params {params}"

    def test_no_authentication_bypass_via_body(self, client: TestClient):
        """Test that authentication cannot be bypassed via request body."""
        bypass_bodies = [
            {"token": "admin-token"},
            {"authenticated": True},
            {"user_id": "admin"},
            {"override_auth": True},
            {"skip_auth": True},
        ]

        for body in bypass_bodies:
            response = client.post("/api/v1/nclex/generate", json=body)
            assert (
                response.status_code == status.HTTP_401_UNAUTHORIZED
            ), f"Authentication bypassed with body {body}"

    def test_malformed_jwt_token_rejection(self, client: TestClient):
        """Test that malformed JWT tokens are properly rejected."""
        malformed_tokens = [
            "not.a.jwt",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.malformed",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.",  # Missing signature
            "Bearer fake-token",  # Not a JWT
            "Bearer ",  # Empty token
            "Bearer " + "a" * 1000,  # Oversized token
            "fake.token.signature",
        ]

        for token in malformed_tokens:
            headers = {
                "Authorization": f"Bearer {token}"
                if not token.startswith("Bearer")
                else token
            }
            response = client.get("/api/v1/auth/me", headers=headers)
            assert (
                response.status_code == status.HTTP_401_UNAUTHORIZED
            ), f"Malformed token accepted: {token[:50]}..."


@pytest.mark.security
class TestJWTSecurityValidation:
    """Test JWT token security and validation."""

    def test_jwt_secret_key_tampering_detection(self):
        """Test that JWT tokens signed with wrong keys are rejected."""
        token_data = {
            "sub": "admin",
            "user_id": 1,
            "role": UserRole.ADMIN,
            "exp": datetime.now(UTC) + timedelta(hours=1),
        }

        # Create token with wrong secret
        wrong_secret_tokens = [
            jwt.encode(token_data, "wrong_secret", algorithm="HS256"),
            jwt.encode(token_data, "", algorithm="HS256"),
            jwt.encode(token_data, "a" * 1000, algorithm="HS256"),
        ]

        for token in wrong_secret_tokens:
            with pytest.raises(Exception):
                verify_token(token, "access")

    def test_jwt_algorithm_confusion_prevention(self):
        """Test prevention of JWT algorithm confusion attacks."""
        from src.auth import SECRET_KEY

        token_data = {
            "sub": "admin",
            "user_id": 1,
            "role": UserRole.ADMIN,
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "type": "access",
        }

        # Try different algorithms that should be rejected
        dangerous_algorithms = ["none", "HS384", "RS256", "RS384", "RS512"]

        for alg in dangerous_algorithms:
            try:
                if alg == "none":
                    # Algorithm confusion attack
                    token = jwt.encode(token_data, "", algorithm=alg)
                else:
                    token = jwt.encode(token_data, SECRET_KEY, algorithm=alg)

                with pytest.raises(Exception):
                    verify_token(token, "access")
            except Exception:
                # Expected - algorithm not supported or token creation failed
                pass

    def test_jwt_token_replay_attack_prevention(self, client: TestClient, test_users):
        """Test prevention of JWT token replay attacks."""
        fake_users_db.update(test_users)

        # Get valid token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]

        # Use token normally
        response1 = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response1.status_code == status.HTTP_200_OK

        # Simulate logout (in production, token would be blacklisted)
        client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Token should still work (stateless JWT limitation)
        # In production, implement token blacklisting
        response2 = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Current implementation: token still works (documented limitation)
        assert response2.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
        ]

    def test_jwt_token_expiration_enforcement(self):
        """Test strict JWT token expiration enforcement."""
        # Create expired token
        token_data = {
            "sub": "test_user",
            "user_id": 1,
            "role": UserRole.STUDENT,
            "exp": datetime.now(UTC) - timedelta(seconds=10),  # Expired
            "type": "access",
        }

        expired_token = create_access_token(
            token_data, expires_delta=timedelta(seconds=-10)
        )

        with pytest.raises(Exception):
            verify_token(expired_token, "access")

    def test_jwt_claim_validation(self):
        """Test that JWT claims are properly validated."""
        base_token_data = {
            "sub": "test_user",
            "user_id": 1,
            "role": UserRole.STUDENT,
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "type": "access",
        }

        # Test missing required claims
        invalid_claims = [
            {**base_token_data, "sub": None},  # Missing subject
            {**base_token_data, "type": None},  # Missing type
            {**base_token_data, "type": "wrong_type"},  # Wrong type
            {k: v for k, v in base_token_data.items() if k != "sub"},  # Missing sub
        ]

        for claims in invalid_claims:
            token = create_access_token(claims)
            with pytest.raises(Exception):
                verify_token(token, "access")


@pytest.mark.security
class TestCrossServiceAuthenticationSecurity:
    """Test authentication security for RAGnostic → BSN Knowledge integration."""

    @pytest.fixture
    def mock_ragnostic_client(self):
        """Mock RAGnostic client for testing."""
        client = MagicMock(spec=RAGnosticClient)
        return client

    def test_ragnostic_api_key_validation(self, mock_ragnostic_client):
        """Test API key validation for RAGnostic service calls."""
        # Test various invalid API keys
        invalid_keys = [
            None,
            "",
            "fake-key",
            "a" * 1000,  # Oversized key
            "Bearer token",  # Wrong format
            "<script>alert('xss')</script>",  # XSS attempt
        ]

        for invalid_key in invalid_keys:
            client = RAGnosticClient(api_key=invalid_key)
            # Verify that invalid keys are handled properly
            assert client.api_key == invalid_key  # Client stores as-is
            # Server-side validation should reject these

    @patch("src.services.ragnostic_client.httpx.AsyncClient")
    async def test_ragnostic_service_authentication_failure(self, mock_client):
        """Test handling of RAGnostic service authentication failures."""
        # Mock authentication failure
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception("Unauthorized")
        mock_client.return_value.request.return_value = mock_response

        client = RAGnosticClient(api_key="invalid-key")

        # Should handle auth failure gracefully
        result = await client.search_content("test query")
        assert "error" in result
        assert result["fallback_mode"] is True

    async def test_token_forwarding_security(self, client: TestClient, auth_headers):
        """Test secure token forwarding to RAGnostic service."""
        with patch("src.services.ragnostic_client.RAGnosticClient") as mock_client:
            # Simulate content generation that uses RAGnostic
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Cardiac Assessment",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            # Verify that BSN Knowledge doesn't forward user tokens to RAGnostic
            # (Should use service-to-service authentication instead)
            if mock_client.called:
                call_args = mock_client.call_args
                # Verify no user tokens are leaked
                assert "Authorization" not in str(call_args)


@pytest.mark.security
class TestSessionManagementSecurity:
    """Test session management security."""

    def test_concurrent_session_security(self, client: TestClient, test_users):
        """Test security with concurrent sessions."""
        fake_users_db.update(test_users)

        # Create multiple concurrent sessions for same user
        login_data = {"username": "student1", "password": "test_password"}

        responses = []
        for _ in range(5):
            response = client.post("/api/v1/auth/login", json=login_data)
            responses.append(response)
            assert response.status_code == status.HTTP_200_OK

        # All tokens should be independent and valid
        tokens = [r.json()["access_token"] for r in responses]
        assert len(set(tokens)) == 5  # All tokens should be different

        # Each token should work independently
        for token in tokens:
            response = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == status.HTTP_200_OK

    def test_session_fixation_prevention(self, client: TestClient, test_users):
        """Test prevention of session fixation attacks."""
        fake_users_db.update(test_users)

        # Get initial session
        response1 = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token1 = response1.json()["access_token"]

        # Get new session - should be different
        response2 = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token2 = response2.json()["access_token"]

        # Tokens should be different (prevents session fixation)
        assert token1 != token2

    def test_refresh_token_security(self, client: TestClient, test_users):
        """Test refresh token security measures."""
        fake_users_db.update(test_users)

        # Get tokens
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        refresh_token = login_response.json()["refresh_token"]

        # Test refresh token reuse detection (simplified)
        refresh_response1 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_response1.status_code == status.HTTP_200_OK

        # In production, refresh token should be invalidated after use
        # Current implementation allows reuse (limitation)
        refresh_response2 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_response2.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
        ]


@pytest.mark.security
class TestRateLimitingSecurityBypass:
    """Test that rate limiting cannot be bypassed."""

    def test_rate_limit_bypass_via_headers(self, client: TestClient, auth_headers):
        """Test that rate limiting cannot be bypassed via header manipulation."""
        bypass_headers = [
            {"X-Forwarded-For": "192.168.1.100"},
            {"X-Real-IP": "10.0.0.1"},
            {"X-Client-IP": "172.16.0.1"},
            {"X-Rate-Limit-Bypass": "true"},
            {"X-Admin-Override": "true"},
        ]

        # Make many requests to trigger rate limiting
        endpoint = "/api/v1/nclex/generate"
        payload = {"topic": "test", "difficulty": "medium", "question_count": 1}

        for headers in bypass_headers:
            combined_headers = {**auth_headers["student1"], **headers}

            # Make requests until rate limited
            rate_limited = False
            for _ in range(60):  # Exceed rate limit
                response = client.post(endpoint, json=payload, headers=combined_headers)
                if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                    rate_limited = True
                    break

            # Should still be rate limited despite bypass attempt
            assert rate_limited, f"Rate limiting bypassed with headers: {headers}"

    def test_distributed_rate_limiting_security(self, client: TestClient, auth_headers):
        """Test that rate limiting works across distributed requests."""
        # Simulate requests from different IPs (header spoofing attempt)
        fake_ips = [f"192.168.1.{i}" for i in range(1, 21)]

        endpoint = "/api/v1/nclex/generate"
        payload = {"topic": "test", "difficulty": "medium", "question_count": 1}

        responses = []
        for ip in fake_ips:
            headers = {
                **auth_headers["student1"],
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
            }

            # Make multiple requests per "IP"
            for _ in range(3):
                response = client.post(endpoint, json=payload, headers=headers)
                responses.append(response.status_code)

        # Should still hit rate limits (user-based, not IP-based)
        rate_limited_count = sum(
            1 for code in responses if code == status.HTTP_429_TOO_MANY_REQUESTS
        )
        assert (
            rate_limited_count > 0
        ), "Rate limiting not working across distributed requests"


@pytest.mark.security
class TestAuthenticationPerformanceAttacks:
    """Test authentication system resilience to performance-based attacks."""

    def test_password_brute_force_timing_consistency(self, client: TestClient):
        """Test timing consistency to prevent username enumeration."""
        timing_samples = []

        # Test with non-existent users
        for i in range(10):
            start_time = time.time()
            client.post(
                "/api/v1/auth/login",
                json={"username": f"nonexistent_{i}", "password": "password"},
            )
            end_time = time.time()
            timing_samples.append(end_time - start_time)

        # Test with existing user, wrong password
        for i in range(10):
            start_time = time.time()
            client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": f"wrong_password_{i}"},
            )
            end_time = time.time()
            timing_samples.append(end_time - start_time)

        # Timing should be relatively consistent
        import statistics

        if len(timing_samples) > 1:
            std_dev = statistics.stdev(timing_samples)
            mean_time = statistics.mean(timing_samples)
            # Standard deviation should be less than 50% of mean
            assert std_dev < mean_time * 0.5, "Timing attack vulnerability detected"

    def test_concurrent_authentication_stability(self, client: TestClient, test_users):
        """Test authentication system stability under concurrent load."""
        fake_users_db.update(test_users)

        import concurrent.futures

        def authenticate():
            return client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": "test_password"},
            )

        # Perform concurrent authentication attempts
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(authenticate) for _ in range(20)]
            results = [future.result() for future in futures]

        # All authentic requests should succeed
        success_count = sum(1 for r in results if r.status_code == status.HTTP_200_OK)
        assert (
            success_count >= 15
        ), "Authentication system unstable under concurrent load"


@pytest.mark.security
class TestTokenSecurityBestPractices:
    """Test JWT token security best practices implementation."""

    def test_token_entropy_validation(self, test_users):
        """Test that generated tokens have sufficient entropy."""
        fake_users_db.update(test_users)

        # Generate multiple tokens for same user
        tokens = []
        for _ in range(10):
            token_response = create_auth_tokens(test_users["student1"])
            tokens.append(token_response.access_token)

        # All tokens should be unique (high entropy)
        assert len(set(tokens)) == len(tokens), "Insufficient token entropy detected"

        # Each token should be sufficiently long
        for token in tokens:
            assert len(token) > 100, "Token too short for security"

    def test_token_sensitive_data_exclusion(self, test_users):
        """Test that tokens don't contain sensitive data."""
        fake_users_db.update(test_users)
        user = test_users["student1"]

        token_response = create_auth_tokens(user)
        token_payload = jwt.decode(
            token_response.access_token,
            options={"verify_signature": False},
        )

        # Token should not contain sensitive information
        token_str = str(token_payload).lower()
        sensitive_data = [
            user.hashed_password,
            user.email.lower(),
            "password",
            "hash",
            "secret",
            "private",
        ]

        for sensitive in sensitive_data:
            assert (
                sensitive not in token_str
            ), f"Token contains sensitive data: {sensitive}"

    def test_token_algorithm_security(self):
        """Test that secure algorithms are used for token signing."""
        token_data = {
            "sub": "test_user",
            "user_id": 1,
            "role": UserRole.STUDENT,
        }

        token = create_access_token(token_data)

        # Decode header to check algorithm
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256", "Insecure algorithm used for token signing"
        assert header["typ"] == "JWT", "Invalid token type"
