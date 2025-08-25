"""
Authentication and Authorization Tests for BSN Knowledge API

Tests JWT authentication, role-based access control, token validation,
and OAuth2 integration.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.auth import (
    UserRole,
    authenticate_user,
    create_access_token,
    create_auth_tokens,
    create_refresh_token,
    fake_users_db,
    verify_token,
)


@pytest.mark.auth
class TestJWTTokenGeneration:
    """Test JWT token creation and validation."""

    def test_create_access_token_success(self, assert_valid_jwt_token):
        """Test successful access token creation."""
        token_data = {
            "sub": "test_user",
            "user_id": 123,
            "role": UserRole.STUDENT,
            "scopes": [],
        }

        token = create_access_token(token_data)
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are typically long

        # Validate token structure
        payload = assert_valid_jwt_token(token)
        assert payload["sub"] == "test_user"
        assert payload["user_id"] == 123
        assert payload["role"] == UserRole.STUDENT
        assert payload["type"] == "access"

    def test_create_refresh_token_success(self, assert_valid_jwt_token):
        """Test successful refresh token creation."""
        token_data = {
            "sub": "test_user",
            "user_id": 123,
            "role": UserRole.INSTRUCTOR,
            "scopes": [],
        }

        token = create_refresh_token(token_data)
        assert isinstance(token, str)

        # Validate token structure
        payload = assert_valid_jwt_token(token)
        assert payload["sub"] == "test_user"
        assert payload["type"] == "refresh"

    def test_token_expiration_times(self, assert_valid_jwt_token):
        """Test that tokens have appropriate expiration times."""
        token_data = {"sub": "test_user", "user_id": 1, "role": UserRole.STUDENT}

        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)

        access_payload = assert_valid_jwt_token(access_token)
        refresh_payload = assert_valid_jwt_token(refresh_token)

        # Access token should expire sooner than refresh token
        assert access_payload["exp"] < refresh_payload["exp"]

        # Access token should expire in ~30 minutes
        access_exp = datetime.fromtimestamp(access_payload["exp"], tz=UTC)
        now = datetime.now(UTC)
        access_duration = access_exp - now
        assert 25 <= access_duration.total_seconds() / 60 <= 35  # 25-35 minutes range

    def test_custom_expiration_delta(self, assert_valid_jwt_token):
        """Test token creation with custom expiration."""
        token_data = {"sub": "test_user", "user_id": 1, "role": UserRole.ADMIN}
        custom_expires = timedelta(hours=2)

        token = create_access_token(token_data, expires_delta=custom_expires)
        payload = assert_valid_jwt_token(token)

        exp_time = datetime.fromtimestamp(payload["exp"], tz=UTC)
        now = datetime.now(UTC)
        duration = exp_time - now

        # Should be approximately 2 hours (allow some variance)
        assert 115 <= duration.total_seconds() / 60 <= 125  # 115-125 minutes


@pytest.mark.auth
class TestTokenVerification:
    """Test JWT token verification and validation."""

    def test_verify_valid_access_token(self):
        """Test verification of valid access token."""
        token_data = {
            "sub": "test_user",
            "user_id": 123,
            "role": UserRole.STUDENT,
            "scopes": [],
        }

        token = create_access_token(token_data)
        result = verify_token(token, "access")

        assert result.username == "test_user"
        assert result.user_id == 123
        assert result.role == UserRole.STUDENT
        assert result.scopes == []

    def test_verify_valid_refresh_token(self):
        """Test verification of valid refresh token."""
        token_data = {
            "sub": "refresh_user",
            "user_id": 456,
            "role": UserRole.INSTRUCTOR,
            "scopes": [],
        }

        token = create_refresh_token(token_data)
        result = verify_token(token, "refresh")

        assert result.username == "refresh_user"
        assert result.user_id == 456
        assert result.role == UserRole.INSTRUCTOR

    def test_verify_wrong_token_type(self):
        """Test verification fails for wrong token type."""
        token_data = {"sub": "test_user", "user_id": 1, "role": UserRole.STUDENT}
        access_token = create_access_token(token_data)

        # Try to verify access token as refresh token
        with pytest.raises(Exception):  # Should raise authentication error
            verify_token(access_token, "refresh")

    def test_verify_malformed_token(self):
        """Test verification fails for malformed token."""
        malformed_tokens = [
            "not.a.jwt",
            "definitely-not-a-token",
            "",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.malformed",
        ]

        for bad_token in malformed_tokens:
            with pytest.raises(Exception):
                verify_token(bad_token, "access")

    def test_verify_expired_token(self):
        """Test verification fails for expired token."""
        token_data = {"sub": "test_user", "user_id": 1, "role": UserRole.STUDENT}
        # Create token that expires immediately
        expired_token = create_access_token(
            token_data, expires_delta=timedelta(seconds=-10)
        )

        with pytest.raises(Exception):
            verify_token(expired_token, "access")


@pytest.mark.auth
class TestUserAuthentication:
    """Test user authentication logic."""

    def test_authenticate_valid_user(self, test_users):
        """Test authentication with valid credentials."""
        # Add test user to fake database
        fake_users_db.update(test_users)

        user = authenticate_user("student1", "test_password")
        assert user is not None
        assert user.username == "student1"
        assert user.role == UserRole.STUDENT
        assert user.is_active is True

    def test_authenticate_invalid_username(self, test_users):
        """Test authentication fails with invalid username."""
        fake_users_db.update(test_users)

        user = authenticate_user("nonexistent_user", "test_password")
        assert user is None

    def test_authenticate_invalid_password(self, test_users):
        """Test authentication fails with invalid password."""
        fake_users_db.update(test_users)

        user = authenticate_user("student1", "wrong_password")
        assert user is None

    def test_authenticate_inactive_user(self, test_users):
        """Test authentication of inactive user."""
        fake_users_db.update(test_users)

        user = authenticate_user("inactive_user", "test_password")
        assert user is not None  # authenticate_user doesn't check is_active
        assert user.is_active is False


@pytest.mark.auth
class TestLoginEndpoint:
    """Test authentication login endpoint."""

    def test_login_success(self, client: TestClient, test_users):
        """Test successful login."""
        fake_users_db.update(test_users)

        response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1800  # 30 minutes
        assert len(data["access_token"]) > 50
        assert len(data["refresh_token"]) > 50

    def test_login_invalid_credentials(self, client: TestClient, test_users):
        """Test login with invalid credentials."""
        fake_users_db.update(test_users)

        response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "wrong_password"},
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "access_token" not in response.json()

    def test_login_inactive_user(self, client: TestClient, test_users):
        """Test login with inactive user."""
        fake_users_db.update(test_users)

        response = client.post(
            "/api/v1/auth/login",
            json={"username": "inactive_user", "password": "test_password"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "disabled" in response.json()["detail"].lower()

    def test_login_missing_fields(self, client: TestClient):
        """Test login with missing fields."""
        # Missing password
        response = client.post("/api/v1/auth/login", json={"username": "student1"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Missing username
        response = client.post("/api/v1/auth/login", json={"password": "password"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Empty request
        response = client.post("/api/v1/auth/login", json={})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.auth
class TestOAuth2Login:
    """Test OAuth2 compatible login endpoint."""

    def test_oauth2_login_success(self, client: TestClient, test_users):
        """Test successful OAuth2 login."""
        fake_users_db.update(test_users)

        response = client.post(
            "/api/v1/auth/login/oauth2",
            data={"username": "instructor1", "password": "test_password"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_oauth2_login_with_scopes(self, client: TestClient, test_users):
        """Test OAuth2 login with scopes."""
        fake_users_db.update(test_users)

        response = client.post(
            "/api/v1/auth/login/oauth2",
            data={
                "username": "instructor1",
                "password": "test_password",
                "scope": "read write",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        # Scopes are not currently used but should not cause errors


@pytest.mark.auth
class TestTokenRefresh:
    """Test token refresh functionality."""

    def test_refresh_token_success(self, client: TestClient, test_users):
        """Test successful token refresh."""
        fake_users_db.update(test_users)

        # First get tokens by logging in
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token to get new tokens
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

        # New tokens should be different from original
        assert data["access_token"] != login_response.json()["access_token"]

    def test_refresh_invalid_token(self, client: TestClient):
        """Test refresh with invalid token."""
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": "invalid.token.here"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_access_token_as_refresh(self, client: TestClient, test_users):
        """Test refresh using access token (should fail)."""
        fake_users_db.update(test_users)

        # Get access token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        access_token = login_response.json()["access_token"]

        # Try to use access token as refresh token
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": access_token}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.auth
class TestAuthenticatedEndpoints:
    """Test authentication requirements for protected endpoints."""

    def test_get_current_user_success(self, client: TestClient, auth_headers):
        """Test getting current user info with valid token."""
        response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["username"] == "student1"
        assert data["role"] == UserRole.STUDENT
        assert data["is_active"] is True
        assert "hashed_password" not in data  # Password should not be returned

    def test_get_current_user_no_token(self, client: TestClient):
        """Test getting current user info without token."""
        response = client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_current_user_invalid_token(self, client: TestClient):
        """Test getting current user info with invalid token."""
        response = client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_success(self, client: TestClient, auth_headers):
        """Test successful logout."""
        response = client.post(
            "/api/v1/auth/logout", headers=auth_headers["instructor1"]
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "logged out successfully" in data["message"]
        assert data["username"] == "instructor1"

    def test_verify_token_endpoint(self, client: TestClient, auth_headers):
        """Test token verification endpoint."""
        response = client.get(
            "/api/v1/auth/verify-token", headers=auth_headers["admin1"]
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["valid"] is True
        assert data["user"]["username"] == "admin1"
        assert data["user"]["role"] == UserRole.ADMIN


@pytest.mark.auth
class TestRoleBasedAccess:
    """Test role-based access control."""

    def test_admin_can_list_users(self, client: TestClient, auth_headers):
        """Test that admin can access user list."""
        response = client.get("/api/v1/auth/users", headers=auth_headers["admin1"])

        assert response.status_code == status.HTTP_200_OK
        users = response.json()

        assert isinstance(users, list)
        assert len(users) > 0
        # Verify no passwords are returned
        for user in users:
            assert "hashed_password" not in user

    def test_non_admin_cannot_list_users(self, client: TestClient, auth_headers):
        """Test that non-admin users cannot access user list."""
        # Student trying to access admin endpoint
        response = client.get("/api/v1/auth/users", headers=auth_headers["student1"])

        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Instructor trying to access admin endpoint
        response = client.get("/api/v1/auth/users", headers=auth_headers["instructor1"])

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_list_users_pagination(self, client: TestClient, auth_headers):
        """Test user list pagination."""
        response = client.get(
            "/api/v1/auth/users?skip=0&limit=2", headers=auth_headers["admin1"]
        )

        assert response.status_code == status.HTTP_200_OK
        users = response.json()

        assert len(users) <= 2


@pytest.mark.auth
class TestAuthUtilityEndpoints:
    """Test authentication utility endpoints."""

    def test_get_available_roles(self, client: TestClient):
        """Test getting list of available roles."""
        response = client.get("/api/v1/auth/roles")

        assert response.status_code == status.HTTP_200_OK
        roles = response.json()

        expected_roles = [UserRole.STUDENT, UserRole.INSTRUCTOR, UserRole.ADMIN]
        assert set(roles) == set(expected_roles)

    def test_auth_health_check(self, client: TestClient):
        """Test authentication service health check."""
        response = client.get("/api/v1/auth/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["service"] == "authentication"
        assert data["status"] == "healthy"
        assert "features" in data
        assert len(data["features"]) > 0


@pytest.mark.auth
class TestAuthenticationSecurity:
    """Test security aspects of authentication."""

    def test_password_hashing_security(self):
        """Test that passwords are properly hashed."""
        from src.auth import get_password_hash, verify_password

        password = "test_password_123"
        hashed = get_password_hash(password)

        # Hash should not contain the original password
        assert password not in hashed
        assert len(hashed) > 50  # bcrypt hashes are long
        assert hashed.startswith("$2b$")  # bcrypt format

        # Verify password works
        assert verify_password(password, hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_token_contains_no_sensitive_data(self, assert_valid_jwt_token, test_users):
        """Test that JWT tokens don't contain sensitive information."""
        fake_users_db.update(test_users)
        user = test_users["student1"]

        token_response = create_auth_tokens(user)
        payload = assert_valid_jwt_token(token_response.access_token)

        # Token should not contain password or other sensitive data
        token_str = str(payload)
        assert "password" not in token_str.lower()
        assert "hashed_password" not in token_str.lower()
        assert user.hashed_password not in token_str

    def test_different_users_get_different_tokens(self, test_users):
        """Test that different users get different tokens."""
        fake_users_db.update(test_users)

        student_tokens = create_auth_tokens(test_users["student1"])
        instructor_tokens = create_auth_tokens(test_users["instructor1"])

        assert student_tokens.access_token != instructor_tokens.access_token
        assert student_tokens.refresh_token != instructor_tokens.refresh_token

    def test_sql_injection_prevention(self, client: TestClient):
        """Test that login endpoint prevents SQL injection attempts."""
        sql_injection_attempts = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin' OR 1=1 --",
            "'; SELECT * FROM users WHERE ''='",
        ]

        for injection_attempt in sql_injection_attempts:
            response = client.post(
                "/api/v1/auth/login",
                json={"username": injection_attempt, "password": "password"},
            )

            # Should return 401 (unauthorized) not 500 (server error)
            # This indicates proper input validation
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_timing_attack_resistance(self, client: TestClient, test_users):
        """Test basic timing attack resistance."""
        fake_users_db.update(test_users)

        import time

        # Test with valid username, invalid password
        start = time.time()
        response1 = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "wrong_password"},
        )
        time1 = time.time() - start

        # Test with invalid username
        start = time.time()
        response2 = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent", "password": "password"},
        )
        time2 = time.time() - start

        assert response1.status_code == status.HTTP_401_UNAUTHORIZED
        assert response2.status_code == status.HTTP_401_UNAUTHORIZED

        # Time difference should be minimal (basic check)
        # Note: This is a basic test; real timing attack prevention requires more sophisticated measures
        time_diff = abs(time1 - time2)
        assert time_diff < 1.0  # Should complete within similar timeframes
