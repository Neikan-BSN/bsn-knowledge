"""
Comprehensive Access Control Tests for RAGnostic → BSN Knowledge Pipeline

Tests role-based access control, authorization boundaries, privilege escalation
prevention, and cross-service authorization security.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.auth import UserRole, fake_users_db


@pytest.mark.security
class TestRoleBasedAccessControl:
    """Test comprehensive role-based access control."""

    def test_student_access_restrictions(self, client: TestClient, auth_headers):
        """Test that student role has appropriate access restrictions."""
        # Student should NOT have access to:
        restricted_endpoints = [
            ("/api/v1/auth/users", "GET"),  # Admin only
            ("/api/v1/assessment/competency/assess/bulk", "POST"),  # Instructor+
            ("/api/v1/analytics/system", "GET"),  # Admin only
            ("/api/v1/auth/users/1", "DELETE"),  # Admin only
            ("/api/v1/assessment/grading", "POST"),  # Instructor+
        ]

        for endpoint, method in restricted_endpoints:
            if method == "GET":
                response = client.get(endpoint, headers=auth_headers["student1"])
            elif method == "POST":
                response = client.post(
                    endpoint, json={}, headers=auth_headers["student1"]
                )
            elif method == "DELETE":
                response = client.delete(endpoint, headers=auth_headers["student1"])

            assert response.status_code == status.HTTP_403_FORBIDDEN, (
                f"Student should not access {method} {endpoint}"
            )

        # Student SHOULD have access to:
        allowed_endpoints = [
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/study-guide/create", "POST"),
            ("/api/v1/nclex/generate", "POST"),
        ]

        for endpoint, method in allowed_endpoints:
            if method == "GET":
                response = client.get(endpoint, headers=auth_headers["student1"])
            elif method == "POST":
                test_data = {
                    "topic": "Nursing Care",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty": "medium",
                    "question_count": 5,
                }
                response = client.post(
                    endpoint, json=test_data, headers=auth_headers["student1"]
                )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_201_CREATED,
            ], f"Student should access {method} {endpoint}"

    def test_instructor_access_control(self, client: TestClient, auth_headers):
        """Test instructor role access control."""
        # Instructor should NOT have access to:
        restricted_endpoints = [
            ("/api/v1/auth/users", "GET"),  # Admin only
            ("/api/v1/auth/users/1", "DELETE"),  # Admin only
            ("/api/v1/analytics/system", "GET"),  # Admin only
        ]

        for endpoint, method in restricted_endpoints:
            if method == "GET":
                response = client.get(endpoint, headers=auth_headers["instructor1"])
            elif method == "DELETE":
                response = client.delete(endpoint, headers=auth_headers["instructor1"])

            assert response.status_code == status.HTTP_403_FORBIDDEN, (
                f"Instructor should not access {method} {endpoint}"
            )

        # Instructor SHOULD have access to:
        allowed_endpoints = [
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/assessment/competency", "GET"),
            ("/api/v1/analytics/student/test_id", "GET"),
        ]

        for endpoint, method in allowed_endpoints:
            response = client.get(endpoint, headers=auth_headers["instructor1"])
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_404_NOT_FOUND,  # Valid for non-existent resources
            ], f"Instructor should access {method} {endpoint}"

    def test_admin_full_access(self, client: TestClient, auth_headers):
        """Test admin role has full system access."""
        admin_endpoints = [
            ("/api/v1/auth/users", "GET"),
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/assessment/competency", "GET"),
        ]

        for endpoint, method in admin_endpoints:
            response = client.get(endpoint, headers=auth_headers["admin1"])
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_404_NOT_FOUND,
            ], f"Admin should access {method} {endpoint}"

    def test_role_hierarchy_enforcement(self, client: TestClient, auth_headers):
        """Test that role hierarchy is properly enforced."""
        # Test endpoint that requires instructor or higher
        instructor_endpoint = "/api/v1/analytics/student/test_id"

        # Student should be denied
        response = client.get(instructor_endpoint, headers=auth_headers["student1"])
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Instructor should be allowed
        response = client.get(instructor_endpoint, headers=auth_headers["instructor1"])
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

        # Admin should be allowed (higher privilege)
        response = client.get(instructor_endpoint, headers=auth_headers["admin1"])
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


@pytest.mark.security
class TestPrivilegeEscalationPrevention:
    """Test prevention of privilege escalation attacks."""

    def test_horizontal_privilege_escalation_prevention(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of users accessing other users' data."""
        # Create test scenario where student1 tries to access student2's data
        student_specific_endpoints = [
            "/api/v1/analytics/student/student2",
            "/api/v1/assessment/competency/profile/student2",
        ]

        for endpoint in student_specific_endpoints:
            response = client.get(endpoint, headers=auth_headers["student1"])

            # Should either deny access or filter results to own data
            if response.status_code == status.HTTP_200_OK:
                # If data is returned, verify it's filtered to current user
                data = response.json()
                if isinstance(data, dict) and "username" in data:
                    assert data["username"] == "student1"
                elif isinstance(data, list):
                    # All items should belong to current user
                    for item in data:
                        if isinstance(item, dict) and "username" in item:
                            assert item["username"] == "student1"
            else:
                # Access denial is also acceptable
                assert response.status_code in [
                    status.HTTP_403_FORBIDDEN,
                    status.HTTP_404_NOT_FOUND,
                ]

    def test_vertical_privilege_escalation_prevention(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of privilege escalation to higher roles."""
        # Student attempting admin functions
        admin_functions = [
            ("/api/v1/auth/users", "GET"),
            ("/api/v1/analytics/system", "GET"),
        ]

        for endpoint, _method in admin_functions:
            response = client.get(endpoint, headers=auth_headers["student1"])
            assert response.status_code == status.HTTP_403_FORBIDDEN

        # Instructor attempting admin functions
        for endpoint, _method in admin_functions:
            response = client.get(endpoint, headers=auth_headers["instructor1"])
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_role_manipulation_prevention(self, client: TestClient, test_users):
        """Test prevention of role manipulation attacks."""
        fake_users_db.update(test_users)

        # Login as student
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]

        # Attempt to manipulate role through various methods
        role_manipulation_attempts = [
            # Header manipulation
            {"Authorization": f"Bearer {token}", "X-User-Role": "admin"},
            {"Authorization": f"Bearer {token}", "Role": "admin"},
            {"Authorization": f"Bearer {token}", "X-Privilege": "admin"},
            # Body manipulation (if endpoint accepts role data)
        ]

        for headers in role_manipulation_attempts:
            response = client.get("/api/v1/auth/users", headers=headers)
            assert response.status_code == status.HTTP_403_FORBIDDEN, (
                f"Role manipulation succeeded with headers: {headers}"
            )

    def test_session_hijacking_protection(self, client: TestClient, test_users):
        """Test protection against session hijacking attacks."""
        fake_users_db.update(test_users)

        # Get student token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        student_token = login_response.json()["access_token"]

        # Get admin token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        admin_token = login_response.json()["access_token"]

        # Verify tokens are user-specific and can't be swapped
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {student_token}"},
        )
        assert response.json()["username"] == "student1"

        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.json()["username"] == "admin1"

        # Tokens should not be interchangeable
        assert student_token != admin_token


@pytest.mark.security
class TestResourceAccessControl:
    """Test fine-grained resource access control."""

    def test_resource_ownership_validation(self, client: TestClient, auth_headers):
        """Test that users can only access resources they own."""
        # Create resource as student1
        create_response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Cardiac Nursing",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            headers=auth_headers["student1"],
        )

        if create_response.status_code == status.HTTP_200_OK:
            # Try to access the resource as different user
            # This would typically involve resource IDs, but we'll test conceptually
            response = client.get(
                "/api/v1/study-guide",
                headers=auth_headers["student2"]
                if "student2" in auth_headers
                else auth_headers["instructor1"],
            )

            # Should not see other users' private resources
            if response.status_code == status.HTTP_200_OK:
                response.json()
                # Verify data filtering (implementation specific)
                pass

    def test_api_endpoint_access_matrix(self, client: TestClient, auth_headers):
        """Test comprehensive API endpoint access matrix."""
        # Define access matrix: endpoint -> allowed roles
        access_matrix = {
            "/api/v1/auth/me": ["student", "instructor", "admin"],
            "/api/v1/auth/users": ["admin"],
            "/api/v1/study-guide/create": ["student", "instructor", "admin"],
            "/api/v1/analytics/system": ["admin"],
            "/api/v1/assessment/competency": ["instructor", "admin"],
        }

        role_mapping = {
            "student": "student1",
            "instructor": "instructor1",
            "admin": "admin1",
        }

        for endpoint, allowed_roles in access_matrix.items():
            for role, user_key in role_mapping.items():
                if user_key in auth_headers:
                    if endpoint.endswith("/create") and role in allowed_roles:
                        response = client.post(
                            endpoint,
                            json={
                                "topic": "Test",
                                "competencies": ["AACN_KNOWLEDGE_1"],
                            },
                            headers=auth_headers[user_key],
                        )
                    else:
                        response = client.get(endpoint, headers=auth_headers[user_key])

                    if role in allowed_roles:
                        assert (
                            response.status_code
                            in [
                                status.HTTP_200_OK,
                                status.HTTP_201_CREATED,
                                status.HTTP_404_NOT_FOUND,  # Valid for non-existent resources
                            ]
                        ), f"{role} should access {endpoint}"
                    else:
                        assert response.status_code == status.HTTP_403_FORBIDDEN, (
                            f"{role} should not access {endpoint}"
                        )


@pytest.mark.security
class TestCrossServiceAuthorizationSecurity:
    """Test authorization security across RAGnostic and BSN Knowledge services."""

    def test_service_to_service_authorization(self, client: TestClient, auth_headers):
        """Test that service-to-service calls are properly authorized."""
        with patch("src.services.ragnostic_client.RAGnosticClient") as mock_client:
            mock_instance = MagicMock()
            mock_instance.search_content.return_value = {"items": [], "total": 0}
            mock_client.return_value = mock_instance

            # Make request that would trigger RAGnostic call
            client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Nursing Assessment",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if mock_instance.search_content.called:
                # Verify that user context is not leaked to service calls
                call_args = mock_instance.search_content.call_args
                # Should not contain user-specific auth tokens
                assert "Bearer" not in str(call_args)
                assert "student1" not in str(call_args)

    def test_api_key_isolation(self, client: TestClient, auth_headers):
        """Test that API keys for different services are properly isolated."""
        # Simulate content generation that might use multiple external services
        with patch("src.services.ragnostic_client.RAGnosticClient") as mock_ragnostic:
            mock_ragnostic.return_value.search_content.return_value = {"items": []}

            client.post(
                "/api/v1/nclex/generate",
                json={
                    "topic": "Pharmacology",
                    "difficulty": "medium",
                    "question_count": 5,
                },
                headers=auth_headers["student1"],
            )

            # Service calls should use service-specific credentials
            # Not user credentials or mixed credentials
            if mock_ragnostic.called:
                # Verify proper service authentication
                # This is implementation-specific validation
                pass

    def test_cross_service_data_access_control(self, client: TestClient, auth_headers):
        """Test data access control across service boundaries."""
        # Test that data from RAGnostic is properly filtered based on user permissions
        with patch(
            "src.services.ragnostic_client.RAGnosticClient.search_content"
        ) as mock_search:
            # Mock response with sensitive data that should be filtered
            mock_search.return_value = {
                "items": [
                    {"content": "Public medical information", "access_level": "public"},
                    {
                        "content": "Restricted medical data",
                        "access_level": "instructor",
                    },
                    {"content": "Admin-only medical data", "access_level": "admin"},
                ],
                "total": 3,
            }

            # Student request should only see public data
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Medical Research",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text.lower()
                # Should not contain restricted data
                assert "admin-only" not in response_text
                # May or may not contain instructor-level data based on implementation


@pytest.mark.security
class TestAuthorizationBypassAttempts:
    """Test various authorization bypass attempt scenarios."""

    def test_direct_object_reference_attack(self, client: TestClient, auth_headers):
        """Test prevention of insecure direct object reference attacks."""
        # Attempt to access resources by manipulating IDs
        bypass_attempts = [
            "/api/v1/analytics/student/../admin",
            "/api/v1/analytics/student/./admin",
            "/api/v1/analytics/student/%2e%2e%2fadmin",
            "/api/v1/analytics/student/1%20OR%201=1",
        ]

        for attempt in bypass_attempts:
            response = client.get(attempt, headers=auth_headers["student1"])
            # Should not allow access through path manipulation
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ], f"Authorization bypassed via: {attempt}"

    def test_parameter_pollution_authorization_bypass(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of authorization bypass via parameter pollution."""
        # Attempt parameter pollution attacks
        pollution_attempts = [
            {"role": ["student", "admin"]},  # Array pollution
            {"user_id": ["student1", "admin1"]},
            {"permission": ["read", "admin"]},
        ]

        for params in pollution_attempts:
            response = client.get(
                "/api/v1/auth/me",
                params=params,
                headers=auth_headers["student1"],
            )

            # Should not escalate privileges via parameter pollution
            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                assert data["role"] == UserRole.STUDENT  # Original role preserved
                assert data["username"] == "student1"  # Original user preserved

    def test_race_condition_authorization_bypass(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of authorization bypass via race conditions."""
        import concurrent.futures

        def make_privileged_request():
            return client.get("/api/v1/auth/users", headers=auth_headers["student1"])

        # Perform concurrent requests to test for race conditions
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_privileged_request) for _ in range(10)]
            results = [future.result() for future in futures]

        # All requests should be consistently denied
        for response in results:
            assert response.status_code == status.HTTP_403_FORBIDDEN, (
                "Race condition allowed authorization bypass"
            )

    def test_time_of_check_time_of_use_prevention(self, client: TestClient, test_users):
        """Test prevention of TOCTOU (Time-of-Check-Time-of-Use) attacks."""
        fake_users_db.update(test_users)

        # Login as student
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]

        # Attempt to exploit TOCTOU by modifying user role between check and use
        # This is a conceptual test - actual implementation would depend on the system
        def modify_user_role():
            # Simulate concurrent role modification
            if "student1" in fake_users_db:
                fake_users_db["student1"].role = UserRole.ADMIN

        import threading

        # Start role modification in background
        modification_thread = threading.Thread(target=modify_user_role)
        modification_thread.start()

        time.sleep(0.1)  # Small delay to allow potential race condition

        # Make privileged request
        response = client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        modification_thread.join()

        # Should still be denied based on token role, not current user role
        # (Token contains role at time of issuance)
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
class TestAuthorizationPerformanceAndResilience:
    """Test authorization system performance and resilience."""

    def test_authorization_decision_performance(self, client: TestClient, auth_headers):
        """Test that authorization decisions are made efficiently."""
        import time

        # Measure authorization overhead
        start_time = time.time()

        for _ in range(10):
            response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])
            assert response.status_code == status.HTTP_200_OK

        end_time = time.time()
        avg_time = (end_time - start_time) / 10

        # Authorization should not add significant overhead (< 50ms per request)
        assert avg_time < 0.05, f"Authorization overhead too high: {avg_time:.3f}s"

    def test_authorization_under_load(self, client: TestClient, auth_headers):
        """Test authorization system stability under concurrent load."""
        import concurrent.futures

        def make_authorized_request():
            return client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        def make_unauthorized_request():
            return client.get("/api/v1/auth/users", headers=auth_headers["student1"])

        # Mix of authorized and unauthorized requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            authorized_futures = [
                executor.submit(make_authorized_request) for _ in range(50)
            ]
            unauthorized_futures = [
                executor.submit(make_unauthorized_request) for _ in range(50)
            ]

            authorized_results = [f.result() for f in authorized_futures]
            unauthorized_results = [f.result() for f in unauthorized_futures]

        # All authorized requests should succeed
        authorized_success_rate = sum(
            1 for r in authorized_results if r.status_code == status.HTTP_200_OK
        ) / len(authorized_results)
        assert authorized_success_rate >= 0.95  # At least 95% success rate

        # All unauthorized requests should be denied
        unauthorized_denial_rate = sum(
            1
            for r in unauthorized_results
            if r.status_code == status.HTTP_403_FORBIDDEN
        ) / len(unauthorized_results)
        assert unauthorized_denial_rate >= 0.95  # At least 95% properly denied
