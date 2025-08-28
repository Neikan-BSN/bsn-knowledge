"""
Error Handling Tests for BSN Knowledge API

Tests comprehensive error handling, custom error responses,
input validation, and error logging.
"""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.api.error_handlers import (
    APIError,
    AssessmentError,
    AuthenticationError,
    AuthorizationError,
    BusinessLogicError,
    ContentGenerationError,
    ExternalServiceError,
    RateLimitExceededError,
    ResourceNotFoundError,
    create_error_response,
)
from src.api.error_handlers import (
    ValidationError as APIValidationError,
)


@pytest.mark.endpoints
class TestCustomErrorClasses:
    """Test custom error classes and their properties."""

    def test_api_error_base_class(self):
        """Test APIError base class functionality."""
        error = APIError(
            message="Test error message",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="TEST_ERROR",
            details={"key": "value"},
        )

        assert error.message == "Test error message"
        assert error.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert error.error_code == "TEST_ERROR"
        assert error.details == {"key": "value"}
        assert str(error) == "Test error message"

    def test_validation_error(self):
        """Test ValidationError class."""
        error = APIValidationError(
            message="Invalid input data",
            details={"field": "username", "issue": "too short"},
        )

        assert error.status_code == status.HTTP_400_BAD_REQUEST
        assert error.error_code == "VALIDATION_ERROR"
        assert error.message == "Invalid input data"
        assert error.details["field"] == "username"

    def test_authentication_error(self):
        """Test AuthenticationError class."""
        error = AuthenticationError("Invalid token provided")

        assert error.status_code == status.HTTP_401_UNAUTHORIZED
        assert error.error_code == "AUTHENTICATION_ERROR"
        assert error.message == "Invalid token provided"

    def test_authorization_error(self):
        """Test AuthorizationError class."""
        error = AuthorizationError("Admin access required")

        assert error.status_code == status.HTTP_403_FORBIDDEN
        assert error.error_code == "AUTHORIZATION_ERROR"
        assert error.message == "Admin access required"

    def test_resource_not_found_error(self):
        """Test ResourceNotFoundError class."""
        error = ResourceNotFoundError("Student", "student_123")

        assert error.status_code == status.HTTP_404_NOT_FOUND
        assert error.error_code == "RESOURCE_NOT_FOUND"
        assert "Student" in error.message
        assert "student_123" in error.message
        assert error.details["resource_type"] == "Student"
        assert error.details["resource_id"] == "student_123"

    def test_business_logic_error(self):
        """Test BusinessLogicError class."""
        error = BusinessLogicError(
            "Cannot assess competency without prerequisite completion",
            details={"prerequisite": "AACN_FOUNDATION_1"},
        )

        assert error.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert error.error_code == "BUSINESS_LOGIC_ERROR"
        assert "prerequisite" in error.message

    def test_external_service_error(self):
        """Test ExternalServiceError class."""
        error = ExternalServiceError("RAGnostic", "Connection timeout")

        assert error.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert error.error_code == "EXTERNAL_SERVICE_ERROR"
        assert "RAGnostic" in error.message
        assert error.details["service"] == "RAGnostic"

    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError class."""
        error = RateLimitExceededError(3600, "content_generation")

        assert error.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert error.error_code == "RATE_LIMIT_EXCEEDED"
        assert "content_generation" in error.message
        assert error.details["retry_after_seconds"] == 3600
        assert error.details["endpoint_type"] == "content_generation"

    def test_content_generation_error(self):
        """Test ContentGenerationError class."""
        error = ContentGenerationError("NCLEX questions", "Invalid topic specified")

        assert error.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert error.error_code == "CONTENT_GENERATION_ERROR"
        assert "NCLEX questions" in error.message
        assert error.details["content_type"] == "NCLEX questions"
        assert error.details["reason"] == "Invalid topic specified"

    def test_assessment_error(self):
        """Test AssessmentError class."""
        error = AssessmentError("Competency evaluation", "Missing performance data")

        assert error.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert error.error_code == "ASSESSMENT_ERROR"
        assert "Competency evaluation" in error.message
        assert error.details["assessment_type"] == "Competency evaluation"


@pytest.mark.endpoints
class TestErrorResponseGeneration:
    """Test error response generation and formatting."""

    def test_create_error_response_structure(self):
        """Test that error responses have correct structure."""
        from unittest.mock import MagicMock

        from fastapi import Request

        # Mock request object
        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/api/v1/test"

        error = APIError(
            message="Test error",
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="TEST_ERROR",
            details={"field": "value"},
        )

        response = create_error_response(error, mock_request)
        data = json.loads(response.body)

        # Check response structure
        assert data["error"] is True
        assert data["error_code"] == "TEST_ERROR"
        assert data["message"] == "Test error"
        assert "timestamp" in data
        assert "request_id" in data
        assert data["path"] == "/api/v1/test"
        assert data["details"]["field"] == "value"

        # Check response headers
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "X-Request-ID" in response.headers

    def test_error_response_timestamp_format(self):
        """Test that error response timestamps are ISO formatted."""
        from unittest.mock import MagicMock

        from fastapi import Request

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test"

        error = APIError("Test error")
        response = create_error_response(error, mock_request)
        data = json.loads(response.body)

        # Parse timestamp to ensure it's valid ISO format
        timestamp_str = data["timestamp"]
        parsed_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        assert isinstance(parsed_time, datetime)

    def test_error_response_without_details(self):
        """Test error response when no details are provided."""
        from unittest.mock import MagicMock

        from fastapi import Request

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test"

        error = APIError("Simple error")  # No details provided
        response = create_error_response(error, mock_request)
        data = json.loads(response.body)

        # Details should not be included if empty
        assert "details" not in data or data.get("details") is None


@pytest.mark.endpoints
class TestPydanticValidationHandling:
    """Test handling of Pydantic validation errors."""

    def test_pydantic_validation_error_conversion(self, client: TestClient):
        """Test that Pydantic validation errors are properly converted."""
        # Send invalid data that will trigger Pydantic validation
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": "",  # Empty username should fail validation
                "password": "test",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()

        assert data["error"] is True
        assert data["error_code"] == "VALIDATION_ERROR"
        assert "validation failed" in data["message"].lower()

        if "details" in data and "validation_errors" in data["details"]:
            validation_errors = data["details"]["validation_errors"]
            assert isinstance(validation_errors, list)
            assert len(validation_errors) > 0

            # Check validation error structure
            error_item = validation_errors[0]
            assert "field" in error_item
            assert "message" in error_item
            assert "type" in error_item

    def test_invalid_email_validation(self, client: TestClient):
        """Test email validation in requests."""
        # This test assumes there's an endpoint that validates email
        # If not available, this test can be skipped or adapted
        invalid_emails = [
            "not-an-email",
            "@missing-local.com",
            "missing-domain@",
            "spaces in@email.com",
            "double@@domain.com",
        ]

        for invalid_email in invalid_emails:
            # Test any endpoint that accepts email validation
            # This is a conceptual test - adapt to actual endpoints
            response = client.post(
                "/api/v1/auth/login",
                json={"username": invalid_email, "password": "test"},
            )

            # Should either validate properly or reject gracefully
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,  # Valid format, invalid credentials
                status.HTTP_422_UNPROCESSABLE_ENTITY,  # Invalid format
            ]

    def test_missing_required_fields(self, client: TestClient):
        """Test handling of missing required fields."""
        endpoints_and_required_fields = [
            ("/api/v1/auth/login", ["username", "password"]),
            # Add more endpoints as needed
        ]

        for endpoint, required_fields in endpoints_and_required_fields:
            # Test with completely empty request
            response = client.post(endpoint, json={})
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test with missing each required field
            for field_to_omit in required_fields:
                incomplete_data = {
                    field: "test_value"
                    for field in required_fields
                    if field != field_to_omit
                }
                response = client.post(endpoint, json=incomplete_data)
                assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.endpoints
class TestInputValidationSecurity:
    """Test input validation and security error handling."""

    def test_sql_injection_input_handling(self, client: TestClient, auth_headers):
        """Test that SQL injection attempts are handled properly."""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "1; DELETE FROM sessions WHERE 1=1; --",
            "' UNION SELECT password FROM users WHERE username='admin' --",
        ]

        for payload in sql_injection_payloads:
            # Test in path parameters
            response = client.get(
                f"/api/v1/analytics/student/{payload}",
                headers=auth_headers.get("instructor1", {}),
            )

            # Should return proper error codes, not server errors
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            ]
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

            # Test in JSON payloads
            response = client.post(
                "/api/v1/assessment/competency",
                json={
                    "student_id": payload,
                    "competency_id": "test",
                    "performance_data": {},
                },
                headers=auth_headers.get("instructor1", {}),
            )

            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            ]

    def test_xss_input_handling(self, client: TestClient, auth_headers):
        """Test that XSS attempts are handled properly."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
        ]

        for payload in xss_payloads:
            # Test XSS in study guide creation
            response = client.post(
                "/api/v1/study-guide/create",
                json={"topic": payload, "competencies": ["AACN_KNOWLEDGE_1"]},
                headers=auth_headers.get("student1", {}),
            )

            if response.status_code == status.HTTP_200_OK:
                # If successful, response should not contain unescaped script
                response_text = response.text
                assert "<script>" not in response_text
                assert "onerror=" not in response_text
                assert "javascript:" not in response_text

    def test_path_traversal_prevention(self, client: TestClient, auth_headers):
        """Test prevention of path traversal attacks."""
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "....//....//....//etc/passwd",
        ]

        for payload in path_traversal_payloads:
            # Test in path parameters
            response = client.get(
                f"/api/v1/analytics/student/{payload}",
                headers=auth_headers.get("instructor1", {}),
            )

            # Should not allow path traversal
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
            ]

    def test_large_payload_handling(self, client: TestClient, auth_headers):
        """Test handling of unusually large payloads."""
        # Create a large payload
        large_string = "A" * 100000  # 100KB string
        large_payload = {
            "topic": large_string,
            "competencies": ["AACN_KNOWLEDGE_1"],
            "description": large_string,
        }

        response = client.post(
            "/api/v1/study-guide/create",
            json=large_payload,
            headers=auth_headers.get("student1", {}),
        )

        # Should either process gracefully or reject with appropriate status
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_400_BAD_REQUEST,
        ]
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_malformed_json_handling(self, client: TestClient, auth_headers):
        """Test handling of malformed JSON."""
        malformed_json_payloads = [
            '{"incomplete": json',
            '{"duplicate": "keys", "duplicate": "values"}',
            '{"trailing": "comma",}',
            '{invalid: "json"}',
            '{"unicode": "\\u00ZZ"}',  # Invalid unicode
        ]

        for payload in malformed_json_payloads:
            response = client.post(
                "/api/v1/nclex/generate",
                data=payload,
                headers={
                    **auth_headers.get("student1", {}),
                    "Content-Type": "application/json",
                },
            )

            # Should handle malformed JSON gracefully
            assert response.status_code in [
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST,
            ]
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.endpoints
class TestDatabaseErrorHandling:
    """Test handling of database-related errors."""

    @patch("src.services.analytics_service.AnalyticsService")
    def test_database_connection_error_handling(
        self, mock_analytics, client: TestClient, auth_headers
    ):
        """Test handling when database is unavailable."""
        # Mock database connection failure
        mock_service = MagicMock()
        mock_service.get_student_analytics.side_effect = Exception(
            "Database connection failed"
        )
        mock_analytics.return_value = mock_service

        response = client.get(
            "/api/v1/analytics/student/student_001", headers=auth_headers["instructor1"]
        )

        # Should return proper error response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        data = response.json()

        assert data["error"] is True
        assert "error_code" in data

    @patch("src.services.content_generation_service.ContentGenerationService")
    def test_service_timeout_handling(
        self, mock_service, client: TestClient, auth_headers
    ):
        """Test handling of service timeouts."""
        # Mock service timeout
        mock_gen_service = MagicMock()
        mock_gen_service.generate_questions.side_effect = TimeoutError(
            "Service timeout"
        )
        mock_service.return_value = mock_gen_service

        response = client.post(
            "/api/v1/nclex/generate",
            json={"topic": "test", "difficulty": "easy", "question_count": 5},
            headers=auth_headers["student1"],
        )

        # Should handle timeout gracefully
        assert response.status_code in [
            status.HTTP_503_SERVICE_UNAVAILABLE,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

        if response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR:
            data = response.json()
            assert data["error"] is True


@pytest.mark.endpoints
class TestExternalServiceErrorHandling:
    """Test handling of external service errors."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_ragnostic_service_error_handling(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test handling when RAGnostic service fails."""
        # Mock RAGnostic service failure
        mock_client = MagicMock()
        mock_client.generate_questions.side_effect = Exception(
            "RAGnostic service unavailable"
        )
        mock_ragnostic.return_value = mock_client

        response = client.post(
            "/api/v1/nclex/generate",
            json={"topic": "cardiology", "difficulty": "medium", "question_count": 5},
            headers=auth_headers["student1"],
        )

        # Should handle external service failure gracefully
        assert response.status_code in [
            status.HTTP_503_SERVICE_UNAVAILABLE,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

        if response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            data = response.json()
            assert data["error"] is True
            assert data["error_code"] == "EXTERNAL_SERVICE_ERROR"

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_external_service_timeout(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test handling of external service timeouts."""

        # Mock timeout
        mock_client = MagicMock()
        mock_client.generate_questions.side_effect = TimeoutError("Request timeout")
        mock_ragnostic.return_value = mock_client

        response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Nursing Fundamentals",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            headers=auth_headers["student1"],
        )

        # Should handle timeout appropriately
        assert response.status_code in [
            status.HTTP_503_SERVICE_UNAVAILABLE,
            status.HTTP_504_GATEWAY_TIMEOUT,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]


@pytest.mark.endpoints
class TestErrorLogging:
    """Test that errors are properly logged."""

    @patch("src.api.error_handlers.logger")
    def test_server_errors_are_logged(self, mock_logger, client: TestClient):
        """Test that 5xx errors are logged as errors."""
        # This would require triggering a 500 error
        # For now, test the logging function directly
        from unittest.mock import MagicMock

        from fastapi import Request

        from src.api.error_handlers import log_error

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test"
        mock_request.method = "POST"

        error = APIError(
            message="Server error",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="INTERNAL_ERROR",
        )

        log_error(error, mock_request, "test_request_id")

        # Should log as error level for 5xx errors
        mock_logger.error.assert_called_once()

    @patch("src.api.error_handlers.logger")
    def test_client_errors_are_logged_as_warnings(self, mock_logger):
        """Test that 4xx errors are logged as warnings."""
        from unittest.mock import MagicMock

        from fastapi import Request

        from src.api.error_handlers import log_error

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test"
        mock_request.method = "GET"

        error = APIError(
            message="Client error",
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="BAD_REQUEST",
        )

        log_error(error, mock_request, "test_request_id")

        # Should log as warning level for 4xx errors
        mock_logger.warning.assert_called_once()


@pytest.mark.endpoints
class TestErrorRecovery:
    """Test error recovery and graceful degradation."""

    def test_partial_service_failure_handling(self, client: TestClient, auth_headers):
        """Test handling when some services fail but others work."""
        # This test would be more meaningful with actual service dependencies
        # For now, test that health endpoint works even if some features fail
        response = client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["status"] == "healthy"
        # Health check should report feature status
        assert "features_status" in data

    def test_cascading_failure_prevention(self, client: TestClient):
        """Test that single component failures don't cascade."""
        # Test that authentication still works even if other services fail
        response = client.post(
            "/api/v1/auth/login", json={"username": "nonexistent", "password": "wrong"}
        )

        # Should still handle auth properly, not crash
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_error_handling_doesnt_leak_sensitive_info(self, client: TestClient):
        """Test that error messages don't leak sensitive information."""
        # Test various error scenarios to ensure no sensitive data leaks
        sensitive_data_indicators = [
            "password",
            "secret",
            "key",
            "token",
            "database",
            "connection string",
            "internal",
            "stack trace",
            "traceback",
            "/home/",
            "/etc/",
            "admin",
            "root",
            "sa",
        ]

        # Test authentication error
        response = client.post(
            "/api/v1/auth/login", json={"username": "test", "password": "wrong"}
        )

        response_text = response.text.lower()
        for sensitive_term in sensitive_data_indicators:
            assert (
                sensitive_term not in response_text
            ), f"Sensitive term '{sensitive_term}' found in error response"

        # Test validation error
        response = client.post("/api/v1/auth/login", json={})
        response_text = response.text.lower()

        for sensitive_term in sensitive_data_indicators:
            assert (
                sensitive_term not in response_text
            ), f"Sensitive term '{sensitive_term}' found in validation error"


@pytest.mark.endpoints
class TestCustomValidationRules:
    """Test custom validation rules from validation.py."""

    def test_student_id_validation(self):
        """Test student ID validation rules."""
        from src.api.error_handlers import validate_student_id

        # Valid student IDs
        valid_ids = ["STU001", "student_123", "BSN2024_001"]
        for student_id in valid_ids:
            result = validate_student_id(student_id)
            assert result == student_id.strip()

        # Invalid student IDs
        with pytest.raises(APIValidationError):
            validate_student_id("")  # Empty

        with pytest.raises(APIValidationError):
            validate_student_id("AB")  # Too short

        with pytest.raises(APIValidationError):
            validate_student_id(None)  # None value

    def test_competency_id_validation(self):
        """Test competency ID validation rules."""
        from src.api.error_handlers import validate_competency_id

        # Valid competency IDs
        valid_ids = ["AACN_KNOWLEDGE_1", "COMP_001", "ASSESSMENT_A1"]
        for comp_id in valid_ids:
            result = validate_competency_id(comp_id)
            assert result == comp_id.strip()

        # Invalid competency IDs
        with pytest.raises(APIValidationError):
            validate_competency_id("")  # Empty

        with pytest.raises(APIValidationError):
            validate_competency_id("A")  # Too short

        with pytest.raises(APIValidationError):
            validate_competency_id(None)  # None value

    def test_pagination_validation(self):
        """Test pagination parameter validation."""
        from src.api.error_handlers import validate_pagination_params

        # Valid pagination
        skip, limit = validate_pagination_params(0, 50)
        assert skip == 0
        assert limit == 50

        skip, limit = validate_pagination_params(100, 25)
        assert skip == 100
        assert limit == 25

        # Invalid pagination
        with pytest.raises(APIValidationError):
            validate_pagination_params(-1, 50)  # Negative skip

        with pytest.raises(APIValidationError):
            validate_pagination_params(0, 0)  # Zero limit

        with pytest.raises(APIValidationError):
            validate_pagination_params(0, 1001)  # Limit too high

    def test_json_data_validation(self):
        """Test JSON data validation with required fields."""
        from src.api.error_handlers import validate_json_data

        # Valid data
        valid_data = {"username": "test", "password": "test123"}
        result = validate_json_data(valid_data, ["username", "password"])
        assert result == valid_data

        # Missing required fields
        with pytest.raises(APIValidationError) as exc_info:
            validate_json_data({"username": "test"}, ["username", "password"])

        assert "missing required fields" in str(exc_info.value).lower()
        assert "password" in str(exc_info.value)

        # Non-dict data
        with pytest.raises(APIValidationError):
            validate_json_data("not a dict", ["field"])

        with pytest.raises(APIValidationError):
            validate_json_data(None, ["field"])
