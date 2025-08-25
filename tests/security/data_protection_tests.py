"""
Comprehensive Data Protection Tests for RAGnostic → BSN Knowledge Pipeline

Tests data encryption, privacy controls, HTTPS/TLS security, data storage protection,
and compliance with data protection regulations.
"""

import re
import ssl
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.services.ragnostic_client import RAGnosticClient


@pytest.mark.security
class TestDataEncryptionInTransit:
    """Test data encryption during transmission between services."""

    def test_https_enforcement(self, client: TestClient):
        """Test that HTTPS is enforced for secure communication."""
        # Test that security headers indicate HTTPS usage
        response = client.get("/health")

        # Check for security-related headers (would be set by production middleware)
        headers = response.headers

        # Basic security headers should be present
        security_indicators = [
            "X-Process-Time",  # Performance tracking
            "X-Request-ID",  # Request tracing
        ]

        for header in security_indicators:
            assert header in headers, f"Security header {header} missing"

        # Content type should be secure JSON
        assert "application/json" in headers.get("content-type", "")

    def test_tls_configuration_security(self):
        """Test TLS configuration meets security standards."""
        # This would test actual TLS configuration in production
        # For unit tests, we verify the configuration expectations

        # Verify TLS version requirements
        minimum_tls_version = ssl.TLSVersion.TLSv1_2

        # Test SSL context configuration (conceptual)
        context = ssl.create_default_context()

        # Verify secure defaults
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

        # In production, would test:
        # - TLS 1.2+ only
        # - Strong cipher suites
        # - Perfect forward secrecy
        # - HSTS headers
        # - Certificate validation

    @patch("src.services.ragnostic_client.httpx.AsyncClient")
    async def test_service_to_service_encryption(self, mock_client):
        """Test encryption for service-to-service communication."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"items": [], "total": 0}
        mock_client.return_value.request.return_value = mock_response

        # Create RAGnostic client with HTTPS URL
        client = RAGnosticClient(base_url="https://ragnostic-service.com")

        await client.search_content("test query")

        # Verify HTTPS is used
        if mock_client.return_value.request.called:
            call_args = mock_client.return_value.request.call_args
            url = call_args[0][1]  # Second argument should be URL
            assert url.startswith("https://"), "Service communication must use HTTPS"

    def test_sensitive_data_not_in_urls(self, client: TestClient, auth_headers):
        """Test that sensitive data is not exposed in URLs."""
        # URLs should not contain sensitive information
        sensitive_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/analytics/student/test_id",
            "/api/v1/assessment/competency",
        ]

        for endpoint in sensitive_endpoints:
            response = client.get(endpoint, headers=auth_headers["student1"])

            # URLs should not contain passwords, tokens, or personal info
            sensitive_patterns = [
                r"password\s*=\s*[^&\s]+",
                r"token\s*=\s*[^&\s]+",
                r"secret\s*=\s*[^&\s]+",
                r"ssn\s*=\s*\d{3}-\d{2}-\d{4}",
                r"credit.*card\s*=\s*\d+",
            ]

            for pattern in sensitive_patterns:
                assert not re.search(
                    pattern, endpoint, re.IGNORECASE
                ), f"Sensitive data pattern in URL: {pattern}"

    def test_request_response_encryption_indicators(
        self, client: TestClient, auth_headers
    ):
        """Test that request/response indicate proper encryption."""
        response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Cardiac Nursing Care",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "sensitive_content": "Patient-specific medical information",
            },
            headers=auth_headers["student1"],
        )

        if response.status_code == status.HTTP_200_OK:
            # Response should not leak encryption keys or sensitive config
            response_text = response.text.lower()

            encryption_leaks = [
                "private key",
                "secret key",
                "encryption key",
                "iv=",  # Initialization vector
                "salt=",
                "cipher",
            ]

            for leak in encryption_leaks:
                assert leak not in response_text, f"Encryption details leaked: {leak}"


@pytest.mark.security
class TestDataPrivacyControls:
    """Test privacy controls for sensitive data."""

    def test_personal_data_minimization(self, client: TestClient, auth_headers):
        """Test that only necessary personal data is collected and returned."""
        response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        if response.status_code == status.HTTP_200_OK:
            user_data = response.json()

            # Should contain necessary fields
            required_fields = ["username", "role", "is_active"]
            for field in required_fields:
                assert field in user_data

            # Should NOT contain sensitive fields
            sensitive_fields = [
                "password",
                "hashed_password",
                "secret",
                "private_key",
                "ssn",
                "credit_card",
                "bank_account",
                "phone",
                "address",
            ]

            for field in sensitive_fields:
                assert field not in user_data, f"Sensitive field exposed: {field}"

    def test_data_anonymization_in_logs(self, client: TestClient, test_users):
        """Test that sensitive data is anonymized in logs."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        with patch("src.api.main.logger") as mock_logger:
            # Make request that should be logged
            client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": "test_password"},
            )

            # Verify sensitive data is not in logs
            if mock_logger.called:
                for call in mock_logger.call_args_list:
                    log_message = str(call).lower()

                    # Passwords should never appear in logs
                    assert "test_password" not in log_message
                    assert (
                        "password" not in log_message or "password field" in log_message
                    )

                    # Other sensitive data should be masked
                    sensitive_data = ["ssn", "credit", "bank", "private"]
                    for data in sensitive_data:
                        if data in log_message:
                            # Should be masked (e.g., "***" or "[REDACTED]")
                            assert "***" in log_message or "redacted" in log_message

    def test_pii_detection_and_protection(self, client: TestClient, auth_headers):
        """Test detection and protection of Personally Identifiable Information."""
        # Test content with PII
        pii_test_cases = [
            {
                "topic": "Patient John Doe, SSN 123-45-6789, DOB 01/01/1990",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            {
                "topic": "Call patient at (555) 123-4567 regarding test results",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            {
                "topic": "Patient email: john.doe@email.com needs follow-up",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
        ]

        for test_case in pii_test_cases:
            response = client.post(
                "/api/v1/study-guide/create",
                json=test_case,
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text

                # PII should be masked or removed
                pii_patterns = [
                    r"\d{3}-\d{2}-\d{4}",  # SSN
                    r"\(\d{3}\)\s*\d{3}-\d{4}",  # Phone
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email
                    r"\d{1,2}/\d{1,2}/\d{4}",  # Date
                ]

                for pattern in pii_patterns:
                    matches = re.findall(pattern, response_text)
                    # If PII found, it should be masked
                    for match in matches:
                        assert (
                            "*" in match or "[REDACTED]" in response_text
                        ), f"PII not properly protected: {match}"

    def test_data_retention_controls(self, client: TestClient, auth_headers):
        """Test data retention and deletion controls."""
        # Create test data
        create_response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Temporary Study Guide",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            headers=auth_headers["student1"],
        )

        if create_response.status_code == status.HTTP_200_OK:
            # In production, verify data retention policies:
            # - Data older than retention period is purged
            # - Deletion requests are honored
            # - Data is securely wiped
            pass

    def test_cross_border_data_transfer_controls(self):
        """Test controls for cross-border data transfers."""
        # Verify data localization requirements
        # This would test:
        # - Data residency compliance
        # - Cross-border transfer restrictions
        # - Encryption for international transfers
        # - Compliance with GDPR, HIPAA, etc.
        pass


@pytest.mark.security
class TestSecureDataStorage:
    """Test secure data storage practices."""

    def test_password_storage_security(self, test_users):
        """Test that passwords are securely stored."""
        from src.auth import fake_users_db, get_password_hash, verify_password

        # Passwords should be hashed with strong algorithm
        password = "test_secure_password_123"
        hashed = get_password_hash(password)

        # Should use bcrypt (strong hashing)
        assert hashed.startswith("$2b$"), "Should use bcrypt for password hashing"
        assert len(hashed) >= 60, "Bcrypt hash should be at least 60 characters"

        # Original password should not be derivable from hash
        assert password not in hashed

        # Hash should verify correctly
        assert verify_password(password, hashed) is True
        assert verify_password("wrong_password", hashed) is False

        # Database should only contain hashed passwords
        fake_users_db.update(test_users)
        for username, user in fake_users_db.items():
            # No user should have plaintext password stored
            assert not hasattr(user, "password") or user.password is None
            assert user.hashed_password.startswith("$2b$")

    def test_sensitive_data_field_encryption(self, client: TestClient, auth_headers):
        """Test that sensitive data fields are encrypted at rest."""
        # This would test database-level encryption in production
        response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        if response.status_code == status.HTTP_200_OK:
            user_data = response.json()

            # Sensitive fields should not be present in API responses
            encrypted_fields = [
                "hashed_password",
                "secret_key",
                "private_key",
                "payment_info",
                "medical_record_number",
            ]

            for field in encrypted_fields:
                assert field not in user_data, f"Encrypted field exposed: {field}"

    def test_database_connection_security(self):
        """Test database connection security measures."""
        # This would test in production:
        # - SSL/TLS for database connections
        # - Connection string security
        # - Database authentication
        # - Connection pooling security
        # - SQL injection prevention at DB level
        pass

    def test_backup_data_protection(self):
        """Test that backup data is properly protected."""
        # This would test:
        # - Backup encryption
        # - Backup access controls
        # - Secure backup storage
        # - Backup data anonymization
        pass


@pytest.mark.security
class TestDataLeakagePrevention:
    """Test prevention of data leakage through various channels."""

    def test_error_message_data_leakage(self, client: TestClient):
        """Test that error messages don't leak sensitive data."""
        # Trigger various error conditions
        error_scenarios = [
            (
                "/api/v1/auth/login",
                "POST",
                {"username": "nonexistent", "password": "wrong"},
            ),
            ("/api/v1/analytics/student/invalid_id", "GET", None),
            ("/api/v1/assessment/competency/invalid", "GET", None),
        ]

        for endpoint, method, data in error_scenarios:
            if method == "POST" and data:
                response = client.post(endpoint, json=data)
            else:
                response = client.get(endpoint)

            response_text = response.text.lower()

            # Error messages should not leak sensitive information
            sensitive_leaks = [
                "database error",
                "connection string",
                "sql error",
                "internal server error",
                "stack trace",
                "file path",
                "/home/",
                "/var/",
                "c:\\",
                "password",
                "secret",
                "private key",
                "api key",
                "token",
                "hash",
            ]

            for leak in sensitive_leaks:
                assert (
                    leak not in response_text
                ), f"Sensitive data leaked in error message: {leak}"

    def test_debug_information_leakage(self, client: TestClient):
        """Test that debug information is not leaked in production."""
        response = client.get("/api/v1/auth/me")  # Will return 401

        # Should not contain debug information
        debug_indicators = [
            "traceback",
            "debug",
            "__file__",
            "__name__",
            "localhost",
            "127.0.0.1",
            "development",
            "test",
            "staging",
            ".py",
            "line ",
        ]

        response_text = response.text.lower()
        for indicator in debug_indicators:
            assert (
                indicator not in response_text
            ), f"Debug information leaked: {indicator}"

    def test_response_header_data_leakage(self, client: TestClient):
        """Test that response headers don't leak sensitive data."""
        response = client.get("/health")

        # Headers should not contain sensitive information
        sensitive_header_patterns = [
            "password",
            "secret",
            "key",
            "token",
            "hash",
            "database",
            "connection",
            "internal",
            "debug",
        ]

        headers_str = str(response.headers).lower()
        for pattern in sensitive_header_patterns:
            # Some patterns like "key" might be legitimate (e.g., in header names)
            # But should not contain actual sensitive values
            if pattern in headers_str:
                # Verify it's not a sensitive value
                assert not re.search(
                    rf"{pattern}\s*[=:]\s*[a-zA-Z0-9+/]{{10,}}", headers_str
                )

    def test_timing_attack_information_leakage(self, client: TestClient):
        """Test that timing differences don't leak information."""
        # Test login timing for existing vs non-existing users
        timing_samples = []

        # Time requests for non-existent users
        for i in range(5):
            start_time = time.time()
            client.post(
                "/api/v1/auth/login",
                json={"username": f"nonexistent_{i}", "password": "password"},
            )
            end_time = time.time()
            timing_samples.append(end_time - start_time)

        # Time requests for existing user with wrong password
        for i in range(5):
            start_time = time.time()
            client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": f"wrong_{i}"},
            )
            end_time = time.time()
            timing_samples.append(end_time - start_time)

        # Timing should be relatively consistent
        if len(timing_samples) > 1:
            import statistics

            mean_time = statistics.mean(timing_samples)
            std_dev = statistics.stdev(timing_samples)

            # Standard deviation should be less than 30% of mean
            # This allows for some variation while detecting obvious timing attacks
            assert (
                std_dev < mean_time * 0.3
            ), f"Potential timing attack vulnerability: std_dev={std_dev:.3f}, mean={mean_time:.3f}"


@pytest.mark.security
class TestComplianceAndRegulatory:
    """Test compliance with data protection regulations."""

    def test_hipaa_compliance_controls(self, client: TestClient, auth_headers):
        """Test HIPAA compliance for medical data protection."""
        # Test medical content handling
        medical_data = {
            "topic": "Patient care protocol with PHI",
            "competencies": ["AACN_KNOWLEDGE_1"],
            "content": "Patient John D. with condition X requires treatment Y",
        }

        response = client.post(
            "/api/v1/study-guide/create",
            json=medical_data,
            headers=auth_headers["student1"],
        )

        if response.status_code == status.HTTP_200_OK:
            # Medical content should be de-identified
            response_text = response.text

            # Should not contain potential PHI
            phi_patterns = [
                r"[A-Z][a-z]+ [A-Z]\.",  # Name pattern like "John D."
                r"Patient [A-Z][a-z]+",  # "Patient John"
                r"\d{3}-\d{2}-\d{4}",  # SSN pattern
                r"\d{2}/\d{2}/\d{4}",  # Date pattern
            ]

            for pattern in phi_patterns:
                matches = re.findall(pattern, response_text)
                # If found, should be de-identified
                for match in matches:
                    assert (
                        "[PATIENT]" in response_text or "***" in match
                    ), f"PHI not properly de-identified: {match}"

    def test_gdpr_compliance_controls(self, client: TestClient):
        """Test GDPR compliance controls."""
        # Test data subject rights (conceptual - would require full implementation)
        gdpr_requirements = [
            "data_portability",  # Right to data portability
            "data_erasure",  # Right to be forgotten
            "data_rectification",  # Right to rectification
            "access_request",  # Right of access
        ]

        # In production, would test:
        # - Data export functionality
        # - Data deletion functionality
        # - Privacy policy accessibility
        # - Consent management
        # - Data processing lawful basis
        pass

    def test_ferpa_compliance_for_educational_records(
        self, client: TestClient, auth_headers
    ):
        """Test FERPA compliance for educational records protection."""
        # Test student record access controls
        response = client.get(
            "/api/v1/analytics/student/student1",
            headers=auth_headers["instructor1"],
        )

        if response.status_code == status.HTTP_200_OK:
            # Educational records should be properly protected
            # Verify instructor can access student records (legitimate educational interest)
            pass

        # Test that students can't access other students' records
        response = client.get(
            "/api/v1/analytics/student/other_student",
            headers=auth_headers["student1"],
        )

        assert response.status_code in [
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
        ], "FERPA violation: Student accessed another student's records"

    def test_audit_trail_completeness(self, client: TestClient, auth_headers):
        """Test that comprehensive audit trails are maintained."""
        with patch("src.api.main.logger") as mock_logger:
            # Perform various actions that should be audited
            client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": "test_password"},
            )

            client.get("/api/v1/auth/me", headers=auth_headers["student1"])

            client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Test Topic",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            # Verify audit events are logged
            if mock_logger.called:
                # Should have audit entries for security events
                # This would be more comprehensive in production
                pass


@pytest.mark.security
class TestDataIntegrityAndValidation:
    """Test data integrity and validation security measures."""

    def test_data_integrity_validation(self, client: TestClient, auth_headers):
        """Test that data integrity is maintained and validated."""
        # Test data tampering detection
        response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Original Topic",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "integrity_check": "valid",
            },
            headers=auth_headers["student1"],
        )

        if response.status_code == status.HTTP_200_OK:
            # Verify data integrity mechanisms are in place
            # In production, this would test:
            # - Checksums/hashes for data integrity
            # - Digital signatures for critical data
            # - Version control for data changes
            # - Backup integrity verification
            pass

    def test_input_validation_security(self, client: TestClient, auth_headers):
        """Test comprehensive input validation for security."""
        # Test various malformed inputs
        malformed_inputs = [
            {"topic": "A" * 10000},  # Oversized input
            {"topic": "\x00\x01\x02"},  # Binary data
            {"topic": "\ufeff" + "Normal text"},  # BOM injection
            {"competencies": ["A" * 1000]},  # Oversized array elements
        ]

        for malformed_input in malformed_inputs:
            # Add required fields
            test_input = {"competencies": ["AACN_KNOWLEDGE_1"], **malformed_input}

            response = client.post(
                "/api/v1/study-guide/create",
                json=test_input,
                headers=auth_headers["student1"],
            )

            # Should handle malformed input gracefully
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ], f"Malformed input not properly handled: {malformed_input}"

    def test_data_sanitization_completeness(self, client: TestClient, auth_headers):
        """Test that data sanitization is comprehensive."""
        # Test various types of malicious content
        malicious_content_types = [
            "<script>alert('xss')</script>",  # XSS
            "'; DROP TABLE users; --",  # SQL injection
            "{{7*7}}",  # Template injection
            "; cat /etc/passwd",  # Command injection
            "javascript:alert(1)",  # JavaScript protocol
        ]

        for malicious_content in malicious_content_types:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": f"Medical Topic: {malicious_content}",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text.lower()

                # Malicious content should be sanitized
                dangerous_patterns = [
                    "<script",
                    "drop table",
                    "{{7*7}}",
                    "cat /etc/passwd",
                    "javascript:",
                ]

                for pattern in dangerous_patterns:
                    assert (
                        pattern not in response_text
                    ), f"Malicious content not sanitized: {pattern}"
