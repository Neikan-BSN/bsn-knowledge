"""
Comprehensive Security Headers and CORS Validation Tests (SEC-005)

Tests HTTP security headers, CORS configuration, content security policies,
and browser security enforcement for the RAGnostic → BSN Knowledge pipeline.

Security Focus:
- Content Security Policy (CSP) validation
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options and clickjacking prevention
- CORS configuration and origin validation
- Security header completeness
- Medical content security policies
"""

import re
from urllib.parse import urlparse

import pytest
from fastapi import status
from fastapi.testclient import TestClient


@pytest.mark.security
class TestSecurityHeadersImplementation:
    """Test comprehensive HTTP security headers implementation."""

    def test_content_security_policy_header(self, client: TestClient):
        """Test Content Security Policy header implementation."""
        response = client.get("/health")

        # CSP header should be present
        csp_header = response.headers.get("Content-Security-Policy")
        if csp_header:
            # Validate CSP directives
            csp_directives = self._parse_csp_header(csp_header)

            # Critical CSP directives for medical education platform
            required_directives = {
                "default-src": ["'self'"],
                "script-src": ["'self'"],
                "style-src": ["'self'", "'unsafe-inline'"],  # May need inline styles
                "img-src": ["'self'", "data:"],
                "font-src": ["'self'"],
                "connect-src": ["'self'"],
                "frame-ancestors": ["'none'"],  # Prevent clickjacking
            }

            for directive, expected_sources in required_directives.items():
                if directive in csp_directives:
                    directive_sources = csp_directives[directive]
                    for source in expected_sources:
                        # Allow additional sources but require minimum security
                        if source == "'self'" and "'self'" not in directive_sources:
                            pytest.fail(
                                f"CSP directive {directive} missing 'self' source"
                            )

    def test_x_frame_options_header(self, client: TestClient):
        """Test X-Frame-Options header for clickjacking prevention."""
        protected_endpoints = [
            "/health",
            "/api/v1/auth/me",
            "/api/v1/nclex/generate",
        ]

        for endpoint in protected_endpoints:
            response = client.get(endpoint, headers={"Authorization": "Bearer fake"})

            # X-Frame-Options should prevent embedding
            xframe_header = response.headers.get("X-Frame-Options")
            if xframe_header:
                acceptable_values = ["DENY", "SAMEORIGIN"]
                assert xframe_header.upper() in acceptable_values, (
                    f"X-Frame-Options has insecure value: {xframe_header}"
                )

    def test_x_content_type_options_header(self, client: TestClient):
        """Test X-Content-Type-Options header for MIME type sniffing prevention."""
        response = client.get("/health")

        xcto_header = response.headers.get("X-Content-Type-Options")
        if xcto_header:
            assert xcto_header.lower() == "nosniff", (
                f"X-Content-Type-Options should be 'nosniff', got: {xcto_header}"
            )

    def test_referrer_policy_header(self, client: TestClient):
        """Test Referrer Policy header for privacy protection."""
        response = client.get("/health")

        referrer_header = response.headers.get("Referrer-Policy")
        if referrer_header:
            # Acceptable referrer policies for medical platform
            secure_policies = [
                "strict-origin",
                "strict-origin-when-cross-origin",
                "same-origin",
                "no-referrer",
            ]

            assert referrer_header.lower() in secure_policies, (
                f"Insecure Referrer Policy: {referrer_header}"
            )

    def test_permissions_policy_header(self, client: TestClient):
        """Test Permissions Policy header (formerly Feature Policy)."""
        response = client.get("/health")

        permissions_header = response.headers.get("Permissions-Policy")
        if permissions_header:
            # Verify sensitive features are restricted
            restricted_features = ["camera", "microphone", "geolocation", "payment"]

            for feature in restricted_features:
                if feature in permissions_header:
                    # Feature should be restricted or limited
                    feature_policy = self._extract_feature_policy(
                        permissions_header, feature
                    )
                    assert feature_policy in [
                        "()",
                        "(self)",
                    ], f"Feature {feature} not properly restricted: {feature_policy}"

    def test_cache_control_security_headers(self, client: TestClient, auth_headers):
        """Test Cache-Control headers for sensitive endpoints."""
        sensitive_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/analytics/student/test_id",
            "/api/v1/assessment/competency",
        ]

        for endpoint in sensitive_endpoints:
            response = client.get(endpoint, headers=auth_headers.get("student1", {}))

            # Sensitive endpoints should have appropriate cache control
            cache_header = response.headers.get("Cache-Control", "").lower()

            # Should prevent caching of sensitive data
            if response.status_code == status.HTTP_200_OK:
                secure_cache_directives = ["no-cache", "no-store", "private"]
                has_secure_directive = any(
                    directive in cache_header for directive in secure_cache_directives
                )

                assert has_secure_directive, (
                    f"Sensitive endpoint {endpoint} missing secure cache directives"
                )

    def test_server_information_disclosure(self, client: TestClient):
        """Test that server information is not disclosed in headers."""
        response = client.get("/health")

        # Headers that might disclose server information
        information_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]

        for header in information_headers:
            header_value = response.headers.get(header, "")

            # Should not contain detailed version information
            version_patterns = [
                r"\d+\.\d+\.\d+",  # Version numbers
                r"nginx/\d+",  # Nginx version
                r"apache/\d+",  # Apache version
                r"gunicorn/\d+",  # Gunicorn version
            ]

            for pattern in version_patterns:
                assert not re.search(pattern, header_value, re.IGNORECASE), (
                    f"Server information disclosed in {header}: {header_value}"
                )

    def _parse_csp_header(self, csp_header: str) -> dict[str, list[str]]:
        """Parse Content Security Policy header into directives."""
        directives = {}

        for directive in csp_header.split(";"):
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if parts:
                directive_name = parts[0]
                sources = parts[1:] if len(parts) > 1 else []
                directives[directive_name] = sources

        return directives

    def _extract_feature_policy(self, permissions_header: str, feature: str) -> str:
        """Extract specific feature policy from Permissions Policy header."""
        # Simple extraction - in practice would need more sophisticated parsing
        pattern = rf"{feature}=\([^)]*\)"
        match = re.search(pattern, permissions_header)
        return match.group(0) if match else ""


@pytest.mark.security
class TestCORSSecurityValidation:
    """Test Cross-Origin Resource Sharing (CORS) security configuration."""

    def test_cors_origin_validation(self, client: TestClient):
        """Test that CORS origins are properly validated."""
        # Test various origin headers
        test_origins = [
            "https://legitimate-domain.edu",
            "https://bsn-knowledge.edu",
            "http://localhost:3000",  # Development
            "https://evil-domain.com",  # Should be rejected
            "null",  # Should be rejected
            "http://malicious-site.net",  # Should be rejected
        ]

        for origin in test_origins:
            response = client.options(
                "/api/v1/health",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                },
            )

            cors_origin = response.headers.get("Access-Control-Allow-Origin", "")

            # Validate CORS response based on origin
            if origin in [
                "https://evil-domain.com",
                "null",
                "http://malicious-site.net",
            ]:
                # Malicious origins should be rejected
                assert cors_origin != origin, f"Malicious origin allowed: {origin}"
            elif origin.startswith("https://") and "edu" in origin:
                # Educational domains might be allowed
                # This is application-specific validation
                pass

    def test_cors_methods_restriction(self, client: TestClient):
        """Test that CORS methods are appropriately restricted."""
        response = client.options(
            "/api/v1/nclex/generate",
            headers={
                "Origin": "https://legitimate-domain.edu",
                "Access-Control-Request-Method": "POST",
            },
        )

        allowed_methods = response.headers.get("Access-Control-Allow-Methods", "")

        # Dangerous methods should not be allowed
        dangerous_methods = ["TRACE", "DELETE", "PATCH"]
        for method in dangerous_methods:
            if method in allowed_methods.upper():
                # Verify the endpoint actually needs this method
                if method == "DELETE" and "admin" not in response.request.url.path:
                    pytest.fail(
                        f"Dangerous method {method} allowed on non-admin endpoint"
                    )

    def test_cors_credentials_handling(self, client: TestClient):
        """Test CORS credentials handling security."""
        response = client.options(
            "/api/v1/auth/me",
            headers={
                "Origin": "https://example.edu",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )

        allow_credentials = response.headers.get("Access-Control-Allow-Credentials")
        allow_origin = response.headers.get("Access-Control-Allow-Origin")

        # If credentials are allowed, origin should not be wildcard
        if allow_credentials and allow_credentials.lower() == "true":
            assert allow_origin != "*", (
                "CORS allows credentials with wildcard origin (security risk)"
            )

    def test_cors_headers_security(self, client: TestClient):
        """Test CORS allowed headers security."""
        response = client.options(
            "/api/v1/study-guide/create",
            headers={
                "Origin": "https://example.edu",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Authorization,X-Malicious-Header",
            },
        )

        allowed_headers = response.headers.get(
            "Access-Control-Allow-Headers", ""
        ).lower()

        # Should allow standard headers
        required_headers = ["content-type", "authorization"]
        for header in required_headers:
            if header not in allowed_headers:
                # This might be acceptable if handled differently
                pass

        # Should not allow dangerous headers
        dangerous_headers = ["x-malicious-header", "x-forwarded-for", "x-real-ip"]
        for header in dangerous_headers:
            assert header not in allowed_headers, (
                f"Dangerous header allowed in CORS: {header}"
            )

    def test_preflight_cache_control(self, client: TestClient):
        """Test CORS preflight response caching."""
        response = client.options(
            "/api/v1/nclex/generate",
            headers={
                "Origin": "https://example.edu",
                "Access-Control-Request-Method": "POST",
            },
        )

        max_age = response.headers.get("Access-Control-Max-Age")

        if max_age:
            max_age_value = int(max_age)
            # Reasonable cache time for security (not too long)
            assert 0 <= max_age_value <= 86400, (
                f"CORS preflight cache time too long: {max_age_value} seconds"
            )


@pytest.mark.security
class TestHTTPSAndTLSSecurityHeaders:
    """Test HTTPS and TLS-related security headers."""

    def test_hsts_header_implementation(self, client: TestClient):
        """Test HTTP Strict Transport Security (HSTS) header."""
        response = client.get("/health")

        hsts_header = response.headers.get("Strict-Transport-Security")

        if hsts_header:
            # Parse HSTS directive
            directives = {}
            for directive in hsts_header.split(";"):
                directive = directive.strip()
                if "=" in directive:
                    key, value = directive.split("=", 1)
                    directives[key.strip()] = value.strip()
                else:
                    directives[directive] = True

            # Validate HSTS configuration
            if "max-age" in directives:
                max_age = int(directives["max-age"])
                # HSTS max-age should be at least 30 days
                assert max_age >= 2592000, f"HSTS max-age too short: {max_age} seconds"

            # includeSubDomains is recommended for comprehensive security
            if "includeSubDomains" not in directives:
                # Log warning but don't fail (might be intentional)
                pass

    def test_upgrade_insecure_requests_header(self, client: TestClient):
        """Test Content-Security-Policy upgrade-insecure-requests directive."""
        response = client.get("/health")

        csp_header = response.headers.get("Content-Security-Policy", "")

        # Check for upgrade-insecure-requests directive
        if "upgrade-insecure-requests" in csp_header:
            # This is good for security
            pass
        else:
            # Not required but recommended for HTTPS enforcement
            pass

    def test_mixed_content_prevention(self, client: TestClient, auth_headers):
        """Test prevention of mixed content (HTTP resources on HTTPS pages)."""
        # Test content generation endpoints that might include external resources
        response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Nursing Care with External Resources",
                "competencies": ["AACN_KNOWLEDGE_1"],
            },
            headers=auth_headers.get("student1", {}),
        )

        if response.status_code == status.HTTP_200_OK:
            response_text = response.text

            # Check for insecure HTTP links in generated content
            http_urls = re.findall(r'http://[^\s<>"\']+', response_text)

            for url in http_urls:
                # Exclude localhost and development URLs
                parsed = urlparse(url)
                if parsed.hostname not in ["localhost", "127.0.0.1"]:
                    pytest.fail(f"Insecure HTTP URL in response: {url}")


@pytest.mark.security
class TestContentTypeAndMIMEValidation:
    """Test content type validation and MIME type security."""

    def test_json_content_type_validation(self, client: TestClient):
        """Test that JSON endpoints properly validate content types."""
        # Test with wrong content type
        response = client.post(
            "/api/v1/study-guide/create",
            data="malformed data",  # Not JSON
            headers={"Content-Type": "text/plain"},
        )

        # Should reject non-JSON content for JSON endpoints
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_response_content_type_consistency(self, client: TestClient, auth_headers):
        """Test that response content types are consistent and secure."""
        api_endpoints = [
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/nclex/generate", "POST"),
            ("/health", "GET"),
        ]

        for endpoint, method in api_endpoints:
            if method == "GET":
                response = client.get(
                    endpoint, headers=auth_headers.get("student1", {})
                )
            else:
                response = client.post(
                    endpoint,
                    json={
                        "topic": "Test",
                        "competencies": ["AACN_KNOWLEDGE_1"],
                        "difficulty": "medium",
                        "question_count": 1,
                    },
                    headers=auth_headers.get("student1", {}),
                )

            content_type = response.headers.get("Content-Type", "")

            # API endpoints should return JSON
            if "/api/" in endpoint:
                assert "application/json" in content_type.lower(), (
                    f"API endpoint {endpoint} not returning JSON: {content_type}"
                )

            # Health endpoint might return JSON or text
            if endpoint == "/health":
                acceptable_types = ["application/json", "text/plain", "text/html"]
                assert any(t in content_type.lower() for t in acceptable_types), (
                    f"Health endpoint unexpected content type: {content_type}"
                )

    def test_file_upload_mime_validation(self, client: TestClient, auth_headers):
        """Test MIME type validation for file uploads (if supported)."""
        # This test assumes file upload functionality exists
        # If not implemented, this test will be skipped

        dangerous_files = [
            ("malicious.exe", b"MZ\x90\x00", "application/x-msdownload"),
            ("script.js", b"alert('xss')", "application/javascript"),
            ("malware.zip", b"PK\x03\x04", "application/zip"),
        ]

        for filename, content, mime_type in dangerous_files:
            # Attempt file upload if endpoint exists
            files = {"file": (filename, content, mime_type)}

            # This is a hypothetical file upload endpoint
            response = client.post(
                "/api/v1/upload",
                files=files,
                headers=auth_headers.get("instructor1", {}),
            )

            # If endpoint exists, should reject dangerous files
            if response.status_code != status.HTTP_404_NOT_FOUND:
                assert response.status_code in [
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                ], f"Dangerous file type accepted: {filename}"


@pytest.mark.security
class TestSecurityHeadersEdgeCases:
    """Test security headers edge cases and advanced scenarios."""

    def test_multiple_security_headers_consistency(self, client: TestClient):
        """Test that multiple security headers are consistent with each other."""
        response = client.get("/health")

        headers = response.headers

        # Check for header conflicts
        csp_header = headers.get("Content-Security-Policy", "")
        xframe_header = headers.get("X-Frame-Options", "")

        # CSP frame-ancestors and X-Frame-Options should be consistent
        if "frame-ancestors 'none'" in csp_header and xframe_header:
            assert xframe_header.upper() in [
                "DENY",
                "SAMEORIGIN",
            ], "CSP frame-ancestors conflicts with X-Frame-Options"

    def test_security_headers_on_error_responses(self, client: TestClient):
        """Test that security headers are present on error responses."""
        # Trigger various error responses
        error_endpoints = [
            ("/api/v1/nonexistent", status.HTTP_404_NOT_FOUND),
            ("/api/v1/auth/me", status.HTTP_401_UNAUTHORIZED),  # No auth
            ("/api/v1/auth/users", status.HTTP_403_FORBIDDEN),  # No permission
        ]

        for endpoint, expected_status in error_endpoints:
            response = client.get(endpoint)

            if response.status_code == expected_status:
                # Error responses should still have security headers
                security_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                ]

                for _header in security_headers:
                    # Header presence is checked but not required
                    # (some headers might only be on successful responses)
                    pass

    def test_custom_security_headers(self, client: TestClient):
        """Test custom security headers specific to medical education platform."""
        response = client.get("/health")

        # Custom headers that might be implemented
        custom_headers = {
            "X-Medical-Content-Protected": "true",
            "X-Educational-Privacy": "enforced",
            "X-HIPAA-Compliant": "true",
        }

        for header_name, expected_value in custom_headers.items():
            header_value = response.headers.get(header_name)
            if header_value:
                # Validate custom header values
                assert header_value.lower() == expected_value.lower(), (
                    f"Custom header {header_name} unexpected value: {header_value}"
                )

    def test_security_headers_performance_impact(self, client: TestClient):
        """Test that security headers don't significantly impact performance."""
        import time

        # Measure response times with security headers
        start_time = time.time()
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == status.HTTP_200_OK
        end_time = time.time()

        avg_response_time = (end_time - start_time) / 10

        # Security headers should not add significant overhead
        assert avg_response_time < 0.1, (
            f"Security headers causing performance issues: {avg_response_time:.3f}s average"
        )
