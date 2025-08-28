#!/usr/bin/env python3
"""
Security Headers Validator for Group 3C Complete Security Validation

Comprehensive security headers validation with enterprise-grade testing
for medical education platform security compliance.

Validation Areas:
- Content Security Policy (CSP) Advanced Validation
- HTTP Strict Transport Security (HSTS) Enforcement
- Cross-Origin Resource Sharing (CORS) Security
- X-Frame-Options and Clickjacking Prevention
- Security Headers Completeness and Consistency
- Medical Platform Specific Headers
- Headers Under Attack Conditions

Compliance Standards:
- OWASP Security Headers Best Practices
- HIPAA Medical Data Protection Headers
- FERPA Educational Privacy Headers
- Enterprise Security Policy Enforcement
"""

import re
from datetime import datetime
from typing import Any

from fastapi.testclient import TestClient


class SecurityHeadersValidator:
    """Comprehensive security headers validation framework."""

    def __init__(self):
        self.validation_results = {}
        self.header_violations = []
        self.compliance_issues = []

    def validate_comprehensive_security_headers(
        self, client: TestClient, endpoints: list[str] | None = None
    ) -> dict[str, Any]:
        """Execute comprehensive security headers validation."""

        if endpoints is None:
            endpoints = [
                "/health",
                "/api/v1/auth/me",
                "/api/v1/nclex/generate",
                "/api/v1/study-guide/create",
                "/api/v1/analytics/student/test_id",
                "/api/v1/clinical-support/scenarios/generate",
            ]

        validation_report = {
            "timestamp": datetime.now().isoformat(),
            "total_endpoints_tested": len(endpoints),
            "total_violations": 0,
            "compliance_score": 0.0,
            "header_validations": {},
        }

        for endpoint in endpoints:
            endpoint_results = self._validate_endpoint_headers(client, endpoint)
            validation_report["header_validations"][endpoint] = endpoint_results
            validation_report["total_violations"] += endpoint_results.get(
                "violations", 0
            )

        # Calculate overall compliance score
        total_checks = sum(
            result.get("total_checks", 0)
            for result in validation_report["header_validations"].values()
        )
        total_violations = validation_report["total_violations"]
        validation_report["compliance_score"] = (
            ((total_checks - total_violations) / total_checks * 100)
            if total_checks > 0
            else 0.0
        )

        return validation_report

    def _validate_endpoint_headers(
        self, client: TestClient, endpoint: str
    ) -> dict[str, Any]:
        """Validate security headers for a specific endpoint."""
        result = {
            "endpoint": endpoint,
            "total_checks": 0,
            "violations": 0,
            "header_results": {},
            "recommendations": [],
        }

        try:
            # Test different HTTP methods
            responses = self._get_endpoint_responses(client, endpoint)

            for method, response in responses.items():
                if response is not None:
                    method_results = self._validate_response_headers(
                        response, endpoint, method
                    )
                    result["header_results"][method] = method_results
                    result["total_checks"] += method_results.get("checks", 0)
                    result["violations"] += method_results.get("violations", 0)
                    result["recommendations"].extend(
                        method_results.get("recommendations", [])
                    )

        except Exception as e:
            result["error"] = str(e)
            result["violations"] += 1

        return result

    def _get_endpoint_responses(
        self, client: TestClient, endpoint: str
    ) -> dict[str, Any]:
        """Get responses for different HTTP methods."""
        responses = {}

        # GET request
        try:
            responses["GET"] = client.get(endpoint)
        except Exception:
            responses["GET"] = None

        # OPTIONS request (for CORS testing)
        try:
            responses["OPTIONS"] = client.options(
                endpoint,
                headers={
                    "Origin": "https://example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        except Exception:
            responses["OPTIONS"] = None

        # POST request (if applicable)
        if "/api/" in endpoint and endpoint not in ["/api/v1/auth/me"]:
            try:
                responses["POST"] = client.post(
                    endpoint,
                    json={"test": "data"},
                    headers={"Content-Type": "application/json"},
                )
            except Exception:
                responses["POST"] = None

        return responses

    def _validate_response_headers(
        self, response, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate security headers in a response."""
        result = {
            "method": method,
            "status_code": response.status_code,
            "checks": 0,
            "violations": 0,
            "header_analysis": {},
            "recommendations": [],
        }

        headers = response.headers

        # Validate each security header
        security_header_validations = [
            ("Content-Security-Policy", self._validate_csp_header),
            ("Strict-Transport-Security", self._validate_hsts_header),
            ("X-Frame-Options", self._validate_xframe_header),
            ("X-Content-Type-Options", self._validate_content_type_options_header),
            ("Referrer-Policy", self._validate_referrer_policy_header),
            ("Permissions-Policy", self._validate_permissions_policy_header),
            ("Access-Control-Allow-Origin", self._validate_cors_origin_header),
            ("Cache-Control", self._validate_cache_control_header),
        ]

        for header_name, validation_function in security_header_validations:
            result["checks"] += 1
            header_result = validation_function(headers, header_name, endpoint, method)
            result["header_analysis"][header_name] = header_result

            if not header_result["valid"]:
                result["violations"] += 1
                result["recommendations"].extend(
                    header_result.get("recommendations", [])
                )

        # Additional security checks
        result["checks"] += 1
        server_disclosure = self._check_server_information_disclosure(headers)
        result["header_analysis"]["Server-Information-Disclosure"] = server_disclosure
        if not server_disclosure["valid"]:
            result["violations"] += 1
            result["recommendations"].extend(
                server_disclosure.get("recommendations", [])
            )

        return result

    def _validate_csp_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate Content Security Policy header."""
        csp_header = headers.get(header_name, "")

        if not csp_header:
            return {
                "valid": False,
                "present": False,
                "recommendations": [
                    f"Add Content-Security-Policy header to {endpoint}"
                ],
            }

        # Parse CSP directives
        directives = self._parse_csp_header(csp_header)

        # Critical CSP directives for medical education platform
        required_directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],  # May need inline styles for UI
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "frame-ancestors": ["'none'"],  # Prevent clickjacking
        }

        violations = []
        recommendations = []

        for directive, expected_sources in required_directives.items():
            if directive not in directives:
                violations.append(f"Missing CSP directive: {directive}")
                recommendations.append(f"Add {directive} directive to CSP")
            else:
                directive_sources = directives[directive]

                # Check for 'self' requirement
                if "'self'" in expected_sources and "'self'" not in directive_sources:
                    violations.append(
                        f"CSP directive {directive} missing 'self' source"
                    )
                    recommendations.append(f"Add 'self' to {directive} directive")

                # Check for dangerous sources
                dangerous_sources = ["*", "'unsafe-eval'", "data:", "http:"]
                for dangerous in dangerous_sources:
                    if (
                        dangerous in directive_sources
                        and dangerous != "data:"
                        and directive != "img-src"
                    ):
                        violations.append(
                            f"Dangerous CSP source in {directive}: {dangerous}"
                        )
                        recommendations.append(
                            f"Remove dangerous source {dangerous} from {directive}"
                        )

        return {
            "valid": len(violations) == 0,
            "present": True,
            "directives": directives,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _validate_hsts_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate HTTP Strict Transport Security header."""
        hsts_header = headers.get(header_name, "")

        if not hsts_header:
            return {
                "valid": False,
                "present": False,
                "recommendations": [
                    f"Add Strict-Transport-Security header to {endpoint}"
                ],
            }

        # Parse HSTS directives
        directives = {}
        violations = []
        recommendations = []

        for directive in hsts_header.split(";"):
            directive = directive.strip()
            if "=" in directive:
                key, value = directive.split("=", 1)
                directives[key.strip()] = value.strip()
            else:
                directives[directive] = True

        # Validate max-age
        if "max-age" not in directives:
            violations.append("HSTS missing max-age directive")
            recommendations.append("Add max-age directive to HSTS header")
        else:
            try:
                max_age = int(directives["max-age"])
                if max_age < 2592000:  # 30 days minimum
                    violations.append(f"HSTS max-age too short: {max_age} seconds")
                    recommendations.append(
                        "Set HSTS max-age to at least 2592000 seconds (30 days)"
                    )
            except ValueError:
                violations.append("Invalid HSTS max-age value")
                recommendations.append("Set valid numeric HSTS max-age value")

        # Recommend includeSubDomains for comprehensive security
        if "includeSubDomains" not in directives:
            recommendations.append("Consider adding includeSubDomains to HSTS header")

        return {
            "valid": len(violations) == 0,
            "present": True,
            "directives": directives,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _validate_xframe_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate X-Frame-Options header."""
        xframe_header = headers.get(header_name, "")

        # Check if CSP frame-ancestors is present as alternative
        csp_header = headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_header

        if not xframe_header and not has_frame_ancestors:
            return {
                "valid": False,
                "present": False,
                "recommendations": [
                    f"Add X-Frame-Options header or CSP frame-ancestors to {endpoint}"
                ],
            }

        violations = []
        recommendations = []

        if xframe_header:
            acceptable_values = ["DENY", "SAMEORIGIN"]
            if xframe_header.upper() not in acceptable_values:
                violations.append(f"Insecure X-Frame-Options value: {xframe_header}")
                recommendations.append("Set X-Frame-Options to DENY or SAMEORIGIN")

        return {
            "valid": len(violations) == 0,
            "present": bool(xframe_header),
            "value": xframe_header,
            "csp_alternative": has_frame_ancestors,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _validate_content_type_options_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate X-Content-Type-Options header."""
        header_value = headers.get(header_name, "")

        if not header_value:
            return {
                "valid": False,
                "present": False,
                "recommendations": [
                    f"Add X-Content-Type-Options: nosniff header to {endpoint}"
                ],
            }

        violations = []
        if header_value.lower() != "nosniff":
            violations.append(f"Invalid X-Content-Type-Options value: {header_value}")

        return {
            "valid": len(violations) == 0,
            "present": True,
            "value": header_value,
            "violations": violations,
            "recommendations": ["Set X-Content-Type-Options to 'nosniff'"]
            if violations
            else [],
        }

    def _validate_referrer_policy_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate Referrer Policy header for medical privacy."""
        referrer_header = headers.get(header_name, "")

        # Referrer-Policy is especially important for medical platforms
        if not referrer_header:
            return {
                "valid": False,
                "present": False,
                "recommendations": [
                    f"Add Referrer-Policy header to {endpoint} for medical privacy"
                ],
            }

        # Secure referrer policies for medical platform
        secure_policies = [
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin",
            "no-referrer",
        ]

        violations = []
        if referrer_header.lower() not in secure_policies:
            violations.append(
                f"Insecure Referrer-Policy for medical platform: {referrer_header}"
            )

        return {
            "valid": len(violations) == 0,
            "present": True,
            "value": referrer_header,
            "violations": violations,
            "recommendations": [
                "Use secure Referrer-Policy (strict-origin, same-origin, or no-referrer)"
            ]
            if violations
            else [],
        }

    def _validate_permissions_policy_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate Permissions Policy header."""
        permissions_header = headers.get(header_name, "")

        if not permissions_header:
            return {
                "valid": True,  # Optional header
                "present": False,
                "recommendations": [
                    f"Consider adding Permissions-Policy header to {endpoint}"
                ],
            }

        # Check for properly restricted sensitive features
        restricted_features = ["camera", "microphone", "geolocation", "payment", "usb"]
        violations = []
        recommendations = []

        for feature in restricted_features:
            if feature in permissions_header:
                feature_policy = self._extract_feature_policy(
                    permissions_header, feature
                )
                if feature_policy not in ["()", "(self)"]:
                    violations.append(
                        f"Feature {feature} not properly restricted: {feature_policy}"
                    )
                    recommendations.append(
                        f"Restrict {feature} feature to () or (self)"
                    )

        return {
            "valid": len(violations) == 0,
            "present": True,
            "value": permissions_header,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _validate_cors_origin_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate CORS Access-Control-Allow-Origin header."""
        cors_origin = headers.get(header_name, "")

        # CORS validation is method-specific
        if method != "OPTIONS":
            return {
                "valid": True,
                "present": bool(cors_origin),
                "note": "CORS validation skipped for non-OPTIONS request",
            }

        violations = []
        recommendations = []

        if cors_origin:
            # Check for overly permissive CORS
            if cors_origin == "*":
                # Check if credentials are also allowed (dangerous combination)
                allow_credentials = headers.get("Access-Control-Allow-Credentials", "")
                if allow_credentials and allow_credentials.lower() == "true":
                    violations.append(
                        "Dangerous CORS configuration: wildcard origin with credentials"
                    )
                    recommendations.append(
                        "Do not use wildcard origin with credentials enabled"
                    )

        # Validate CORS methods
        allowed_methods = headers.get("Access-Control-Allow-Methods", "")
        if allowed_methods:
            dangerous_methods = ["TRACE", "DELETE", "PATCH"]
            for method_check in dangerous_methods:
                if method_check in allowed_methods.upper():
                    # Only flag as violation if endpoint doesn't need this method
                    if "admin" not in endpoint.lower():
                        violations.append(
                            f"Potentially dangerous CORS method allowed: {method_check}"
                        )
                        recommendations.append(
                            f"Review necessity of {method_check} method for {endpoint}"
                        )

        return {
            "valid": len(violations) == 0,
            "present": bool(cors_origin),
            "origin": cors_origin,
            "methods": allowed_methods,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _validate_cache_control_header(
        self, headers: dict, header_name: str, endpoint: str, method: str
    ) -> dict[str, Any]:
        """Validate Cache-Control header for sensitive endpoints."""
        cache_header = headers.get(header_name, "")

        # Identify sensitive endpoints that should have secure cache control
        sensitive_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/analytics/",
            "/api/v1/assessment/",
        ]

        is_sensitive = any(sensitive in endpoint for sensitive in sensitive_endpoints)

        if not is_sensitive:
            return {
                "valid": True,
                "present": bool(cache_header),
                "note": "Cache control validation skipped for non-sensitive endpoint",
            }

        violations = []
        recommendations = []

        if not cache_header:
            violations.append(
                f"Missing Cache-Control header on sensitive endpoint: {endpoint}"
            )
            recommendations.append(
                "Add secure Cache-Control header (no-cache, no-store, or private)"
            )
        else:
            # Check for secure cache directives
            secure_directives = ["no-cache", "no-store", "private"]
            has_secure_directive = any(
                directive in cache_header.lower() for directive in secure_directives
            )

            if not has_secure_directive:
                violations.append(
                    f"Insecure cache control on sensitive endpoint: {cache_header}"
                )
                recommendations.append(
                    "Use secure cache directives (no-cache, no-store, or private) on sensitive endpoints"
                )

        return {
            "valid": len(violations) == 0,
            "present": bool(cache_header),
            "value": cache_header,
            "is_sensitive_endpoint": is_sensitive,
            "violations": violations,
            "recommendations": recommendations,
        }

    def _check_server_information_disclosure(self, headers: dict) -> dict[str, Any]:
        """Check for server information disclosure in headers."""
        information_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Framework",
        ]

        violations = []
        recommendations = []
        disclosed_info = {}

        for header in information_headers:
            header_value = headers.get(header, "")
            if header_value:
                disclosed_info[header] = header_value

                # Check for detailed version information
                version_patterns = [
                    r"\d+\.\d+\.\d+",  # Version numbers
                    r"nginx/\d+",  # Nginx version
                    r"apache/\d+",  # Apache version
                    r"gunicorn/\d+",  # Gunicorn version
                    r"fastapi/\d+",  # FastAPI version
                ]

                for pattern in version_patterns:
                    if re.search(pattern, header_value, re.IGNORECASE):
                        violations.append(
                            f"Server version disclosed in {header}: {header_value}"
                        )
                        recommendations.append(
                            f"Remove version information from {header} header"
                        )
                        break

        return {
            "valid": len(violations) == 0,
            "present": len(disclosed_info) > 0,
            "disclosed_headers": disclosed_info,
            "violations": violations,
            "recommendations": recommendations,
        }

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
        # Simplified extraction for basic validation
        pattern = rf"{feature}=\([^)]*\)"
        match = re.search(pattern, permissions_header)
        return match.group(0) if match else ""


# Integration with Group 3C Security Validation


def validate_security_headers_comprehensive(
    client: TestClient, endpoints: list[str] | None = None
) -> dict[str, Any]:
    """Comprehensive security headers validation for Group 3C."""
    validator = SecurityHeadersValidator()
    return validator.validate_comprehensive_security_headers(client, endpoints)


# Medical Platform Specific Security Headers Validation


def validate_medical_platform_security_headers(client: TestClient) -> dict[str, Any]:
    """Validate medical platform specific security headers."""
    medical_endpoints = [
        "/api/v1/nclex/generate",
        "/api/v1/clinical-support/scenarios/generate",
        "/api/v1/study-guide/create",
        "/api/v1/analytics/student/test_id",
        "/api/v1/assessment/competency",
    ]

    validator = SecurityHeadersValidator()
    return validator.validate_comprehensive_security_headers(client, medical_endpoints)


if __name__ == "__main__":
    print("Security Headers Validator for Group 3C Complete Security Validation")
    print("Comprehensive security headers validation with enterprise-grade testing")
    print()
    print("Features:")
    print("- Content Security Policy (CSP) Advanced Validation")
    print("- HTTP Strict Transport Security (HSTS) Enforcement")
    print("- Cross-Origin Resource Sharing (CORS) Security")
    print("- Medical Platform Specific Headers")
    print("- Server Information Disclosure Prevention")
    print()
    print("Usage:")
    print(
        "  from security_headers_validator import validate_security_headers_comprehensive"
    )
    print("  report = validate_security_headers_comprehensive(client)")
