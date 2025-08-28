"""
Security Test Suite for RAGnostic → BSN Knowledge Pipeline

Comprehensive security testing framework covering authentication, authorization,
data protection, and injection prevention for enterprise-grade security validation.

Test Categories:
- Authentication Security: JWT validation, session management, bypass prevention
- Injection Prevention: SQL, XSS, command, LDAP, NoSQL injection prevention
- Access Control: RBAC, privilege escalation prevention, resource protection
- Data Protection: Encryption, privacy controls, compliance validation

Usage:
    pytest tests/security/ -v --security-comprehensive
    pytest tests/security/auth_security_tests.py --auth-security
    pytest tests/security/injection_prevention_tests.py --injection-tests
    pytest tests/security/access_control_tests.py --access-control
    pytest tests/security/data_protection_tests.py --data-protection
"""

__version__ = "1.0.0"
__author__ = "BSN Knowledge Security Team"

# Test suite constants
SECURITY_TEST_CATEGORIES = [
    "authentication",
    "authorization",
    "injection_prevention",
    "data_protection",
    "compliance",
]

SECURITY_TEST_LEVELS = {
    "basic": "Essential security validations",
    "standard": "Comprehensive security testing",
    "enterprise": "Full enterprise-grade security validation",
}

# Import all security test modules for convenience
try:
    from . import (
        access_control_tests,  # noqa: F401
        auth_security_tests,  # noqa: F401
        data_protection_tests,  # noqa: F401
        injection_prevention_tests,  # noqa: F401
    )
except ImportError:
    # Handle import errors gracefully during development
    pass
