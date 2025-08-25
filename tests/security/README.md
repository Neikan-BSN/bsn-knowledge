# Security Validation Test Suite

## Overview

Comprehensive enterprise-grade security validation framework for the RAGnostic → BSN Knowledge pipeline. This test suite provides thorough security testing across authentication, authorization, data protection, and injection prevention.

## Test Categories

### 1. Authentication Security (`auth_security_tests.py`)
- Authentication bypass prevention
- JWT security validation
- Cross-service authentication
- Session management security
- Rate limiting bypass prevention
- Performance attack resistance
- Token security best practices

### 2. Injection Prevention (`injection_prevention_tests.py`)
- SQL injection prevention (classic, blind, second-order)
- XSS prevention (reflected, stored, DOM-based)
- Command injection prevention
- LDAP injection prevention
- NoSQL injection prevention
- Template injection prevention
- Comprehensive input sanitization

### 3. Access Control (`access_control_tests.py`)
- Role-based access control validation
- Privilege escalation prevention
- Resource access control
- Cross-service authorization
- Authorization bypass prevention
- Performance and resilience testing

### 4. Data Protection (`data_protection_tests.py`)
- Data encryption in transit
- Data privacy controls
- Secure data storage
- Data leakage prevention
- Compliance validation (HIPAA, GDPR, FERPA)
- Data integrity and validation

## Quick Start

### Run All Security Tests
```bash
# Comprehensive security validation
python run_security_validation.py --level=enterprise

# Standard security testing
python run_security_validation.py --level=standard

# Basic security validation
python run_security_validation.py --level=basic
```

### Run Specific Categories
```bash
# Authentication tests only
pytest tests/security/auth_security_tests.py -v

# Injection prevention tests
pytest tests/security/injection_prevention_tests.py -v

# Access control tests
pytest tests/security/access_control_tests.py -v

# Data protection tests
pytest tests/security/data_protection_tests.py -v
```

### Compliance Testing
```bash
# HIPAA compliance validation
python run_security_validation.py --compliance=hipaa

# Multiple compliance standards
python run_security_validation.py --compliance=hipaa,ferpa,gdpr
```

## Test Structure

Each test file follows a consistent structure:

```python
@pytest.mark.security
class TestSecurityCategory:
    """Test class for specific security category."""

    def test_specific_vulnerability(self, client, auth_headers):
        """Test prevention of specific vulnerability."""
        # Test implementation
        pass
```

## Security Requirements

### Critical Security Standards
- ✅ Zero authentication bypass tolerance
- ✅ Complete injection prevention
- ✅ Strict role-based access control
- ✅ Comprehensive data protection
- ✅ Full compliance validation

### Performance Requirements
- Authentication overhead: < 50ms per request
- Authorization decisions: < 10ms per request
- Input validation: < 25ms per request
- Security middleware: < 100ms total overhead

## CI/CD Integration

### Pre-commit Hooks
```bash
# Run security linting
bandit -r src/
semgrep --config=security src/

# Quick security tests
pytest tests/security/ -m "not slow" --tb=short
```

### CI Pipeline Integration
```yaml
# .github/workflows/security.yml
- name: Run Security Tests
  run: |
    python run_security_validation.py --level=standard
    pytest tests/security/ --cov=src --cov-report=xml
```

## Test Data and Fixtures

### Authentication Fixtures
- `auth_headers`: Pre-configured authentication headers for different roles
- `test_users`: Test user data with various roles and permissions
- `assert_valid_jwt_token`: JWT token validation helper

### Security Test Data
- SQL injection payloads
- XSS attack vectors
- Command injection patterns
- Malformed authentication attempts
- Privilege escalation scenarios

## Security Monitoring

The test suite integrates with security monitoring:

### Real-time Alerts
- Failed authentication attempts
- Injection attack detection
- Privilege escalation attempts
- Data protection violations

### Compliance Reporting
- HIPAA compliance validation
- FERPA educational record protection
- GDPR data privacy controls
- SOC 2 security controls

## Contributing

### Adding New Security Tests

1. **Identify Security Risk**: Determine specific vulnerability or threat
2. **Choose Test Category**: Place in appropriate test file
3. **Follow Naming Convention**: Use descriptive test names
4. **Add Comprehensive Coverage**: Test positive and negative cases
5. **Update Documentation**: Add to relevant sections

### Test Naming Convention
```python
def test_[vulnerability_type]_prevention(self, fixtures):
    """Test prevention of [specific vulnerability]."""
```

### Example Test Addition
```python
@pytest.mark.security
def test_new_injection_type_prevention(self, client, auth_headers):
    """Test prevention of new injection attack type."""
    malicious_payloads = [
        "payload1",
        "payload2",
        "payload3"
    ]

    for payload in malicious_payloads:
        response = client.post(
            "/api/endpoint",
            json={"data": payload},
            headers=auth_headers["student1"]
        )

        # Verify attack is prevented
        assert response.status_code != 500
        assert "malicious_result" not in response.text
```

## Troubleshooting

### Common Issues

**Test Environment Setup**
```bash
# Install security testing dependencies
pip install pytest-security pytest-httpx bandit semgrep

# Set test environment variables
export JWT_SECRET_KEY="test_secret_key_for_testing"
export DATABASE_URL="sqlite:///test_security.db"
```

**Authentication Test Failures**
- Verify test users are properly configured in fixtures
- Check JWT secret key configuration
- Ensure test database is clean between runs

**Injection Test Failures**
- Review input validation implementation
- Check sanitization functions
- Verify output encoding

**Performance Test Issues**
- Ensure adequate test environment resources
- Check for test interference or race conditions
- Review timeout configurations

## Security Test Metrics

### Coverage Targets
- **Authentication**: 95%+ test coverage
- **Authorization**: 90%+ test coverage
- **Input Validation**: 95%+ test coverage
- **Data Protection**: 85%+ test coverage

### Success Criteria
- Zero critical security vulnerabilities
- All enterprise security tests passing
- Complete compliance validation
- Performance requirements met

## Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [BSN Knowledge Security Documentation](../docs/security/)
- [RAGnostic Security Integration Guide](../docs/security/ragnostic-integration.md)

---

**Security Contact**: security@bsnknowledge.edu
**Last Updated**: 2025-08-25
**Version**: 1.0.0
