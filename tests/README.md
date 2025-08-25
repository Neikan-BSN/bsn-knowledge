# BSN Knowledge API Testing Suite

Comprehensive testing suite for the BSN Knowledge nursing education platform API, covering authentication, endpoints, rate limiting, security, and performance testing.

## Overview

This testing suite provides >90% test coverage for the BSN Knowledge API with the following test categories:

- **Authentication & Authorization**: JWT tokens, role-based access, OAuth2 flow
- **API Endpoints**: All Phase 3 critical endpoints and core functionality
- **Rate Limiting**: Tiered rate limits, enforcement, bypass prevention
- **Error Handling**: Custom errors, input validation, graceful failures
- **Security**: XSS/SQL injection prevention, input sanitization
- **Integration**: End-to-end workflows, data consistency
- **Performance**: Response times, concurrent handling, scalability

## Test Structure

```
tests/
├── conftest.py              # Test configuration and fixtures
├── test_authentication.py   # Authentication & authorization tests
├── test_endpoints.py        # API endpoint tests
├── test_rate_limiting.py    # Rate limiting tests
├── test_error_handling.py   # Error handling tests
├── test_security.py         # Security tests
├── test_integration.py      # Integration tests
├── test_performance.py      # Performance tests
├── utils/
│   ├── test_helpers.py      # Test utility functions
│   └── mock_data.py         # Test data generators
└── README.md               # This file
```

## Quick Start

### Prerequisites

- Python 3.12+ with UV package manager
- BSN Knowledge API running locally
- Test dependencies installed

### Setup

1. **Install dependencies**:
   ```bash
   uv sync --all-extras
   ```

2. **Set environment variables**:
   ```bash
   export TEST_DATABASE_URL="sqlite+aiosqlite:///./test_bsn_knowledge.db"
   export JWT_SECRET_KEY="test_secret_key_for_testing_only"
   ```

3. **Start the API server** (in separate terminal):
   ```bash
   uvicorn src.api.main:app --reload --port 8000
   ```

### Running Tests

**Run all tests**:
```bash
pytest tests/ -v
```

**Run specific test categories**:
```bash
pytest tests/ -m "auth" -v                    # Authentication tests
pytest tests/ -m "endpoints" -v               # Endpoint tests
pytest tests/ -m "rate_limiting" -v           # Rate limiting tests
pytest tests/ -m "security" -v                # Security tests
pytest tests/ -m "performance" -v             # Performance tests
pytest tests/ -m "integration" -v             # Integration tests
```

**Run with coverage**:
```bash
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing
```

**Run performance benchmarks only**:
```bash
pytest tests/test_performance.py -v -s
```

**Skip slow tests**:
```bash
pytest tests/ -v -m "not slow"
```

## Test Categories

### 1. Authentication Tests (`test_authentication.py`)

Tests JWT authentication, role-based access control, and OAuth2 integration.

**Key Test Areas**:
- JWT token generation and validation
- Password hashing security
- Role-based endpoint access
- Token refresh mechanism
- Authentication bypass prevention

**Critical Tests**:
- `test_jwt_token_claims_security` - Ensures tokens don't contain sensitive data
- `test_role_based_access_enforcement` - Validates role restrictions
- `test_password_timing_attack_resistance` - Security timing validation

### 2. API Endpoint Tests (`test_endpoints.py`)

Tests all API endpoints including Phase 3 critical endpoints.

**Phase 3 Critical Endpoints**:
- `POST /api/v1/nclex/generate` - NCLEX question generation
- `POST /api/v1/assessment/competency` - Competency assessment
- `POST /api/v1/study-guide/create` - Study guide creation
- `GET /api/v1/analytics/student/{id}` - Student analytics

**Key Test Areas**:
- Endpoint functionality and response validation
- Authentication requirements
- Input validation and error handling
- Response format consistency

### 3. Rate Limiting Tests (`test_rate_limiting.py`)

Tests tiered rate limiting system with different limits per endpoint type.

**Rate Limit Tiers**:
- General endpoints: 1,000 requests/hour
- Content generation: 50 requests/hour
- Assessment endpoints: 200 requests/hour
- Analytics endpoints: 500 requests/hour

**Key Test Areas**:
- Rate limit enforcement per tier
- Rate limit headers in responses
- Bypass prevention techniques
- Performance impact of rate limiting

### 4. Error Handling Tests (`test_error_handling.py`)

Tests comprehensive error handling and custom error responses.

**Error Types Tested**:
- Validation errors (400, 422)
- Authentication errors (401)
- Authorization errors (403)
- Resource not found (404)
- Rate limit exceeded (429)
- Internal server errors (500)

**Key Test Areas**:
- Custom error response format
- Input validation security
- Error logging (no sensitive data)
- Graceful error recovery

### 5. Security Tests (`test_security.py`)

Tests security measures and vulnerability prevention.

**Security Areas**:
- SQL injection prevention
- XSS (Cross-Site Scripting) prevention
- Path traversal prevention
- Command injection prevention
- Medical content validation safety

**Key Test Areas**:
- Input sanitization effectiveness
- Authentication security measures
- Medical content injection prevention
- Threat model scenario testing

### 6. Integration Tests (`test_integration.py`)

Tests end-to-end workflows and system integration.

**Integration Scenarios**:
- Complete student learning workflow
- Instructor class management
- Administrator system management
- RAGnostic service integration

**Key Test Areas**:
- Cross-endpoint data consistency
- End-to-end user journeys
- External service integration
- Bulk operations

### 7. Performance Tests (`test_performance.py`)

Tests API performance requirements and scalability.

**Performance Requirements**:
- Health endpoint: <100ms
- Simple operations: <500ms
- Complex operations: <2000ms
- Concurrent request handling
- Memory usage stability

**Key Test Areas**:
- Response time validation
- Concurrent user handling
- Memory usage patterns
- Database operation performance
- Load testing scenarios

## Test Data and Fixtures

### Test Users

The test suite includes pre-configured test users:

```python
# Available test users
test_users = {
    "student1": UserRole.STUDENT,
    "instructor1": UserRole.INSTRUCTOR,
    "admin1": UserRole.ADMIN,
    "inactive_user": UserRole.STUDENT (inactive)
}

# All use password: "test_password"
```

### Mock Data Generators

**Nursing-Specific Data**:
- Realistic NCLEX questions
- Clinical scenarios (cardiovascular, medication safety, infection control)
- Student performance data
- Competency assessments
- Learning analytics

**Test Helpers**:
- Authentication token generation
- Performance monitoring
- Response validation
- Security test payloads

### Fixtures Available

**Authentication**:
- `auth_tokens` - JWT tokens for all test users
- `auth_headers` - Authorization headers ready for requests
- `test_users` - Complete user objects

**Mock Services**:
- `mock_ragnostic_client` - Mocked RAGnostic service
- `mock_competency_framework` - Mocked AACN framework
- `mock_analytics_data` - Sample analytics responses

**Testing Utilities**:
- `performance_monitor` - Performance measurement
- `assert_valid_jwt_token` - JWT validation helper
- `reset_rate_limiter` - Rate limiter state reset

## Running Specific Test Scenarios

### Test Authentication Flow

```bash
# Test complete authentication workflow
pytest tests/test_authentication.py::TestJWTTokenGeneration -v

# Test role-based access
pytest tests/test_authentication.py::TestRoleBasedAccess -v
```

### Test Phase 3 Endpoints

```bash
# Test all Phase 3 critical endpoints
pytest tests/test_endpoints.py::TestNCLEXGenerationEndpoint -v
pytest tests/test_endpoints.py::TestCompetencyAssessmentEndpoint -v
pytest tests/test_endpoints.py::TestStudyGuideEndpoint -v
pytest tests/test_endpoints.py::TestAnalyticsEndpoint -v
```

### Test Rate Limiting

```bash
# Test tiered rate limiting
pytest tests/test_rate_limiting.py::TestTieredRateLimiting -v

# Test bypass prevention
pytest tests/test_rate_limiting.py::TestRateLimitBypassPrevention -v
```

### Test Security

```bash
# Test input sanitization
pytest tests/test_security.py::TestInputSanitization -v

# Test medical content safety
pytest tests/test_security.py::TestMedicalContentValidationSecurity -v
```

### Test Performance

```bash
# Test response time requirements
pytest tests/test_performance.py::TestResponseTimePerformance -v

# Test concurrent handling
pytest tests/test_performance.py::TestConcurrentRequestHandling -v
```

## Coverage Analysis

### Target Coverage: >90%

The test suite aims for >90% code coverage across all modules:

**Generate coverage report**:
```bash
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html  # View detailed coverage report
```

**Coverage by module**:
```bash
pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=90
```

### Coverage Areas

**High Priority (Must be >95%)**:
- Authentication logic (`src/auth.py`)
- API endpoints (`src/api/routers/`)
- Error handlers (`src/api/error_handlers.py`)

**Medium Priority (Must be >90%)**:
- Business logic (`src/services/`)
- Data models (`src/models/`)
- Utilities (`src/utils/`)

**Lower Priority (Must be >80%)**:
- Configuration (`src/config.py`)
- Database migrations
- External integrations

## Performance Benchmarks

### Response Time Benchmarks

Established benchmarks for performance regression testing:

| Endpoint Type | Target Response Time | Test Method |
|---------------|---------------------|-------------|
| Health Check | <100ms | `test_health_endpoint_response_time` |
| Authentication | <500ms | `test_authentication_response_time` |
| Simple Endpoints | <500ms | `test_simple_endpoint_response_times` |
| Complex Operations | <2000ms | `test_complex_endpoint_response_times` |

### Concurrency Benchmarks

| Scenario | Concurrent Users | Success Rate | Test Method |
|----------|------------------|--------------|-------------|
| Health Checks | 10 | 100% | `test_concurrent_health_checks` |
| Authentication | 3 | 100% | `test_concurrent_authentication` |
| Mixed Operations | 4 | >95% | `test_mixed_concurrent_operations` |

## Troubleshooting

### Common Issues

**1. Test database connection errors**:
```bash
# Ensure test database is accessible
export TEST_DATABASE_URL="sqlite+aiosqlite:///./test_bsn_knowledge.db"
```

**2. Authentication test failures**:
```bash
# Reset test user database
pytest tests/test_authentication.py --setup-show
```

**3. Rate limiting test interference**:
```bash
# Run rate limiting tests in isolation
pytest tests/test_rate_limiting.py --forked
```

**4. Performance test variability**:
```bash
# Run performance tests multiple times for stability
pytest tests/test_performance.py --count=3
```

### Debug Mode

**Run tests with detailed output**:
```bash
pytest tests/ -v -s --tb=long
```

**Run single test with debug**:
```bash
pytest tests/test_authentication.py::test_login_success -v -s --pdb
```

### Test Environment Issues

**Check test environment setup**:
```bash
# Verify API is running
curl http://localhost:8000/health

# Check test database
ls -la *.db

# Verify test dependencies
uv sync --all-extras
pip list | grep pytest
```

## Contributing to Tests

### Adding New Tests

1. **Follow naming conventions**:
   - Test files: `test_*.py`
   - Test methods: `test_*`
   - Test classes: `Test*`

2. **Use appropriate markers**:
   ```python
   @pytest.mark.auth          # Authentication tests
   @pytest.mark.endpoints     # Endpoint tests
   @pytest.mark.security      # Security tests
   @pytest.mark.performance   # Performance tests
   @pytest.mark.slow          # Slow running tests
   ```

3. **Include docstrings**:
   ```python
   def test_new_functionality(self, client, auth_headers):
       """Test new functionality with proper authentication."""
       # Test implementation
   ```

4. **Use fixtures appropriately**:
   ```python
   def test_with_mock_data(self, client, auth_headers, mock_nclex_questions):
       """Use existing fixtures for consistent testing."""
   ```

### Test Data Guidelines

**Use realistic nursing data**:
- Medical terminology
- Clinical scenarios
- Student performance ranges
- Assessment criteria

**Mock external services**:
- RAGnostic AI responses
- Database operations
- Third-party APIs

**Maintain test isolation**:
- Use fresh data per test
- Clean up after tests
- Reset shared state

## Continuous Integration

### GitHub Actions Integration

The test suite integrates with CI/CD pipeline:

```yaml
# .github/workflows/test.yml
- name: Run BSN Knowledge API Tests
  run: |
    pytest tests/ --cov=src --cov-report=xml --cov-fail-under=90

- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v1
```

### Quality Gates

**All tests must pass**:
- Authentication and security tests
- API endpoint functionality tests
- Performance benchmarks

**Coverage requirements**:
- Overall coverage >90%
- Critical modules >95%
- New code >95%

**Performance requirements**:
- No regression in response times
- Memory usage within bounds
- Concurrent handling maintained

---

## Support

For questions about the testing suite:

1. **Check test documentation** in individual test files
2. **Review test helpers** in `tests/utils/`
3. **Run tests with verbose output** for debugging
4. **Check GitHub issues** for known testing issues

**Test Suite Version**: 1.0.0
**Last Updated**: 2024-08-24
**Compatible with**: BSN Knowledge API v1.0.0
