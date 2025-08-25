# BSN Knowledge End-to-End Pipeline Testing Framework

Comprehensive testing infrastructure for validating the complete RAGnostic → BSN Knowledge educational content pipeline with multi-service orchestration, performance validation, and production-grade resilience testing.

## Overview

This framework provides:
- **Multi-Service Test Environment**: Docker Compose orchestration of all dependencies
- **End-to-End Pipeline Validation**: Complete RAGnostic → BSN Knowledge integration testing
- **Performance Testing**: Concurrent load testing with realistic user patterns
- **Resilience Validation**: Failure mode testing and recovery verification
- **Security Testing**: Cross-service security and input validation
- **Automated Reporting**: Comprehensive test results and performance metrics

## Architecture

### Test Environment Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      BSN Knowledge E2E Test Environment                     │
├─────────────────────────────────────────────────────────────────────────┤
│ Test Orchestrator    │  Load Testing       │  Monitoring         │
│ - Test Coordination  │  - Locust Master     │  - Prometheus        │
│ - Result Aggregation │  - Locust Workers    │  - Grafana          │
│ - Performance Track  │  - Realistic Load    │  - Metrics Collection│
├──────────────────────┬────────────────────┬────────────────────┤
│ Core Services        │  Mock Services      │  Database Services  │
│ - BSN Knowledge      │  - RAGnostic Mock    │  - PostgreSQL       │
│ - Test Integration   │  - OpenAI Mock       │  - Redis            │
│ - Health Monitoring  │  - UMLS Mock         │  - Neo4j            │
│                      │                    │  - Qdrant           │
└──────────────────────┴────────────────────┴────────────────────┘
```

### Test Categories

1. **End-to-End Pipeline Tests** (`test_e2e_pipeline.py`)
   - Complete RAGnostic → BSN Knowledge data flow
   - Medical terminology accuracy validation
   - NCLEX question generation quality
   - Performance benchmarking

2. **Integration Testing** (Service communication)
   - Circuit breaker pattern validation
   - Caching layer integration
   - Authentication handoff testing
   - API contract validation

3. **Performance Testing** (Load and stress)
   - Concurrent user simulation
   - Response time validation
   - Throughput measurement
   - Resource utilization tracking

4. **Resilience Testing** (Failure modes)
   - Service unavailability scenarios
   - Database connection exhaustion
   - Network partition simulation
   - Recovery time measurement

5. **Security Testing** (Cross-service)
   - Authentication boundary validation
   - Input sanitization verification
   - Rate limiting enforcement
   - Authorization flow testing

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.12+
- 8GB+ available RAM
- 20GB+ available disk space

### Environment Setup

1. **Start Test Environment**
   ```bash
   # Start all test services
   docker-compose -f docker-compose.test.yml up -d

   # Verify services are healthy
   docker-compose -f docker-compose.test.yml ps
   ```

2. **Verify Service Health**
   ```bash
   # Check all services are running
   curl http://localhost:8021/health  # BSN Knowledge
   curl http://localhost:8020/health  # RAGnostic Mock
   curl http://localhost:8022/health  # OpenAI Mock
   curl http://localhost:8023/health  # UMLS Mock
   ```

3. **Run Test Suite**
   ```bash
   # Install test dependencies
   pip install -r requirements-test.txt

   # Run complete E2E test suite
   pytest tests/test_e2e_pipeline.py -v --tb=short

   # Run specific test categories
   pytest -m "e2e and pipeline" -v
   pytest -m "resilience" -v
   pytest -m "load" -v
   ```

### Test Execution Modes

#### 1. Basic E2E Testing
```bash
# Quick validation (5-10 minutes)
pytest tests/test_e2e_pipeline.py::TestE2EPipeline::test_umls_to_nclex_generation_pipeline -v
```

#### 2. Performance Testing
```bash
# Start load testing environment
docker-compose -f docker-compose.test.yml --profile load-test up -d

# Access Locust web interface
open http://localhost:8089

# Or run automated load tests
pytest tests/test_e2e_pipeline.py::TestE2EPipeline::test_concurrent_load_performance -v
```

#### 3. Resilience Testing
```bash
# Run failure mode validation
pytest tests/test_e2e_pipeline.py::TestResilienceAndFailure -v
```

#### 4. Security Testing
```bash
# Cross-service security validation
pytest tests/test_e2e_pipeline.py::TestCrossServiceSecurity -v
```

#### 5. Complete Test Suite
```bash
# Full validation (30-45 minutes)
pytest tests/test_e2e_pipeline.py -v --tb=short --durations=10
```

## Test Configuration

### Service Configuration

Test services are configured in `docker-compose.test.yml`:

- **BSN Knowledge Test**: Port 8021, test database, mock integrations
- **RAGnostic Mock**: Port 8020, realistic response simulation
- **Database Services**: Non-conflicting ports (PostgreSQL: 5439, Redis: 6381)
- **Mock External APIs**: OpenAI (8022), UMLS (8023)

### Test Data Management

Test fixtures provide:
- **Medical Test Data**: Curated nursing content, UMLS concepts
- **Performance Benchmarks**: Response time thresholds, accuracy metrics
- **Security Test Vectors**: Injection payloads, authentication tests
- **Load Test Scenarios**: Realistic user behavior patterns

### Environment Variables

Key configuration options:

```bash
# Performance testing
export E2E_CONCURRENT_USERS=50
export E2E_TEST_DURATION=300
export E2E_PERFORMANCE_THRESHOLD_MS=200

# Security testing
export E2E_SECURITY_ENABLED=true
export E2E_RATE_LIMIT_TESTING=true

# Mock service behavior
export MOCK_ERROR_RATE=0.02
export MOCK_RESPONSE_DELAY_MS=50
```

## Advanced Usage

### Custom Test Scenarios

Create custom test scenarios by extending base classes:

```python
# tests/custom_scenarios.py
from tests.test_e2e_pipeline import TestE2EPipeline

class TestCustomScenario(TestE2EPipeline):
    @pytest.mark.asyncio
    async def test_custom_integration(self, pipeline_test_client):
        # Custom test logic
        pass
```

### Performance Benchmarking

Customize performance benchmarks in test fixtures:

```python
# Modify medical_test_data fixture
"performance_benchmarks": {
    "response_time_ms": {
        "p50": 50,   # Tighter requirement
        "p95": 150,  # Stricter P95
        "p99": 300   # More demanding P99
    }
}
```

### Load Testing Customization

Modify Locust configuration for different load patterns:

```python
# tests/framework/load/custom_locustfile.py
class CustomLoadUser(HttpUser):
    weight = 100
    wait_time = between(1, 3)  # Aggressive load

    @task(60)
    def high_frequency_requests(self):
        # Custom high-frequency scenario
        pass
```

### Monitoring Integration

Enable monitoring stack for detailed observability:

```bash
# Start with monitoring
docker-compose -f docker-compose.test.yml --profile monitoring up -d

# Access dashboards
open http://localhost:3000  # Grafana (admin/admin)
open http://localhost:9090  # Prometheus
```

## Test Results and Reporting

### Automated Reports

The framework generates comprehensive reports:

1. **JSON Reports**: Machine-readable results in `test_results/`
2. **HTML Reports**: Visual test results with metrics
3. **Performance Reports**: Load testing metrics and trends
4. **Coverage Reports**: Test coverage analysis

### Key Metrics Tracked

- **Response Times**: P50, P95, P99 latency measurements
- **Throughput**: Requests per second under load
- **Success Rates**: Percentage of successful operations
- **Medical Accuracy**: Terminology and concept validation
- **Resource Usage**: CPU, memory, database connections

### Report Access

```bash
# View latest HTML report
open test_results/e2e_results_$(date +%Y%m%d).html

# JSON analysis
jq '.execution_summary' test_results/e2e_results_*.json

# Performance trends
cat test_results/performance_report_*.json | jq '.summary'
```

## Performance Targets

### Response Time Requirements

- **API Endpoints**: P95 < 200ms, P99 < 500ms
- **Pipeline Processing**: Complete flow < 2s
- **NCLEX Generation**: 5 questions < 1s
- **Search Operations**: Results < 100ms

### Throughput Requirements

- **Concurrent Users**: 100+ simultaneous students
- **Question Generation**: 50+ questions/second
- **Content Processing**: 10+ documents/second
- **Database Operations**: 1000+ queries/second

### Accuracy Requirements

- **Medical Terminology**: >98% accuracy
- **Educational Relevance**: >95% alignment
- **NCLEX Standards**: >92% category compliance
- **Content Quality**: >90% educational value

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service logs
docker-compose -f docker-compose.test.yml logs bsn-knowledge-test
docker-compose -f docker-compose.test.yml logs ragnostic-mock

# Restart specific service
docker-compose -f docker-compose.test.yml restart bsn-knowledge-test
```

#### Test Failures
```bash
# Run single test with detailed output
pytest tests/test_e2e_pipeline.py::TestE2EPipeline::test_umls_to_nclex_generation_pipeline -v -s

# Check test logs
tail -f test_results/test_logs/test_execution.log
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats

# Check database performance
docker-compose -f docker-compose.test.yml exec postgres-test pg_stat_activity

# Analyze slow queries
grep "slow query" test_results/test_logs/*.log
```

#### Network Issues
```bash
# Check network connectivity
docker-compose -f docker-compose.test.yml exec bsn-knowledge-test ping ragnostic-mock

# Verify port bindings
docker-compose -f docker-compose.test.yml ps
netstat -tulpn | grep -E '(8020|8021|8022|8023)'
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
# Set debug environment variables
export E2E_DEBUG=true
export LOG_LEVEL=DEBUG

# Run tests with debug output
pytest tests/test_e2e_pipeline.py -v -s --log-cli-level=DEBUG
```

### Health Check Scripts

```bash
# Comprehensive health check
./scripts/health_check.sh

# Service dependency validation
./scripts/validate_dependencies.sh

# Performance baseline check
./scripts/performance_baseline.sh
```

## Integration with CI/CD

### GitHub Actions Integration

```yaml
# .github/workflows/e2e-testing.yml
name: E2E Pipeline Testing
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Start Test Environment
      run: |
        docker-compose -f docker-compose.test.yml up -d
        sleep 60  # Allow services to start

    - name: Run E2E Tests
      run: |
        pip install -r requirements-test.txt
        pytest tests/test_e2e_pipeline.py -v --tb=short

    - name: Upload Test Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: e2e-test-results
        path: test_results/
```

### Performance Regression Detection

```bash
# Compare with baseline
./scripts/performance_regression_check.sh

# Alert on degradation
if [ $PERF_REGRESSION -gt 10 ]; then
  echo "Performance regression detected: ${PERF_REGRESSION}%"
  exit 1
fi
```

## Security Considerations

### Test Environment Security

- **Isolated Networks**: Test services run in isolated Docker networks
- **Mock Credentials**: All credentials are test-only and non-production
- **Data Isolation**: Test databases are separate and ephemeral
- **Port Management**: Non-conflicting ports prevent interference

### Security Test Coverage

- **Authentication**: JWT validation, API key verification
- **Authorization**: Role-based access control testing
- **Input Validation**: Injection attack prevention
- **Rate Limiting**: Abuse prevention mechanisms

## Maintenance

### Regular Maintenance Tasks

1. **Update Dependencies**
   ```bash
   # Update test dependencies
   pip-compile requirements-test.in
   pip install -r requirements-test.txt
   ```

2. **Refresh Test Data**
   ```bash
   # Update medical terminology database
   ./scripts/update_test_data.sh
   ```

3. **Performance Baseline Updates**
   ```bash
   # Establish new performance baselines
   ./scripts/update_performance_baseline.sh
   ```

4. **Docker Image Updates**
   ```bash
   # Pull latest base images
   docker-compose -f docker-compose.test.yml pull
   ```

### Monitoring Framework Health

```bash
# Weekly framework validation
./scripts/framework_health_check.sh

# Test coverage analysis
./scripts/coverage_analysis.sh

# Performance trend analysis
./scripts/performance_trend_analysis.sh
```

## Support and Contributing

### Getting Help

- **Documentation**: Review this guide and inline code comments
- **Logs**: Check `test_results/test_logs/` for detailed execution logs
- **Health Checks**: Use provided health check scripts
- **Debug Mode**: Enable debug logging for detailed troubleshooting

### Contributing

1. **Adding New Tests**: Follow existing test patterns and use provided fixtures
2. **Performance Tests**: Include baseline measurements and thresholds
3. **Security Tests**: Validate both positive and negative scenarios
4. **Documentation**: Update this guide for new features or changes

### Best Practices

- **Test Isolation**: Each test should be independent and repeatable
- **Resource Cleanup**: Use fixtures for proper setup/teardown
- **Error Handling**: Include comprehensive error scenarios
- **Performance Tracking**: Always include timing and resource measurements
- **Security Validation**: Test both valid and malicious inputs

This comprehensive framework ensures the RAGnostic → BSN Knowledge pipeline meets production requirements for performance, security, reliability, and medical accuracy.
