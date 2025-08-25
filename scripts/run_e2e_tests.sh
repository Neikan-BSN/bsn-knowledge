#!/bin/bash
# BSN Knowledge E2E Pipeline Testing Framework Runner
# Comprehensive test execution with environment management and reporting

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/test_results"
LOG_FILE="$RESULTS_DIR/e2e_test_execution.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Help function
show_help() {
    cat << EOF
BSN Knowledge E2E Pipeline Testing Framework

Usage: $0 [OPTIONS] [TEST_CATEGORY]

TEST_CATEGORIES:
    all                 Run complete E2E test suite (default)
    pipeline            End-to-end pipeline tests only
    performance         Performance and load testing
    resilience          Resilience and failure mode testing
    security            Cross-service security testing
    health              Basic health check validation

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Verbose output
    -q, --quiet         Quiet mode (minimal output)
    --load-test         Include load testing with Locust
    --monitoring        Enable monitoring stack (Prometheus/Grafana)
    --cleanup           Clean up test environment after execution
    --no-build          Skip Docker image building
    --parallel          Run tests in parallel (where possible)
    --timeout SECONDS   Test timeout (default: 1800)
    --workers N         Number of test workers (default: 4)
    --results-only      Only show results summary

EXAMPLES:
    $0                                  # Run all tests
    $0 pipeline --verbose               # Run pipeline tests with verbose output
    $0 performance --load-test          # Run performance tests with load testing
    $0 --monitoring --cleanup           # Run with monitoring and cleanup
    $0 resilience --timeout 3600        # Run resilience tests with 1-hour timeout

EOF
}

# Parse command line arguments
TEST_CATEGORY="all"
VERBOSE=false
QUIET=false
LOAD_TEST=false
MONITORING=false
CLEANUP=false
NO_BUILD=false
PARALLEL=false
TIMEOUT=1800
WORKERS=4
RESULTS_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        --load-test)
            LOAD_TEST=true
            shift
            ;;
        --monitoring)
            MONITORING=true
            shift
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        --results-only)
            RESULTS_ONLY=true
            shift
            ;;
        all|pipeline|performance|resilience|security|health)
            TEST_CATEGORY="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Setup results directory
mkdir -p "$RESULTS_DIR"

# Start execution logging
log_info "Starting BSN Knowledge E2E Testing Framework"
log_info "Timestamp: $TIMESTAMP"
log_info "Test Category: $TEST_CATEGORY"
log_info "Project Directory: $PROJECT_DIR"
log_info "Results Directory: $RESULTS_DIR"

# Environment validation
validate_environment() {
    log_info "Validating test environment..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi

    # Check Python
    if ! command -v python &> /dev/null; then
        log_error "Python is not installed or not in PATH"
        exit 1
    fi

    # Check pytest
    if ! python -c "import pytest" &> /dev/null; then
        log_warning "pytest not found, attempting to install test requirements..."
        if [[ -f "$PROJECT_DIR/requirements-test.txt" ]]; then
            pip install -r "$PROJECT_DIR/requirements-test.txt"
        else
            pip install pytest pytest-asyncio pytest-cov httpx
        fi
    fi

    log_success "Environment validation completed"
}

# Build Docker images
build_images() {
    if [[ "$NO_BUILD" == "true" ]]; then
        log_info "Skipping Docker image building (--no-build specified)"
        return
    fi

    log_info "Building Docker images for test environment..."

    cd "$PROJECT_DIR"

    # Build main application image
    if ! docker build -t bsn-knowledge-test -f Dockerfile .; then
        log_error "Failed to build BSN Knowledge test image"
        exit 1
    fi

    # Build RAGnostic mock service
    if ! docker build -t ragnostic-mock -f tests/framework/services/ragnostic/Dockerfile tests/framework/services/ragnostic/; then
        log_error "Failed to build RAGnostic mock image"
        exit 1
    fi

    log_success "Docker images built successfully"
}

# Start test environment
start_environment() {
    log_info "Starting test environment..."

    cd "$PROJECT_DIR"

    # Determine which profiles to use
    PROFILES=""
    if [[ "$LOAD_TEST" == "true" ]]; then
        PROFILES="$PROFILES --profile load-test"
    fi
    if [[ "$MONITORING" == "true" ]]; then
        PROFILES="$PROFILES --profile monitoring"
    fi

    # Start services
    if ! docker-compose -f docker-compose.test.yml $PROFILES up -d; then
        log_error "Failed to start test environment"
        exit 1
    fi

    log_info "Waiting for services to become healthy..."
    sleep 30  # Initial wait

    # Wait for services to be healthy
    local max_attempts=30
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        local healthy_services=0
        local total_services=0

        # Check core services
        for service in bsn-knowledge-test ragnostic-mock postgres-test redis-test; do
            ((total_services++))
            if docker-compose -f docker-compose.test.yml ps -q "$service" | xargs docker inspect --format='{{.State.Health.Status}}' | grep -q "healthy"; then
                ((healthy_services++))
            fi
        done

        if [[ $healthy_services -eq $total_services ]]; then
            log_success "All services are healthy ($healthy_services/$total_services)"
            return 0
        fi

        log_info "Services health check: $healthy_services/$total_services (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done

    log_error "Services failed to become healthy within timeout"
    docker-compose -f docker-compose.test.yml logs
    exit 1
}

# Run tests based on category
run_tests() {
    log_info "Running tests for category: $TEST_CATEGORY"

    cd "$PROJECT_DIR"

    local pytest_args=""
    local test_markers=""

    # Configure verbosity
    if [[ "$VERBOSE" == "true" ]]; then
        pytest_args="$pytest_args -v -s"
    elif [[ "$QUIET" == "true" ]]; then
        pytest_args="$pytest_args -q"
    else
        pytest_args="$pytest_args --tb=short"
    fi

    # Configure parallel execution
    if [[ "$PARALLEL" == "true" ]]; then
        pytest_args="$pytest_args -n $WORKERS"
    fi

    # Configure timeout
    pytest_args="$pytest_args --timeout=$TIMEOUT"

    # Configure test selection based on category
    case $TEST_CATEGORY in
        "all")
            test_markers="e2e"
            pytest_args="$pytest_args tests/test_e2e_pipeline.py"
            ;;
        "pipeline")
            test_markers="e2e and pipeline"
            pytest_args="$pytest_args -m \"e2e and pipeline\""
            ;;
        "performance")
            test_markers="load or performance"
            pytest_args="$pytest_args -m \"load or performance\""
            ;;
        "resilience")
            test_markers="resilience"
            pytest_args="$pytest_args -m resilience"
            ;;
        "security")
            test_markers="security"
            pytest_args="$pytest_args -m security"
            ;;
        "health")
            pytest_args="$pytest_args tests/test_e2e_pipeline.py::TestE2EPipeline::test_umls_to_nclex_generation_pipeline"
            ;;
    esac

    # Add coverage and reporting
    pytest_args="$pytest_args --cov=src --cov-report=html:$RESULTS_DIR/coverage_$TIMESTAMP --cov-report=term-missing"
    pytest_args="$pytest_args --junit-xml=$RESULTS_DIR/junit_results_$TIMESTAMP.xml"

    log_info "Executing: pytest $pytest_args"

    # Run tests
    local test_start_time=$(date +%s)
    if eval "pytest $pytest_args" 2>&1 | tee "$RESULTS_DIR/pytest_output_$TIMESTAMP.log"; then
        local test_result="PASSED"
    else
        local test_result="FAILED"
    fi
    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log_info "Test execution completed in ${test_duration} seconds with result: $test_result"

    return $([ "$test_result" = "PASSED" ])
}

# Generate load testing report
generate_load_report() {
    if [[ "$LOAD_TEST" != "true" ]]; then
        return
    fi

    log_info "Generating load testing report..."

    # Access Locust stats if available
    if curl -s http://localhost:8089/stats/distribution > "$RESULTS_DIR/locust_stats_$TIMESTAMP.json" 2>/dev/null; then
        log_success "Load testing statistics saved"
    else
        log_warning "Could not retrieve load testing statistics"
    fi
}

# Generate comprehensive test report
generate_report() {
    log_info "Generating comprehensive test report..."

    local report_file="$RESULTS_DIR/e2e_test_report_$TIMESTAMP.html"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>BSN Knowledge E2E Test Report - $TIMESTAMP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .success { color: #28a745; }
        .failure { color: #dc3545; }
        .info { color: #007bff; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>BSN Knowledge E2E Pipeline Test Report</h1>
        <p><strong>Execution Time:</strong> $TIMESTAMP</p>
        <p><strong>Test Category:</strong> $TEST_CATEGORY</p>
        <p><strong>Duration:</strong> ${test_duration:-Unknown} seconds</p>
        <p><strong>Result:</strong> <span class="${test_result,,}">${test_result:-Unknown}</span></p>
    </div>

    <h2>Test Configuration</h2>
    <ul>
        <li>Verbose Mode: $VERBOSE</li>
        <li>Load Testing: $LOAD_TEST</li>
        <li>Monitoring: $MONITORING</li>
        <li>Parallel Execution: $PARALLEL</li>
        <li>Workers: $WORKERS</li>
        <li>Timeout: $TIMEOUT seconds</li>
    </ul>

    <h2>Environment Status</h2>
    <pre>$(docker-compose -f docker-compose.test.yml ps 2>/dev/null || echo "Environment status unavailable")</pre>

    <h2>Test Execution Log</h2>
    <pre>$(tail -n 100 "$LOG_FILE" 2>/dev/null || echo "Log unavailable")</pre>

    <h2>Links</h2>
    <ul>
        <li><a href="coverage_$TIMESTAMP/index.html">Test Coverage Report</a></li>
        <li><a href="pytest_output_$TIMESTAMP.log">Full pytest Output</a></li>
        <li><a href="junit_results_$TIMESTAMP.xml">JUnit XML Results</a></li>
EOF

    if [[ "$LOAD_TEST" == "true" ]]; then
        echo "        <li><a href=\"locust_stats_$TIMESTAMP.json\">Load Testing Statistics</a></li>" >> "$report_file"
    fi

    if [[ "$MONITORING" == "true" ]]; then
        echo "        <li><a href=\"http://localhost:3000\">Grafana Dashboard</a></li>" >> "$report_file"
        echo "        <li><a href=\"http://localhost:9090\">Prometheus Metrics</a></li>" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
    </ul>
</body>
</html>
EOF

    log_success "Test report generated: $report_file"
}

# Cleanup test environment
cleanup_environment() {
    if [[ "$CLEANUP" != "true" ]]; then
        return
    fi

    log_info "Cleaning up test environment..."

    cd "$PROJECT_DIR"

    # Stop and remove containers
    docker-compose -f docker-compose.test.yml down -v --remove-orphans

    # Remove test images if they were built
    if [[ "$NO_BUILD" != "true" ]]; then
        docker image rm bsn-knowledge-test ragnostic-mock 2>/dev/null || true
    fi

    log_success "Environment cleanup completed"
}

# Show results summary
show_results() {
    if [[ "$RESULTS_ONLY" == "true" ]] || [[ "$QUIET" != "true" ]]; then
        log_info "Test execution summary:"
        echo "================================"
        echo "Test Category: $TEST_CATEGORY"
        echo "Execution Time: $TIMESTAMP"
        echo "Duration: ${test_duration:-Unknown} seconds"
        echo "Result: ${test_result:-Unknown}"
        echo "Results Directory: $RESULTS_DIR"
        echo "================================"

        if [[ -f "$RESULTS_DIR/e2e_test_report_$TIMESTAMP.html" ]]; then
            echo "Comprehensive report: $RESULTS_DIR/e2e_test_report_$TIMESTAMP.html"
        fi
    fi
}

# Trap cleanup on exit
trap cleanup_environment EXIT

# Main execution flow
main() {
    validate_environment
    build_images
    start_environment

    local overall_result=0
    if run_tests; then
        log_success "All tests passed successfully"
    else
        log_error "Some tests failed"
        overall_result=1
    fi

    generate_load_report
    generate_report
    show_results

    return $overall_result
}

# Execute main function
if main; then
    log_success "E2E testing framework execution completed successfully"
    exit 0
else
    log_error "E2E testing framework execution failed"
    exit 1
fi
