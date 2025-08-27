#!/bin/bash
# E2E Pipeline Health Check Script
# Validates all services in the RAGnostic → BSN Knowledge pipeline
# Group 1A Infrastructure Provisioning - Service Health Validation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TIMEOUT=30
MAX_RETRIES=5
HEALTH_CHECK_INTERVAL=2
LOG_FILE="/tmp/e2e-health-check-$(date +%Y%m%d_%H%M%S).log"

# Performance targets (from requirements)
TARGET_STARTUP_TIME=60
TARGET_DB_CONNECTION_TIME=5
TARGET_INTER_SERVICE_LATENCY=50

# Service definitions with health endpoints
declare -A SERVICES=(
    ["postgres-e2e"]="postgresql://e2e_user:e2e_test_secure_pass@localhost:5440/ragnostic_e2e"
    ["redis-e2e"]="redis://localhost:6382"
    ["qdrant-e2e"]="http://localhost:6338/health"
    ["neo4j-e2e"]="http://localhost:7479"
    ["ragnostic-orchestrator"]="http://localhost:8030/health"
    ["ragnostic-config"]="http://localhost:8031/health"
    ["ragnostic-storage"]="http://localhost:8032/health"
    ["ragnostic-nursing-processor"]="http://localhost:8033/health"
    ["ragnostic-gateway"]="http://localhost:8034/gateway/health"
    ["bsn-knowledge-api"]="http://localhost:8040/health"
    ["bsn-knowledge-analytics"]="http://localhost:8041/health"
    ["bsn-knowledge-processor"]="http://localhost:8042/health"
    ["umls-mock"]="http://localhost:8050/health"
    ["openai-mock"]="http://localhost:8051/health"
)

# Critical services that must be healthy for E2E testing
CRITICAL_SERVICES=("postgres-e2e" "redis-e2e" "qdrant-e2e" "neo4j-e2e" "ragnostic-orchestrator" "bsn-knowledge-api")

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Function to test database connectivity
test_database_connection() {
    local service=$1
    local connection_string=$2
    local start_time=$(date +%s.%N)

    log_message "INFO" "Testing database connection: $service"

    case $service in
        "postgres-e2e")
            if timeout $TIMEOUT pg_isready -d "$connection_string" >/dev/null 2>&1; then
                local end_time=$(date +%s.%N)
                local duration=$(echo "$end_time - $start_time" | bc)
                local duration_ms=$(echo "$duration * 1000" | bc | cut -d'.' -f1)

                if (( duration_ms <= (TARGET_DB_CONNECTION_TIME * 1000) )); then
                    log_message "INFO" "✅ $service: Connected in ${duration_ms}ms (target: ${TARGET_DB_CONNECTION_TIME}s)"
                    return 0
                else
                    log_message "WARN" "⚠️ $service: Connected in ${duration_ms}ms (exceeds target: ${TARGET_DB_CONNECTION_TIME}s)"
                    return 1
                fi
            else
                log_message "ERROR" "❌ $service: Connection failed"
                return 1
            fi
            ;;
        "redis-e2e")
            if timeout $TIMEOUT redis-cli -u "$connection_string" ping >/dev/null 2>&1; then
                local end_time=$(date +%s.%N)
                local duration=$(echo "$end_time - $start_time" | bc)
                local duration_ms=$(echo "$duration * 1000" | bc | cut -d'.' -f1)
                log_message "INFO" "✅ $service: Redis responding in ${duration_ms}ms"
                return 0
            else
                log_message "ERROR" "❌ $service: Redis connection failed"
                return 1
            fi
            ;;
    esac
}

# Function to test HTTP service health
test_http_service() {
    local service=$1
    local health_url=$2
    local start_time=$(date +%s.%N)

    log_message "INFO" "Testing HTTP service: $service"

    local response=$(timeout $TIMEOUT curl -s -o /dev/null -w "%{http_code},%{time_total}" "$health_url" 2>/dev/null || echo "000,0")
    local http_code=$(echo $response | cut -d',' -f1)
    local response_time=$(echo $response | cut -d',' -f2)
    local response_time_ms=$(echo "$response_time * 1000" | bc | cut -d'.' -f1)

    if [[ $http_code == "200" ]]; then
        if (( response_time_ms <= TARGET_INTER_SERVICE_LATENCY )); then
            log_message "INFO" "✅ $service: Healthy (${response_time_ms}ms, target: ${TARGET_INTER_SERVICE_LATENCY}ms)"
            return 0
        else
            log_message "WARN" "⚠️ $service: Healthy but slow (${response_time_ms}ms, target: ${TARGET_INTER_SERVICE_LATENCY}ms)"
            return 1
        fi
    else
        log_message "ERROR" "❌ $service: HTTP $http_code or connection failed"
        return 1
    fi
}

# Function to test service with retries
test_service_with_retry() {
    local service=$1
    local connection_string=$2
    local retry_count=0

    while (( retry_count < MAX_RETRIES )); do
        if [[ $connection_string == postgresql://* ]]; then
            if test_database_connection "$service" "$connection_string"; then
                return 0
            fi
        elif [[ $connection_string == redis://* ]]; then
            if test_database_connection "$service" "$connection_string"; then
                return 0
            fi
        elif [[ $connection_string == http://* ]]; then
            if test_http_service "$service" "$connection_string"; then
                return 0
            fi
        fi

        retry_count=$((retry_count + 1))
        if (( retry_count < MAX_RETRIES )); then
            log_message "INFO" "🔄 $service: Retry $retry_count/$MAX_RETRIES in ${HEALTH_CHECK_INTERVAL}s..."
            sleep $HEALTH_CHECK_INTERVAL
        fi
    done

    return 1
}

# Function to test inter-service communication
test_inter_service_communication() {
    log_message "INFO" "🔗 Testing inter-service communication patterns..."

    # Test RAGnostic → BSN Knowledge integration
    local start_time=$(date +%s.%N)
    local integration_test=$(timeout $TIMEOUT curl -s -X GET \
        "http://localhost:8040/api/v1/ragnostic/status" \
        -H "Content-Type: application/json" \
        -w "%{http_code}" -o /dev/null 2>/dev/null || echo "000")

    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    local duration_ms=$(echo "$duration * 1000" | bc | cut -d'.' -f1)

    if [[ $integration_test == "200" ]]; then
        log_message "INFO" "✅ RAGnostic ↔ BSN Knowledge integration: Active (${duration_ms}ms)"
        return 0
    else
        log_message "WARN" "⚠️ RAGnostic ↔ BSN Knowledge integration: Not fully initialized"
        return 1
    fi
}

# Function to test database schemas and test data
test_database_schemas() {
    log_message "INFO" "🗄️ Validating database schemas and test data..."

    # Test RAGnostic database
    local ragnostic_tables=$(timeout $TIMEOUT psql -U e2e_user -h localhost -p 5440 -d ragnostic_e2e -t -c "
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
    " 2>/dev/null | xargs || echo "0")

    # Test BSN Knowledge database
    local bsn_tables=$(timeout $TIMEOUT psql -U e2e_user -h localhost -p 5440 -d bsn_knowledge_e2e -t -c "
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
    " 2>/dev/null | xargs || echo "0")

    if (( ragnostic_tables >= 10 && bsn_tables >= 15 )); then
        log_message "INFO" "✅ Database schemas: RAGnostic ($ragnostic_tables tables), BSN Knowledge ($bsn_tables tables)"

        # Test for test data
        local test_jobs=$(timeout $TIMEOUT psql -U e2e_user -h localhost -p 5440 -d ragnostic_e2e -t -c "
            SELECT COUNT(*) FROM jobs;
        " 2>/dev/null | xargs || echo "0")

        local test_users=$(timeout $TIMEOUT psql -U e2e_user -h localhost -p 5440 -d bsn_knowledge_e2e -t -c "
            SELECT COUNT(*) FROM users;
        " 2>/dev/null | xargs || echo "0")

        if (( test_jobs >= 3 && test_users >= 3 )); then
            log_message "INFO" "✅ Test data: RAGnostic ($test_jobs jobs), BSN Knowledge ($test_users users)"
            return 0
        else
            log_message "WARN" "⚠️ Test data incomplete: RAGnostic ($test_jobs jobs), BSN Knowledge ($test_users users)"
            return 1
        fi
    else
        log_message "ERROR" "❌ Database schema validation failed: RAGnostic ($ragnostic_tables), BSN Knowledge ($bsn_tables)"
        return 1
    fi
}

# Function to measure overall startup time
measure_startup_performance() {
    log_message "INFO" "⏱️ Measuring startup performance..."

    # Check Docker containers startup time
    local container_start_times=$(docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(ragnostic|bsn)" | grep -o "[0-9]* seconds ago\|[0-9]* minutes ago" | head -5)

    if [[ -n "$container_start_times" ]]; then
        log_message "INFO" "📊 Container startup times:"
        echo "$container_start_times" | while read -r line; do
            log_message "INFO" "   $line"
        done
    fi

    # Overall assessment
    log_message "INFO" "🎯 Performance targets: Startup <${TARGET_STARTUP_TIME}s, DB connections <${TARGET_DB_CONNECTION_TIME}s, Inter-service <${TARGET_INTER_SERVICE_LATENCY}ms"
}

# Function to generate health report
generate_health_report() {
    local total_services=${#SERVICES[@]}
    local healthy_services=$1
    local critical_healthy=$2
    local total_critical=${#CRITICAL_SERVICES[@]}

    log_message "INFO" "📋 HEALTH CHECK SUMMARY"
    log_message "INFO" "======================="
    log_message "INFO" "Total services: $total_services"
    log_message "INFO" "Healthy services: $healthy_services"
    log_message "INFO" "Critical services: $total_critical"
    log_message "INFO" "Critical healthy: $critical_healthy"
    log_message "INFO" "Success rate: $(echo "scale=1; $healthy_services * 100 / $total_services" | bc)%"
    log_message "INFO" "Critical success: $(echo "scale=1; $critical_healthy * 100 / $total_critical" | bc)%"
    log_message "INFO" "Log file: $LOG_FILE"

    if (( critical_healthy == total_critical )); then
        log_message "INFO" "🚀 E2E PIPELINE READY FOR TESTING"
        return 0
    else
        log_message "ERROR" "⚠️ CRITICAL SERVICES NOT READY - E2E testing not recommended"
        return 1
    fi
}

# Main execution
main() {
    local start_time=$(date +%s)

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              E2E RAGnostic → BSN Knowledge Health Check          ║${NC}"
    echo -e "${BLUE}║              Group 1A Infrastructure Provisioning               ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo

    log_message "INFO" "Starting comprehensive health check for E2E pipeline..."
    log_message "INFO" "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Check if required tools are available
    for tool in curl pg_isready redis-cli bc docker psql; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_message "ERROR" "Required tool not found: $tool"
            exit 1
        fi
    done

    local healthy_count=0
    local critical_healthy=0

    # Test each service
    for service in "${!SERVICES[@]}"; do
        local connection_string=${SERVICES[$service]}

        echo -e "\n${YELLOW}Testing: $service${NC}"
        if test_service_with_retry "$service" "$connection_string"; then
            healthy_count=$((healthy_count + 1))

            # Check if this is a critical service
            for critical in "${CRITICAL_SERVICES[@]}"; do
                if [[ $service == "$critical" ]]; then
                    critical_healthy=$((critical_healthy + 1))
                    break
                fi
            done
        fi
    done

    echo -e "\n${BLUE}Additional Validation Tests${NC}"

    # Test database schemas
    if test_database_schemas; then
        healthy_count=$((healthy_count + 1))
    fi

    # Test inter-service communication
    if test_inter_service_communication; then
        healthy_count=$((healthy_count + 1))
    fi

    # Measure performance
    measure_startup_performance

    echo -e "\n${BLUE}Health Check Results${NC}"
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    log_message "INFO" "Health check completed in ${total_time}s"

    # Generate final report
    if generate_health_report $healthy_count $critical_healthy; then
        echo -e "\n${GREEN}🎉 SUCCESS: E2E pipeline is healthy and ready for testing!${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ FAILURE: E2E pipeline has critical issues${NC}"
        echo -e "${YELLOW}Check the log file for details: $LOG_FILE${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"
