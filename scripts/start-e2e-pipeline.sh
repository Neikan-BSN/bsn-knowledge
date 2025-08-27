#!/bin/bash
# E2E Pipeline Startup Script
# Orchestrates the complete RAGnostic → BSN Knowledge testing environment
# Group 1A Infrastructure Provisioning - Multi-Service Environment Setup

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/tmp/e2e-pipeline-startup-$(date +%Y%m%d_%H%M%S).log"
HEALTH_CHECK_SCRIPT="$SCRIPT_DIR/e2e-health-check.sh"

# Performance targets
TARGET_STARTUP_TIME=60
SERVICE_STARTUP_DELAY=5
HEALTH_CHECK_RETRIES=12
HEALTH_CHECK_INTERVAL=5

# Service startup order (dependencies first)
SERVICE_GROUPS=(
    "databases:postgres-e2e,redis-e2e,qdrant-e2e,neo4j-e2e"
    "ragnostic-core:ragnostic-orchestrator,ragnostic-config,ragnostic-storage"
    "ragnostic-processors:ragnostic-nursing-processor,ragnostic-gateway"
    "bsn-services:bsn-knowledge-api,bsn-knowledge-analytics,bsn-knowledge-processor"
    "mock-services:umls-mock,openai-mock"
)

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Function to print banner
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                    E2E RAGnostic → BSN Knowledge                     ║
║                     Pipeline Startup Orchestrator                   ║
║                                                                      ║
║  Group 1A: Infrastructure Provisioning - Step 1.1.1 Implementation ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    log_message "INFO" "🔍 Checking prerequisites..."

    # Check required tools
    local required_tools=("docker" "docker-compose" "curl" "pg_isready" "redis-cli" "bc")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required tools: ${missing_tools[*]}"
        return 1
    fi

    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_message "ERROR" "Docker daemon is not running"
        return 1
    fi

    # Check available ports
    local required_ports=(5440 6382 6338 6339 7479 7690 8030 8031 8032 8033 8034 8040 8041 8042 8050 8051)
    local occupied_ports=()

    for port in "${required_ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            occupied_ports+=("$port")
        fi
    done

    if [[ ${#occupied_ports[@]} -gt 0 ]]; then
        log_message "WARN" "Ports already in use: ${occupied_ports[*]}"
        log_message "INFO" "Attempting to stop existing E2E environment..."
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" down -v --remove-orphans || true
        sleep 2
    fi

    # Check available disk space (minimum 10GB)
    local available_space=$(df "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
    local min_space=$((10 * 1024 * 1024)) # 10GB in KB

    if (( available_space < min_space )); then
        log_message "WARN" "Low disk space: $(( available_space / 1024 / 1024 ))GB available, 10GB recommended"
    fi

    log_message "INFO" "✅ Prerequisites check completed"
    return 0
}

# Function to prepare environment
prepare_environment() {
    log_message "INFO" "🛠️ Preparing E2E environment..."

    # Create required directories
    local directories=(
        "$PROJECT_ROOT/testing/fixtures"
        "$PROJECT_ROOT/testing/monitoring"
        "$PROJECT_ROOT/tests/framework/orchestrator"
        "$PROJECT_ROOT/tests/framework/mocks/umls"
        "$PROJECT_ROOT/tests/framework/mocks/openai"
        "$PROJECT_ROOT/tests/framework/load"
    )

    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_message "INFO" "Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done

    # Verify fixture files exist
    local fixture_files=(
        "$PROJECT_ROOT/testing/fixtures/init-multiple-databases.sh"
        "$PROJECT_ROOT/testing/fixtures/ragnostic-schema.sql"
        "$PROJECT_ROOT/testing/fixtures/bsn-knowledge-schema.sql"
        "$PROJECT_ROOT/testing/fixtures/test-data-seed.sql"
    )

    for file in "${fixture_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_message "ERROR" "Required fixture file missing: $file"
            return 1
        fi
    done

    # Set proper permissions on database initialization script
    chmod +x "$PROJECT_ROOT/testing/fixtures/init-multiple-databases.sh"

    log_message "INFO" "✅ Environment preparation completed"
    return 0
}

# Function to create missing Docker build contexts
create_build_contexts() {
    log_message "INFO" "🏗️ Creating Docker build contexts..."

    # Create mock service Dockerfiles if they don't exist
    if [[ ! -f "$PROJECT_ROOT/tests/framework/mocks/umls/Dockerfile" ]]; then
        log_message "INFO" "Creating UMLS mock service Dockerfile..."
        cat > "$PROJECT_ROOT/tests/framework/mocks/umls/Dockerfile" << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN pip install fastapi uvicorn

COPY . /app/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF
    fi

    if [[ ! -f "$PROJECT_ROOT/tests/framework/mocks/umls/main.py" ]]; then
        cat > "$PROJECT_ROOT/tests/framework/mocks/umls/main.py" << 'EOF'
from fastapi import FastAPI
import json
import time
import os
from typing import Dict

app = FastAPI(title="UMLS Mock Service", version="1.0.0")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "umls-mock", "timestamp": time.time()}

@app.get("/rest/content/current/CUI/{cui}")
async def get_concept(cui: str):
    # Simulate response delay
    delay_ms = int(os.getenv("MOCK_RESPONSE_DELAY_MS", "100"))
    time.sleep(delay_ms / 1000)

    mock_concepts = {
        "C0020538": {"name": "Hypertension", "definition": "Persistently high systemic arterial blood pressure"},
        "C0011849": {"name": "Diabetes Mellitus", "definition": "A heterogeneous group of disorders characterized by hyperglycemia"},
        "C0032285": {"name": "Pneumonia", "definition": "Infection of the lung often accompanied by inflammation"}
    }

    if cui in mock_concepts:
        return {"result": mock_concepts[cui]}
    else:
        return {"result": {"name": f"Mock_Concept_{cui}", "definition": f"Mock definition for {cui}"}}
EOF
    fi

    # Create OpenAI mock service
    if [[ ! -f "$PROJECT_ROOT/tests/framework/mocks/openai/Dockerfile" ]]; then
        log_message "INFO" "Creating OpenAI mock service Dockerfile..."
        cat > "$PROJECT_ROOT/tests/framework/mocks/openai/Dockerfile" << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN pip install fastapi uvicorn

COPY . /app/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF
    fi

    if [[ ! -f "$PROJECT_ROOT/tests/framework/mocks/openai/main.py" ]]; then
        cat > "$PROJECT_ROOT/tests/framework/mocks/openai/main.py" << 'EOF'
from fastapi import FastAPI
import json
import time
import os

app = FastAPI(title="OpenAI Mock Service", version="1.0.0")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "openai-mock", "timestamp": time.time()}

@app.post("/v1/chat/completions")
async def chat_completions(request: dict):
    # Simulate response delay
    delay_ms = int(os.getenv("MOCK_RESPONSE_DELAY_MS", "300"))
    time.sleep(delay_ms / 1000)

    return {
        "id": "chatcmpl-mock123",
        "object": "chat.completion",
        "model": "gpt-3.5-turbo",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a mock response for medical content generation."
                }
            }
        ]
    }
EOF
    fi

    # Create test orchestrator if missing
    if [[ ! -f "$PROJECT_ROOT/tests/framework/orchestrator/Dockerfile" ]]; then
        log_message "INFO" "Creating test orchestrator Dockerfile..."
        cat > "$PROJECT_ROOT/tests/framework/orchestrator/Dockerfile" << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN pip install pytest asyncio requests

COPY . /app/

CMD ["python", "-m", "pytest", "/app/tests/", "-v"]
EOF
    fi

    log_message "INFO" "✅ Docker build contexts created"
}

# Function to start services in groups
start_service_group() {
    local group_name=$1
    local services=$2

    log_message "INFO" "🚀 Starting service group: $group_name"
    log_message "INFO" "   Services: $services"

    # Start services in this group
    IFS=',' read -ra SERVICE_ARRAY <<< "$services"
    for service in "${SERVICE_ARRAY[@]}"; do
        log_message "INFO" "   Starting: $service"
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" up -d "$service" 2>/dev/null || {
            log_message "WARN" "   Failed to start $service, continuing..."
        }
    done

    # Wait for services to initialize
    log_message "INFO" "   Waiting ${SERVICE_STARTUP_DELAY}s for initialization..."
    sleep $SERVICE_STARTUP_DELAY

    # Check service status
    local healthy_services=0
    local total_services=${#SERVICE_ARRAY[@]}

    for service in "${SERVICE_ARRAY[@]}"; do
        if docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" ps "$service" 2>/dev/null | grep -q "Up"; then
            healthy_services=$((healthy_services + 1))
            log_message "INFO" "   ✅ $service: Running"
        else
            log_message "WARN" "   ⚠️ $service: Not running"
        fi
    done

    log_message "INFO" "   Group status: $healthy_services/$total_services services running"
    return 0
}

# Function to wait for service health
wait_for_health() {
    log_message "INFO" "🏥 Waiting for services to become healthy..."

    local retry_count=0
    while (( retry_count < HEALTH_CHECK_RETRIES )); do
        if [[ -x "$HEALTH_CHECK_SCRIPT" ]]; then
            log_message "INFO" "Running health check (attempt $((retry_count + 1))/$HEALTH_CHECK_RETRIES)..."
            if "$HEALTH_CHECK_SCRIPT" >/dev/null 2>&1; then
                log_message "INFO" "✅ All critical services are healthy!"
                return 0
            fi
        else
            log_message "WARN" "Health check script not found or not executable: $HEALTH_CHECK_SCRIPT"
            # Fallback: basic Docker health check
            local unhealthy=$(docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" ps --filter "health=unhealthy" -q | wc -l)
            if (( unhealthy == 0 )); then
                log_message "INFO" "✅ Docker health checks passed!"
                return 0
            fi
        fi

        retry_count=$((retry_count + 1))
        if (( retry_count < HEALTH_CHECK_RETRIES )); then
            log_message "INFO" "   Waiting ${HEALTH_CHECK_INTERVAL}s before next check..."
            sleep $HEALTH_CHECK_INTERVAL
        fi
    done

    log_message "WARN" "⚠️ Health check timeout reached, but continuing..."
    return 1
}

# Function to display final status
show_final_status() {
    local startup_time=$1

    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    E2E PIPELINE STATUS                       ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

    log_message "INFO" "⏱️ Total startup time: ${startup_time}s (target: ${TARGET_STARTUP_TIME}s)"

    # Show running services
    echo -e "\n${CYAN}🔧 Running Services:${NC}"
    docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" ps --format "table {{.Name}}\t{{.State}}\t{{.Ports}}" | grep -E "(Name|Up)" || true

    echo -e "\n${CYAN}🌐 Service URLs:${NC}"
    cat << EOF
Database Services:
  PostgreSQL:     localhost:5440 (ragnostic_e2e, bsn_knowledge_e2e)
  Redis:          localhost:6382
  Qdrant:         http://localhost:6338
  Neo4j:          http://localhost:7479 (neo4j/e2e_neo4j_secure_pass)

RAGnostic Services:
  Orchestrator:   http://localhost:8030
  Config:         http://localhost:8031
  Storage:        http://localhost:8032
  Nursing Proc:   http://localhost:8033
  Gateway:        http://localhost:8034

BSN Knowledge Services:
  Main API:       http://localhost:8040
  Analytics:      http://localhost:8041
  Processor:      http://localhost:8042

Mock Services:
  UMLS Mock:      http://localhost:8050
  OpenAI Mock:    http://localhost:8051

Testing Tools:
  Prometheus:     http://localhost:9091 (profile: monitoring)
  Grafana:        http://localhost:3001 (profile: monitoring)
  Locust:         http://localhost:8089 (profile: load-testing)
EOF

    echo -e "\n${GREEN}📋 Next Steps:${NC}"
    echo "1. Run health check: $HEALTH_CHECK_SCRIPT"
    echo "2. Execute E2E tests: docker-compose -f docker-compose.e2e.yml --profile test-execution up"
    echo "3. Monitor performance: docker-compose -f docker-compose.e2e.yml --profile monitoring up -d"
    echo "4. Load testing: docker-compose -f docker-compose.e2e.yml --profile load-testing up -d"

    echo -e "\n${YELLOW}📁 Log Files:${NC}"
    echo "Startup log: $LOG_FILE"
    echo "Health check: Run $HEALTH_CHECK_SCRIPT for detailed health report"

    if (( startup_time <= TARGET_STARTUP_TIME )); then
        echo -e "\n${GREEN}🎉 SUCCESS: E2E pipeline started within target time!${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠️ WARNING: Startup exceeded target time (${startup_time}s > ${TARGET_STARTUP_TIME}s)${NC}"
        return 1
    fi
}

# Function to cleanup on exit
cleanup() {
    local exit_code=$?
    if (( exit_code != 0 )); then
        log_message "ERROR" "Script failed with exit code $exit_code"
        echo -e "\n${RED}❌ Startup failed. To cleanup:${NC}"
        echo "docker-compose -f $PROJECT_ROOT/docker-compose.e2e.yml down -v --remove-orphans"
        echo -e "${YELLOW}Check log: $LOG_FILE${NC}"
    fi
}

trap cleanup EXIT

# Main execution
main() {
    local start_time=$(date +%s)

    print_banner

    log_message "INFO" "Starting E2E RAGnostic → BSN Knowledge pipeline..."
    log_message "INFO" "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    log_message "INFO" "Project root: $PROJECT_ROOT"
    log_message "INFO" "Log file: $LOG_FILE"

    # Step 1: Check prerequisites
    if ! check_prerequisites; then
        log_message "ERROR" "Prerequisites check failed"
        exit 1
    fi

    # Step 2: Prepare environment
    if ! prepare_environment; then
        log_message "ERROR" "Environment preparation failed"
        exit 1
    fi

    # Step 3: Create build contexts
    create_build_contexts

    # Step 4: Pull/build images
    log_message "INFO" "🏗️ Building and pulling Docker images..."
    docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" build --pull 2>/dev/null || {
        log_message "WARN" "Some builds may have failed, continuing..."
    }

    # Step 5: Start services in dependency order
    for service_group in "${SERVICE_GROUPS[@]}"; do
        IFS=':' read -ra GROUP_PARTS <<< "$service_group"
        local group_name=${GROUP_PARTS[0]}
        local services=${GROUP_PARTS[1]}

        start_service_group "$group_name" "$services"
    done

    # Step 6: Wait for services to become healthy
    wait_for_health

    # Step 7: Show final status
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))

    show_final_status $total_time

    log_message "INFO" "E2E pipeline startup completed in ${total_time}s"

    # Step 8: Run final health check
    if [[ -x "$HEALTH_CHECK_SCRIPT" ]]; then
        echo -e "\n${CYAN}🏥 Running comprehensive health check...${NC}"
        if "$HEALTH_CHECK_SCRIPT"; then
            echo -e "${GREEN}🎉 E2E pipeline is fully operational and ready for testing!${NC}"
            exit 0
        else
            echo -e "${YELLOW}⚠️ Some services may need additional time to fully initialize${NC}"
            exit 2
        fi
    else
        echo -e "${YELLOW}⚠️ Health check script not available - manual verification recommended${NC}"
        exit 0
    fi
}

# Parse command line arguments
case "${1:-start}" in
    "start")
        main
        ;;
    "stop")
        echo "Stopping E2E pipeline..."
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" down -v --remove-orphans
        echo "E2E pipeline stopped"
        ;;
    "restart")
        echo "Restarting E2E pipeline..."
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" down -v --remove-orphans
        sleep 2
        main
        ;;
    "status")
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" ps
        ;;
    "logs")
        docker-compose -f "$PROJECT_ROOT/docker-compose.e2e.yml" logs -f
        ;;
    "health")
        if [[ -x "$HEALTH_CHECK_SCRIPT" ]]; then
            "$HEALTH_CHECK_SCRIPT"
        else
            echo "Health check script not found: $HEALTH_CHECK_SCRIPT"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|health}"
        echo "  start    - Start the E2E pipeline (default)"
        echo "  stop     - Stop all E2E services"
        echo "  restart  - Restart the E2E pipeline"
        echo "  status   - Show service status"
        echo "  logs     - Show service logs"
        echo "  health   - Run health check"
        exit 1
        ;;
esac
